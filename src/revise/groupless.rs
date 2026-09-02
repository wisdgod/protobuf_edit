//! The groupless revising editor family core, emitted per machine
//! by [`revising_machine!`] for the five facades — session, draft,
//! markup, review, and the stream-ingest draft — and their
//! borrowed-payload and mixed-backing siblings. Four declared
//! sections parameterize a machine — the source holder with its
//! tenure doors, the acceptance (canonical width-erasing against
//! tolerant width-carrying: the scan, the geometry readers, the
//! save arms, and the refusal vocabulary), the payload backing
//! (copied store, borrowed slots, or the mixed slot table whose
//! faces select the backing per install), and the save product —
//! plus the capability and naming literals that ride them; the
//! internal arms below hold each stretch of shared text exactly
//! once.

/// Emits the groupless revising editor family into the invoking
/// module: `vocabulary` lays down the module-wide types (faults,
/// rows, the layer scan, save plumbing) once, `machine` emits the
/// editing machine — struct and its whole face set — `views` the
/// span/iterator products, and `frames` the staged payload frames,
/// all against that vocabulary. Names resolve at the invocation
/// site. The parenthesized roster on `vocabulary` names every
/// public type the module's invocations lay down beyond the
/// `machine`, `backing`, and `frames` lines; the public-type
/// census reads it, so each name must face the auto-trait matrix
/// under the module's path.
macro_rules! revising_machine {
    (
        vocabulary($($public:ident),+ $(,)?),
        capability: $cap:ident,
        tenure: $src:ident,
        acceptance: $acc:ident,
        product: $prod:ident,
        Machine: $Machine:ident,
        noun: $noun:literal,
        a_noun: $a_noun:literal,
        A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal $(,)?
    ) => {
        $crate::revise::groupless::revising_machine!(@vocabulary $cap, tenure: $src, acceptance: $acc, product: $prod, Machine: $Machine, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod);
    };
    (
        @vocabulary $cap:ident,
        tenure: $src:ident,
        acceptance: $acc:ident,
        product: $prod:ident,
        Machine: $Machine:ident,
        noun: $noun:literal,
        a_noun: $a_noun:literal,
        A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal $(,)?
    ) => {
        $crate::revise::groupless::revising_machine!(@faults Machine: $Machine, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod);
        $crate::revise::groupless::revising_machine!(@refusal $acc, Machine: $Machine, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod);
        $crate::revise::groupless::revising_machine!(@open_fault $src $acc, Machine: $Machine, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod);
        $crate::revise::groupless::revising_machine!(@edit_fault $cap, Machine: $Machine, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod);
        $crate::revise::groupless::revising_machine!(@save_fault $prod, Machine: $Machine, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod);
        $crate::revise::groupless::revising_machine!(@descent Machine: $Machine, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod);
        $crate::revise::groupless::revising_machine!(@record_spans $acc, Machine: $Machine, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod);
        $crate::revise::groupless::revising_machine!(@rows_shared $cap, Machine: $Machine, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod);
        $crate::revise::groupless::revising_machine!(@row $acc, Machine: $Machine, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod);
        $crate::revise::groupless::revising_machine!(@row_impl $cap, acc: $acc, Machine: $Machine, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod);
        $crate::revise::groupless::revising_machine!(@witness_points $cap, Machine: $Machine, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod);
        $crate::revise::groupless::revising_machine!(@len_witness $acc);
        $crate::revise::groupless::revising_machine!(@head_width $acc, Machine: $Machine, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod);
        $crate::revise::groupless::revising_machine!(@scan $acc, Machine: $Machine, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod);
        $crate::revise::groupless::revising_machine!(@machine_helpers $src, Machine: $Machine, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod);
        $crate::revise::groupless::revising_machine!(@word_enum $acc, Machine: $Machine, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod);
        $crate::revise::groupless::revising_machine!(@size_frame $acc, Machine: $Machine, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod);
        $crate::revise::groupless::revising_machine!(@arm_enum $cap $acc, Machine: $Machine, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod);
        $crate::revise::groupless::revising_machine!(@out_trait $cap $acc $prod, Machine: $Machine, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod);
        $crate::revise::groupless::revising_machine!(@emit_carrier $cap $prod, Machine: $Machine, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod);
        $crate::revise::groupless::revising_machine!(@vec_emit $cap $acc $prod, Machine: $Machine, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod);
        $crate::revise::groupless::revising_machine!(@sink_emit $cap $acc $prod, Machine: $Machine, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod);
        $crate::revise::groupless::revising_machine!(@canonical_vocab $cap $acc, Machine: $Machine, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod);
    };
    (@canonical_vocab plain tolerant, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
        /// The canonical walk's verdict for one row: every record in the
        /// materialized commitment closure re-emits with minimal framing,
        /// so no whole-record verbatim arm exists — byte runs ride
        /// verbatim only for fixed-width value bytes and opaque payload
        /// bytes, neither of which contains an emitted varint construct.
        enum CanonicalArm {
            /// Shrouded or ghost: contributes nothing.
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
            /// the source offset, for the over-cap fault.
            OpenLen { head: u32, first: Option<RowId>, at: At32 },
        }

        /// Where a canonical row's value comes from: the store for
        /// authored values, the bound scan offset for source-backed
        /// ones.
        #[derive(Clone, Copy)]
        enum CanonicalSrc {
            /// An authored value in the store.
            Store(ValueAt),
            /// A scanned value at this document offset.
            Doc(At32),
        }

        /// Where a canonical fixed-width value's bytes come from. The
        /// `Doc` offset's value bytes follow inside the record.
        #[derive(Clone, Copy)]
        enum CanonicalValue {
            /// The document value bytes at this offset, copied verbatim.
            Doc { at: At32 },
            /// The store word, through the existing bit emitter.
            Store(Word),
        }

        /// Where a canonical opaque payload's bytes come from. The `Doc`
        /// pair names a possibly-empty payload subspan: `len` sits in the
        /// length class, and an empty subspan's `at` may equal the zone
        /// cap (`At32::MAX + 1`), one past [`At32`]'s domain. The length
        /// stays a raw word: a typed niche here repacks the enum below
        /// its pinned size.
        #[derive(Clone, Copy)]
        enum CanonicalPayload {
            /// The document payload extent, copied verbatim.
            Doc { at: u32, len: u32 },
            /// The authored payload store slot.
            Store(ValueAt),
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
            /// Source offset, for the over-cap fault.
            at: At32,
        }
    };
    (@canonical_vocab transfer tolerant, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
        /// The canonical walk's verdict for one row: every record in the
        /// materialized commitment closure re-emits with minimal framing,
        /// so no whole-record verbatim arm exists — byte runs ride
        /// verbatim only for fixed-width value bytes and opaque payload
        /// bytes, neither of which contains an emitted varint construct.
        enum CanonicalArm {
            /// Shrouded or ghost: contributes nothing.
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
            /// the source offset, for the over-cap fault.
            OpenLen { head: u32, first: Option<RowId>, at: At32 },
        }

        /// Where a canonical row's value comes from: the store for
        /// authored values, the bound scan offset for source-backed
        /// ones.
        #[derive(Clone, Copy)]
        enum CanonicalSrc {
            /// An authored value in the store.
            Store(ValueAt),
            /// A scanned value at this document offset.
            Doc(At32),
        }

        /// Where a canonical fixed-width value's bytes come from. The
        /// `Doc` offset's value bytes follow inside the record.
        #[derive(Clone, Copy)]
        enum CanonicalValue {
            /// The document value bytes at this offset, copied verbatim.
            Doc { at: At32 },
            /// The store word, through the existing bit emitter.
            Store(Word),
        }

        /// Where a canonical opaque payload's bytes come from. The `Doc`
        /// pair names a possibly-empty payload subspan: `len` sits in the
        /// length class, and an empty subspan's `at` may equal the zone
        /// cap (`At32::MAX + 1`), one past [`At32`]'s domain. The length
        /// stays a raw word: a typed niche here repacks the enum below
        /// its pinned size.
        #[derive(Clone, Copy)]
        enum CanonicalPayload {
            /// The document payload extent, copied verbatim.
            Doc { at: u32, len: u32 },
            /// The authored payload store slot.
            Store(ValueAt),
            /// The payload subspan of an imported record's store span:
            /// the interior rides byte-exact behind re-derived framing.
            Import(ValueAt),
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
            /// Source offset, for the over-cap fault.
            at: At32,
        }
    };
    (@canonical_vocab $cap:ident tolerant, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
        /// The canonical walk's verdict for one row: every record in the
        /// materialized commitment closure re-emits with minimal framing,
        /// so no whole-record verbatim arm exists — byte runs ride
        /// verbatim only for fixed-width value bytes and opaque payload
        /// bytes, neither of which contains an emitted varint construct.
        enum CanonicalArm {
            /// Shrouded or ghost: contributes nothing.
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
            /// the source offset, for the over-cap fault.
            OpenLen { head: u32, first: Option<RowId>, at: At32 },
        }

        /// Where a canonical row's value comes from: the store for
        /// authored values, the bound scan offset for source-backed
        /// ones.
        #[derive(Clone, Copy)]
        enum CanonicalSrc {
            /// An authored value in the store.
            Store(ValueAt),
            /// A scanned value at this document offset.
            Doc(At32),
        }

        /// Where a canonical fixed-width value's bytes come from. The
        /// `Doc` offset's value bytes follow inside the record.
        #[derive(Clone, Copy)]
        enum CanonicalValue {
            /// The document value bytes at this offset, copied verbatim.
            Doc { at: At32 },
            /// The store word, through the existing bit emitter.
            Store(Word),
        }

        /// Where a canonical opaque payload's bytes come from. The `Doc`
        /// pair names a possibly-empty payload subspan: `len` sits in the
        /// length class, and an empty subspan's `at` may equal the zone
        /// cap (`At32::MAX + 1`), one past [`At32`]'s domain. The length
        /// stays a raw word: a typed niche here repacks the enum below
        /// its pinned size.
        #[derive(Clone, Copy)]
        enum CanonicalPayload {
            /// The document payload extent, copied verbatim.
            Doc { at: u32, len: u32 },
            /// The authored payload store slot.
            Store(ValueAt),
            /// The payload subspan of an imported record's store span:
            /// the interior rides byte-exact behind re-derived framing.
            Import(ValueAt),
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
            /// Source offset, for the over-cap fault.
            at: At32,
        }
    };
    (@canonical_vocab $cap:ident canonical, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {};
    (
        $(#[$mdoc:meta])*
        machine $Machine:ident $(<$lt:lifetime>)? { source: $src_ty:ty }
        capability: $cap:ident,
        tenure: $src:ident,
        acceptance: $acc:ident,
        product: $prod:ident,
        noun: $noun:literal,
        a_noun: $a_noun:literal,
        A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal $(,)?
    ) => {
        $crate::revise::groupless::revising_machine!(@machine_struct $Machine $(<$lt>)?, store: Store, src_ty: $src_ty, $(#[$mdoc])*);
        $crate::revise::groupless::revising_machine!(@core $cap, $Machine $(<$lt>)?, src_lt: [$($lt)?], pay_lt: [], pay: copy, store: Store, src: $src, acc: $acc, prod: $prod, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod);
    };
    (
        $(#[$mdoc:meta])*
        machine $Machine:ident<$lt:lifetime> { source: $src_ty:ty }
        capability: $cap:ident,
        payload: borrow,
        tenure: $src:ident,
        acceptance: $acc:ident,
        product: $prod:ident,
        noun: $noun:literal,
        a_noun: $a_noun:literal,
        A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal $(,)?
    ) => {
        $crate::revise::groupless::revising_machine!(@machine_struct $Machine <$lt>, store: BorrowStore<$lt>, src_ty: $src_ty, $(#[$mdoc])*);
        $crate::revise::groupless::revising_machine!(@core $cap, $Machine <$lt>, src_lt: [], pay_lt: [$lt], pay: borrow, store: BorrowStore, src: $src, acc: $acc, prod: $prod, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod);
    };
    (
        $(#[$mdoc:meta])*
        machine $Machine:ident<$slt:lifetime, $plt:lifetime> { source: $src_ty:ty }
        capability: $cap:ident,
        payload: borrow,
        tenure: $src:ident,
        acceptance: $acc:ident,
        product: $prod:ident,
        noun: $noun:literal,
        a_noun: $a_noun:literal,
        A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal $(,)?
    ) => {
        $crate::revise::groupless::revising_machine!(@machine_struct $Machine <$slt, $plt>, store: BorrowStore<$plt>, src_ty: $src_ty, $(#[$mdoc])*);
        $crate::revise::groupless::revising_machine!(@core $cap, $Machine <$slt, $plt>, src_lt: [$slt], pay_lt: [$plt], pay: borrow, store: BorrowStore, src: $src, acc: $acc, prod: $prod, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod);
    };
    (
        $(#[$mdoc:meta])*
        machine $Machine:ident<$plt:lifetime> { source: $src_ty:ty }
        capability: $cap:ident,
        payload: mixed,
        tenure: $src:ident,
        acceptance: $acc:ident,
        product: $prod:ident,
        noun: $noun:literal,
        a_noun: $a_noun:literal,
        A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal $(,)?
    ) => {
        $crate::revise::groupless::revising_machine!(@machine_struct $Machine <$plt>, store: MixStore<$plt>, src_ty: $src_ty, $(#[$mdoc])*);
        $crate::revise::groupless::revising_machine!(@core $cap, $Machine <$plt>, src_lt: [], pay_lt: [$plt], pay: mixed, store: MixStore, src: $src, acc: $acc, prod: $prod, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod);
    };
    (
        $(#[$mdoc:meta])*
        machine $Machine:ident<$slt:lifetime, $plt:lifetime> { source: $src_ty:ty }
        capability: $cap:ident,
        payload: mixed,
        tenure: $src:ident,
        acceptance: $acc:ident,
        product: $prod:ident,
        noun: $noun:literal,
        a_noun: $a_noun:literal,
        A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal $(,)?
    ) => {
        $crate::revise::groupless::revising_machine!(@machine_struct $Machine <$slt, $plt>, store: MixStore<$plt>, src_ty: $src_ty, $(#[$mdoc])*);
        $crate::revise::groupless::revising_machine!(@core $cap, $Machine <$slt, $plt>, src_lt: [$slt], pay_lt: [$plt], pay: mixed, store: MixStore, src: $src, acc: $acc, prod: $prod, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod);
    };
    (
        views,
        Machine: $Machine:ident,
        noun: $noun:literal,
        a_noun: $a_noun:literal,
        A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal $(,)?
    ) => {
        $crate::revise::groupless::revising_machine!(@views Machine: $Machine, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod);
    };
    (
        frames for $Machine:ident $(<$lt:lifetime>)? (PayloadFrame, SizedPayloadFrame, FrameFault),
        noun: $noun:literal,
        a_noun: $a_noun:literal,
        A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal,
        frame_doc: [$(#[$frame_send:meta])*],
        sized_doc: [$(#[$sized_send:meta])*] $(,)?
    ) => {
        $crate::revise::groupless::revising_machine!(@frames $Machine $(<$lt>)?, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod, frame_doc: [$(#[$frame_send])*], sized_doc: [$(#[$sized_send])*]);
    };
    (
        frames for $Machine:ident<$($lt:lifetime),+> (MixPayloadFrame, MixSizedPayloadFrame),
        noun: $noun:literal,
        a_noun: $a_noun:literal,
        A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal,
        frame_doc: [$(#[$frame_send:meta])*],
        sized_doc: [$(#[$sized_send:meta])*] $(,)?
    ) => {
        $crate::revise::groupless::revising_machine!(@mix_frames $Machine <$($lt),+>, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod, frame_doc: [$(#[$frame_send])*], sized_doc: [$(#[$sized_send])*]);
    };
    (
        $(#[$mdoc:meta])*
        machine $Priced:ident over $Machine:ident,
        capability: $cap:ident,
        noun: $noun:literal,
        a_noun: $a_noun:literal,
        A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal $(,)?
    ) => {
        $crate::revise::groupless::revising_machine!(@priced $cap, $Priced over $Machine, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod, mdoc: [$(#[$mdoc])*]);
    };
    (
        frames for $Priced:ident over $Machine:ident (PricedPayloadFrame, PricedSizedPayloadFrame),
        noun: $noun:literal,
        a_noun: $a_noun:literal,
        A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal,
        frame_doc: [$(#[$frame_send:meta])*],
        sized_doc: [$(#[$sized_send:meta])*] $(,)?
    ) => {
        $crate::revise::groupless::revising_machine!(@priced_frames $Priced over $Machine, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod, frame_doc: [$(#[$frame_send])*], sized_doc: [$(#[$sized_send])*]);
    };
    (@faults Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
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

    };
    (@refusal tolerant, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
        #[doc = concat!(" Lawful wire this ", $noun, " refuses: group codes outside this")]
        /// dialect's language. Padding is admitted — tolerant acceptance
        #[doc = concat!(" is the ", $noun, "'s type-level pole — so no minimality refusal")]
        /// exists here.
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
                }
            }
        }

        impl core::error::Error for Refusal {}

    };
    (@refusal canonical, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
        #[doc = concat!(" Lawful wire this ", $noun, " refuses: padding outside the")]
        /// canonical-minimal policy, and group codes outside this
        /// dialect's language.
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
                }
            }
        }

        impl core::error::Error for Refusal {}

    };
    // A stream cell's machine is minted by its ingest phase's seal
    // alone, so no open judgment — and no fault type for one —
    // exists there.
    (@open_fault stream tolerant, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {};
    (@open_fault vec tolerant, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
        #[doc = concat!(" Why ", $a_noun, " refused to open. The move door returns the buffer")]
        /// intact beside this fault — transactional tenure.
        #[non_exhaustive]
        #[derive(Clone, Copy, PartialEq, Eq, Debug)]
        pub enum OpenFault {
            /// The document exceeds the coordinate class (`i32::MAX`
            /// bytes).
            TooLarge {
                /// The refused input length.
                len: usize,
            },
            #[doc = concat!(" The allocator refused the ", $noun, "'s working storage or the")]
            /// root scan.
            Resource,
            /// The root layer violates the wire grammar.
            Wire(Fault),
            /// The root layer is lawful wire outside this dialect's
            /// language (a group code).
            Refused(Refusal),
        }

        impl core::fmt::Display for OpenFault {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                match *self {
                    Self::TooLarge { len } => {
                        write!(f, "document of {len} bytes exceeds the ")?;
                        f.write_str(concat!($noun, " cap"))
                    }
                    Self::Resource => f.write_str(concat!("allocator refused the ", $noun, "'s working storage")),
                    Self::Wire(fault) => write!(f, "root layer: {fault}"),
                    Self::Refused(refusal) => write!(f, "root layer: {refusal}"),
                }
            }
        }

        impl core::error::Error for OpenFault {
            fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
                match self {
                    Self::Wire(fault) => Some(fault),
                    Self::Refused(refusal) => Some(refusal),
                    Self::TooLarge { .. } | Self::Resource => None,
                }
            }
        }

    };
    (@open_fault borrow tolerant, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
        #[doc = concat!(" Why ", $a_noun, " refused to open.")]
        #[non_exhaustive]
        #[derive(Clone, Copy, PartialEq, Eq, Debug)]
        pub enum OpenFault {
            /// The document exceeds the coordinate class (`i32::MAX`
            /// bytes).
            TooLarge {
                /// The refused input length.
                len: usize,
            },
            #[doc = concat!(" The allocator refused the ", $noun, "'s working storage or the")]
            /// root scan.
            Resource,
            /// The root layer violates the wire grammar.
            Wire(Fault),
            /// The root layer is lawful wire outside this dialect's
            /// language (a group code).
            Refused(Refusal),
        }

        impl core::fmt::Display for OpenFault {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                match *self {
                    Self::TooLarge { len } => {
                        write!(f, "document of {len} bytes exceeds the ")?;
                        f.write_str(concat!($noun, " cap"))
                    }
                    Self::Resource => f.write_str(concat!("allocator refused the ", $noun, "'s working storage")),
                    Self::Wire(fault) => write!(f, "root layer: {fault}"),
                    Self::Refused(refusal) => write!(f, "root layer: {refusal}"),
                }
            }
        }

        impl core::error::Error for OpenFault {
            fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
                match self {
                    Self::Wire(fault) => Some(fault),
                    Self::Refused(refusal) => Some(refusal),
                    Self::TooLarge { .. } | Self::Resource => None,
                }
            }
        }

    };
    (@open_fault borrow canonical, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
        #[doc = concat!(" Why ", $a_noun, " refused to open.")]
        #[non_exhaustive]
        #[derive(Clone, Copy, PartialEq, Eq, Debug)]
        pub enum OpenFault {
            /// The document exceeds the coordinate class (`i32::MAX`
            /// bytes).
            TooLarge {
                /// The refused input length.
                len: usize,
            },
            #[doc = concat!(" The allocator refused the ", $noun, "'s working storage or the")]
            /// root scan.
            Resource,
            /// The root layer violates the wire grammar.
            Wire(Fault),
            #[doc = concat!(" The root layer is lawful wire outside this ", $noun, "'s policy")]
            /// (padding or a group code).
            Refused(Refusal),
        }

        impl core::fmt::Display for OpenFault {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                match *self {
                    Self::TooLarge { len } => {
                        write!(f, "document of {len} bytes exceeds the ")?;
                        f.write_str(concat!($noun, " cap"))
                    }
                    Self::Resource => f.write_str(concat!("allocator refused the ", $noun, "'s working storage")),
                    Self::Wire(fault) => write!(f, "root layer: {fault}"),
                    Self::Refused(refusal) => write!(f, "root layer: {refusal}"),
                }
            }
        }

        impl core::error::Error for OpenFault {
            fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
                match self {
                    Self::Wire(fault) => Some(fault),
                    Self::Refused(refusal) => Some(refusal),
                    Self::TooLarge { .. } | Self::Resource => None,
                }
            }
        }

    };
    (@open_fault carrier canonical, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
        #[doc = concat!(" Why ", $a_noun, " refused to open.")]
        #[non_exhaustive]
        #[derive(Clone, Copy, PartialEq, Eq, Debug)]
        pub enum OpenFault {
            /// The document exceeds the carrier cap.
            TooLarge {
                /// The refused input length.
                len: usize,
            },
            #[doc = concat!(" The allocator refused the ", $noun, "'s working storage or the")]
            /// root scan.
            Resource,
            /// The root layer violates the wire grammar.
            Wire(Fault),
            #[doc = concat!(" The root layer is lawful wire outside this ", $noun, "'s policy")]
            /// (padding or a group code).
            Refused(Refusal),
        }

        impl core::fmt::Display for OpenFault {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                match *self {
                    Self::TooLarge { len } => {
                        write!(f, "document of {len} bytes exceeds the ")?;
                        f.write_str(concat!($noun, " cap"))
                    }
                    Self::Resource => f.write_str(concat!("allocator refused the ", $noun, "'s working storage")),
                    Self::Wire(fault) => write!(f, "root layer: {fault}"),
                    Self::Refused(refusal) => write!(f, "root layer: {refusal}"),
                }
            }
        }

        impl core::error::Error for OpenFault {
            fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
                match self {
                    Self::Wire(fault) => Some(fault),
                    Self::Refused(refusal) => Some(refusal),
                    Self::TooLarge { .. } | Self::Resource => None,
                }
            }
        }

    };
    (@edit_fault plain, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
        /// Why an edit command refused. Failure classes are judged in no
        /// promised order: a command may report a temporary refusal
        /// ([`Self::Resource`]) before a permanent one on the same call.
        #[non_exhaustive]
        #[derive(Clone, Copy, PartialEq, Eq, Debug)]
        pub enum EditFault {
            /// The handle's row was orphaned by a payload replacement.
            DeadHandle,
            /// The record's wire kind does not fit the command.
            KindMismatch {
                /// The record's actual kind.
                have: RecordKind,
            },
            /// The record is deleted; undelete it first.
            DeletedTarget,
            /// The record is not deleted.
            NotDeleted,
            /// Only replaced records clear back to their scanned state.
            NotClearable,
            /// Descend the container before inserting into it.
            TargetUnopened,
            /// Records inside an authored payload are browse-only.
            InsideAuthoredBody,
            /// The interior carries edits or revision-log entries; revert first.
            EditedInterior,
            /// The replacement payload exceeds the length class.
            PayloadTooLarge {
                /// The refused payload length.
                len: usize,
            },
            #[doc = concat!(" The allocator refused ", $noun, " growth; the command changed")]
            /// nothing and may be retried.
            Resource,
            #[doc = concat!(" The ", $noun, "'s edit storage is full; the refusal is")]
            #[doc = concat!(" permanent for this ", $noun, ".")]
            IndexSpaceExhausted,
        }

        impl core::fmt::Display for EditFault {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                match *self {
                    Self::DeadHandle => f.write_str("the row was orphaned by a payload replacement"),
                    Self::KindMismatch { have } => {
                        write!(f, "the command expects another wire kind; the record is {have}")
                    }
                    Self::DeletedTarget => f.write_str("the record is deleted; undelete it first"),
                    Self::NotDeleted => f.write_str("the record is not deleted"),
                    Self::NotClearable => {
                        f.write_str("only replaced records clear back to their scanned state")
                    }
                    Self::TargetUnopened => f.write_str("descend the container before inserting into it"),
                    Self::InsideAuthoredBody => {
                        f.write_str("records inside an authored payload are browse-only")
                    }
                    Self::EditedInterior => {
                        f.write_str("the interior carries edits or revision log entries; revert them first")
                    }
                    Self::PayloadTooLarge { len } => {
                        write!(f, "payload of {len} bytes exceeds the length class")
                    }
                    Self::Resource => f.write_str(concat!("allocator refused ", $noun, " growth")),
                    Self::IndexSpaceExhausted => f.write_str(concat!("the ", $noun, "'s edit storage is full")),
                }
            }
        }

        impl core::error::Error for EditFault {}

    };
    (@edit_fault $cap:ident, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
        /// Why an edit command refused. Failure classes are judged in no
        /// promised order: a command may report a temporary refusal
        /// ([`Self::Resource`]) before a permanent one on the same call.
        #[non_exhaustive]
        #[derive(Clone, Copy, PartialEq, Eq, Debug)]
        pub enum EditFault {
            /// The handle's row was orphaned by a payload replacement.
            DeadHandle,
            /// The record's wire kind does not fit the command.
            KindMismatch {
                /// The record's actual kind.
                have: RecordKind,
            },
            /// The record is deleted; undelete it first.
            DeletedTarget,
            /// The record is not deleted.
            NotDeleted,
            /// Only replaced records clear back to their scanned state.
            NotClearable,
            /// Descend the container before inserting into it.
            TargetUnopened,
            /// Records inside an authored payload are browse-only.
            InsideAuthoredBody,
            /// The interior carries edits or revision-log entries; revert first.
            EditedInterior,
            /// The replacement payload exceeds the length class.
            PayloadTooLarge {
                /// The refused payload length.
                len: usize,
            },
            /// The transfer source is not a live original source
            /// occurrence: authored, copied, imported, and suppressed
            /// rows carry no designation.
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
            #[doc = concat!(" The allocator refused ", $noun, " growth; the command changed")]
            /// nothing and may be retried.
            Resource,
            #[doc = concat!(" The ", $noun, "'s edit storage is full; the refusal is")]
            #[doc = concat!(" permanent for this ", $noun, ".")]
            IndexSpaceExhausted,
        }

        impl core::fmt::Display for EditFault {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                match *self {
                    Self::DeadHandle => f.write_str("the row was orphaned by a payload replacement"),
                    Self::KindMismatch { have } => {
                        write!(f, "the command expects another wire kind; the record is {have}")
                    }
                    Self::DeletedTarget => f.write_str("the record is deleted; undelete it first"),
                    Self::NotDeleted => f.write_str("the record is not deleted"),
                    Self::NotClearable => {
                        f.write_str("only replaced records clear back to their scanned state")
                    }
                    Self::TargetUnopened => f.write_str("descend the container before inserting into it"),
                    Self::InsideAuthoredBody => {
                        f.write_str("records inside an authored payload are browse-only")
                    }
                    Self::EditedInterior => {
                        f.write_str("the interior carries edits or revision log entries; revert them first")
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
                    Self::Resource => f.write_str(concat!("allocator refused ", $noun, " growth")),
                    Self::IndexSpaceExhausted => f.write_str(concat!("the ", $noun, "'s edit storage is full")),
                }
            }
        }

        impl core::error::Error for EditFault {}

    };
    (@save_fault vec, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
        /// Why a save refused.
        #[non_exhaustive]
        #[derive(Clone, Copy, PartialEq, Eq, Debug)]
        pub enum SaveFault {
            /// The allocator refused the size pass or the output document.
            Resource,
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
                    Self::Resource => f.write_str("allocator refused the save"),
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

    };
    (@save_fault carrier, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
        /// Why a save refused.
        #[non_exhaustive]
        #[derive(Clone, Copy, PartialEq, Eq, Debug)]
        pub enum SaveFault {
            /// The allocator refused the size pass or the output document.
            Resource,
            /// A rewritten LEN body outgrew the length class.
            BodyOverCap {
                /// Source offset of the overflowing LEN record.
                at: u32,
            },
            /// The rewritten document outgrew the carrier cap.
            DocOverCap {
                /// The oversized total.
                total: u64,
            },
        }

        impl core::fmt::Display for SaveFault {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                match *self {
                    Self::Resource => f.write_str("allocator refused the save"),
                    Self::BodyOverCap { at } => {
                        write!(f, "rewritten body of the LEN at {at} exceeds the length class")
                    }
                    Self::DocOverCap { total } => {
                        write!(f, "rewritten document of {total} bytes exceeds the carrier cap")
                    }
                }
            }
        }

        impl core::error::Error for SaveFault {}

    };
    (@descent Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
        // ─── verdicts and geometry ───

        /// A descend verdict. Faults and refusals are resident: they park
        /// on the container's slot and project unchanged on every later
        /// call, while the payload stays readable as bytes.
        #[must_use = "the verdict reports whether the payload opened, faulted, or was refused"]
        #[derive(Clone, Copy, PartialEq, Eq, Debug)]
        pub enum Descent<'s> {
            /// The payload parsed; its first child, if any.
            Opened {
                /// First record of the interior layer.
                first: Option<Handle>,
            },
            /// The payload violates the wire grammar (resident).
            Faulted(&'s Fault),
            #[doc = concat!(" The payload is outside this ", $noun, "'s policy (resident).")]
            Refused(&'s Refusal),
        }

    };
    (@record_spans tolerant, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
        /// Source-document geometry of one backed record: the segments
        /// partition the record's span exactly.
        ///
        /// Coordinates answer at the widths the scan actually met — padded
        /// framing reports its padded extents — for the source bytes, not
        /// any pending edit.
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

    };
    (@record_spans canonical, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
        /// Source-document geometry of one backed record: the segments
        /// partition the record's span exactly. Coordinates answer for the
        /// canonically-admitted source bytes, not for any pending edit.
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

    };
    (@rows_shared $cap:ident, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
        // ─── rows ───

        /// `Row.kids` when no child is linked (outside [`RowId`]'s domain,
        /// so the packed slot decodes it as `None`).
        const NO_CHILD: u32 = u32::MAX;

        /// `Row.flags`: the subtree carries dirt.
        const FLAG_DIRTY: u8 = 1;
        /// `Row.flags`: orphaned by a payload replacement.
        const FLAG_DEAD: u8 = 1 << 1;
        /// `Row.flags`: scanned out of an authored payload (browse-only).
        const FLAG_AUTHORED: u8 = 1 << 2;
        /// `Row.flags`: the child slot holds a parsed layer.
        const FLAG_OPENED: u8 = 1 << 3;
        /// `Row.flags`: the child slot holds a resident fault index.
        const FLAG_FAULT: u8 = 1 << 4;
        /// `Row.flags`: the row itself has pending undo entries.
        const FLAG_OWN_HIST: u8 = 1 << 5;
        /// `Row.flags`: the subtree holds pending undo entries (the row's
        /// own or a descendant's).
        const FLAG_HIST: u8 = 1 << 6;
        $crate::revise::groupless::revising_machine!(@alias_flag $cap);

        $crate::_macro::define_valid_range_type! {
            /// A layer-table coordinate: minted by layer publication,
            /// judgment-free downstream. The excluded top value keeps
            /// `Option` free.
            struct LayerId(u32 as u32 in 0..=4_294_967_294) with new, new_unchecked;

            /// A source-run coordinate: minted once per source scan,
            /// judgment-free downstream. The excluded top value keeps
            /// `Option` free.
            struct SourceRunId(u32 as u32 in 0..=4_294_967_294) with min, new;
        }

        impl LayerId {
            /// The layer-table index this coordinate names.
            #[inline]
            #[allow(
                clippy::as_conversions,
                reason = "layer coordinates fit usize on the crate's 32/64-bit targets"
            )]
            const fn index(self) -> usize {
                self.as_inner() as usize
            }
        }

        impl SourceRunId {
            /// The run-table index this coordinate names.
            #[inline]
            #[allow(
                clippy::as_conversions,
                reason = "run coordinates fit usize on the crate's 32/64-bit targets"
            )]
            const fn index(self) -> usize {
                self.as_inner() as usize
            }
        }

        /// One materialized layer: both sibling-chain anchors, the counts
        /// of direct members whose subtree holds dirt and pending
        /// history, and the source run its rows were minted in.
        ///
        /// `source` is `None` for authored backings — their rows own no
        /// hex. A layer whose container's slot re-seals is simply never
        /// reached again; its entry stays behind, inert.
        struct Layer {
            /// The chain head.
            first: Option<RowId>,
            /// The chain tail — the tail-append anchor.
            last: Option<RowId>,
            /// Direct members whose subtree carries dirt.
            dirty_kids: u32,
            /// Direct members whose subtree holds pending history.
            history_kids: u32,
            /// The run of source-backed rows this layer's scan minted.
            source: Option<SourceRunId>,
        }

        const _: () = assert!(core::mem::size_of::<Layer>() == 20);

        impl Layer {
            /// The flagged-member count one mark maintains.
            const fn count(&self, mark: Mark) -> u32 {
                match mark {
                    Mark::Dirt => self.dirty_kids,
                    Mark::Hist => self.history_kids,
                }
            }

            /// Mutable twin of [`Layer::count`].
            const fn count_mut(&mut self, mark: Mark) -> &mut u32 {
                match mark {
                    Mark::Dirt => &mut self.dirty_kids,
                    Mark::Hist => &mut self.history_kids,
                }
            }
        }

        #[doc = concat!(" A subtree aggregate the ", $noun, " maintains. Both marks share")]
        /// one shape: a flag per row, a flagged-direct-member count per
        /// layer, and the same rising/falling climb with early stop.
        #[derive(Clone, Copy)]
        enum Mark {
            /// Pending observable change — the save's pruning judgment.
            Dirt,
            /// Pending undo entries — the backing flip's interior gate.
            Hist,
        }

        impl Mark {
            /// The row flag this mark rides.
            const fn flag(self) -> u8 {
                match self {
                    Self::Dirt => FLAG_DIRTY,
                    Self::Hist => FLAG_HIST,
                }
            }

            /// Whether the row holds the mark by itself, kids aside.
            const fn own(self, row: &Row) -> bool {
                match self {
                    Self::Dirt => row.edit.own_dirty(),
                    Self::Hist => row.own_hist(),
                }
            }
        }

        /// One source scan's arena range: ids `first..end` were minted by
        /// a single scan over document bytes, so their offsets ascend and
        /// the reverse index bisects them. Immutable once pushed.
        struct SourceRun {
            /// The first row the scan minted.
            first: RowId,
            /// One past the last arena index the scan minted; may sit one
            /// past `RowId`'s domain top.
            end: u32,
        }

        const _: () = assert!(core::mem::size_of::<SourceRun>() == 8);

        /// A container row's child-slot state.
        #[derive(Clone, Copy, PartialEq, Eq, Debug)]
        enum Slot {
            /// Never parsed (every scalar; a LEN before its first descend).
            Unopened,
            /// Parsed: the layer descriptor (present even for an empty
            /// interior, so insertion always finds its anchors).
            Opened(LayerId),
            /// Parse halted: the resident verdict's index in the fault
            /// table.
            Fault(u32),
        }

    };
    (@alias_flag plain) => {};
    (@alias_flag $cap:ident) => {
        /// `Row.flags`: output-authored identity over source-zone
        /// geometry — a local whole-record copy's row, or one scanned
        /// out of a transfer's retained source-backed interior. The
        /// geometry stays readable (the save emits it), while the
        /// public identity answers (status, spans, reverse lookup,
        /// designation) speak the authored side.
        const FLAG_ALIAS: u8 = 1 << 7;
    };
    (@row tolerant, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
        /// One record row. The arena is the tree: parent and sibling links
        /// thread it, so every walk in this module climbs instead of
        /// recursing.
        ///
        /// Widths are stored input facts: tolerant admission accepts
        /// padded framing, so geometry and the save's verbatim windows are
        /// rebuilt from the width the scan actually met, never re-derived
        /// from the value it decoded. The two width columns ride the
        /// padding bytes the session's row shape leaves free — the row
        /// stays 36 bytes.
        #[derive(Clone, Copy)]
        struct Row {
            field: FieldNumber,
            /// Source offset in the backing zone; `None` for
            /// command-authored rows (which never turn `Intact`, so every
            /// `Intact` row carries an offset).
            at: Option<At32>,
            /// Exclusive record end in the backing zone; meaningless when
            /// `at` is `None`. A record may end exactly at the zone cap
            /// (`At32::MAX + 1`), one past [`At32`]'s domain.
            end: u32,
            parent: Option<RowId>,
            next: Option<RowId>,
            /// [`Slot`] payload; the discriminant lives in `flags`.
            kids: u32,
            edit: Edit,
            kind: RecordKind,
            flags: u8,
            /// The head tag's actual input width; `None` for authored
            /// rows, which have no source geometry.
            tag_width: Option<WordWidth>,
            /// The LEN length prefix's actual input width. `None` for
            /// scalars and authored rows.
            delim_width: Option<WordWidth>,
        }

        const _: () = assert!(core::mem::size_of::<Edit>() == 8);
        const _: () = assert!(core::mem::size_of::<Row>() == 36);

    };
    (@row canonical, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
        /// One record row. The arena is the tree: parent and sibling links
        /// thread it, so every walk in this module climbs instead of
        /// recursing.
        #[derive(Clone, Copy)]
        struct Row {
            field: FieldNumber,
            /// Source offset in the backing zone; `None` for
            /// command-authored rows (which never turn `Intact`, so every
            /// `Intact` row carries an offset).
            at: Option<At32>,
            /// Exclusive record end in the backing zone; meaningless when
            /// `at` is `None`. A record may end exactly at the zone cap
            /// (`At32::MAX + 1`), one past [`At32`]'s domain.
            end: u32,
            parent: Option<RowId>,
            next: Option<RowId>,
            /// [`Slot`] payload; the discriminant lives in `flags`.
            kids: u32,
            edit: Edit,
            kind: RecordKind,
            flags: u8,
        }

        const _: () = assert!(core::mem::size_of::<Edit>() == 8);
        const _: () = assert!(core::mem::size_of::<Row>() == 36);

    };
    (@row_ctor $cap:ident tolerant, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// A freshly scanned record.
            #[allow(
                clippy::too_many_arguments,
                reason = "the scan hands every stored input fact at the mint; a parameter struct
                          would just respell the row"
            )]
            const fn scanned(
                field: FieldNumber,
                kind: RecordKind,
                at: u32,
                end: u32,
                tag_width: WordWidth,
                delim_width: Option<WordWidth>,
                parent: Option<RowId>,
                authored: bool,
            ) -> Self {
                // SAFETY: record offsets are strictly below their zone's
                // end, and both zones cap under `At32::MAX + 1` (the
                // admission cap and the store's span-end judgment).
                let at = unsafe { At32::new_unchecked(at) };
                Self {
                    field,
                    at: Some(at),
                    end,
                    parent,
                    next: None,
                    kids: NO_CHILD,
                    edit: Edit::Intact,
                    kind,
                    flags: if authored { FLAG_AUTHORED } else { 0 },
                    tag_width: Some(tag_width),
                    delim_width,
                }
            }

            /// A command-authored record, born as its own ghost: the
            /// insert command logs this state as the row's past and then
            /// transitions it live, so reverting the birth shrouds it.
            const fn authored(
                field: FieldNumber,
                kind: RecordKind,
                parent: Option<RowId>,
                next: Option<RowId>,
                value: ValueAt,
            ) -> Self {
                Self {
                    field,
                    at: None,
                    end: 0,
                    parent,
                    next,
                    kids: NO_CHILD,
                    edit: Edit::InsertedDeleted(value),
                    kind,
                    flags: 0,
                    tag_width: None,
                    delim_width: None,
                }
            }

            $crate::revise::groupless::revising_machine!(@row_ctor_transfer $cap tolerant);

            /// Stored widths as coordinate-class integers (zero when
            /// absent — every use sits behind a base or kind dispatch that
            /// proves presence).
            fn tag_w(&self) -> u32 {
                self.tag_width.map_or(0, WordWidth::w)
            }

            fn delim_w(&self) -> u32 {
                self.delim_width.map_or(0, WordWidth::w)
            }

    };
    (@row_ctor $cap:ident canonical, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// A freshly scanned record.
            const fn scanned(
                field: FieldNumber,
                kind: RecordKind,
                at: u32,
                end: u32,
                parent: Option<RowId>,
                authored: bool,
            ) -> Self {
                // SAFETY: record offsets are strictly below their zone's
                // end, and both zones cap under `At32::MAX + 1` (the
                // carrier cap and the store's span-end judgment).
                let at = unsafe { At32::new_unchecked(at) };
                Self {
                    field,
                    at: Some(at),
                    end,
                    parent,
                    next: None,
                    kids: NO_CHILD,
                    edit: Edit::Intact,
                    kind,
                    flags: if authored { FLAG_AUTHORED } else { 0 },
                }
            }

            /// A command-authored record, born as its own ghost: the
            /// insert command logs this state as the row's past and then
            /// transitions it live, so reverting the birth shrouds it.
            const fn authored(
                field: FieldNumber,
                kind: RecordKind,
                parent: Option<RowId>,
                next: Option<RowId>,
                value: ValueAt,
            ) -> Self {
                Self {
                    field,
                    at: None,
                    end: 0,
                    parent,
                    next,
                    kids: NO_CHILD,
                    edit: Edit::InsertedDeleted(value),
                    kind,
                    flags: 0,
                }
            }

            $crate::revise::groupless::revising_machine!(@row_ctor_transfer $cap canonical);

    };
    (@row_ctor_transfer plain $acc:ident) => {};
    (@row_ctor_transfer $cap:ident tolerant) => {
            /// A local whole-record copy's row: the source occurrence's
            /// exact geometry under an output-authored identity, born as
            /// its own ghost (the awakening transition is the command's
            /// one logged step). The interior starts opaque — a later
            /// explicit descent parses the retained source-backed bytes.
            const fn cloned_alias(&self, parent: Option<RowId>, next: Option<RowId>) -> Self {
                Self {
                    field: self.field,
                    at: self.at,
                    end: self.end,
                    parent,
                    next,
                    kids: NO_CHILD,
                    edit: Edit::SourceRecordDeleted,
                    kind: self.kind,
                    flags: FLAG_ALIAS,
                    tag_width: self.tag_width,
                    delim_width: self.delim_width,
                }
            }

            /// A transfer-authored record, born as its own ghost: a
            /// designated-payload insertion or an imported record, whose
            /// state carries the coordinates.
            const fn transfer_authored(
                field: FieldNumber,
                kind: RecordKind,
                parent: Option<RowId>,
                next: Option<RowId>,
                edit: Edit,
            ) -> Self {
                Self {
                    field,
                    at: None,
                    end: 0,
                    parent,
                    next,
                    kids: NO_CHILD,
                    edit,
                    kind,
                    flags: 0,
                    tag_width: None,
                    delim_width: None,
                }
            }
    };
    (@row_ctor_transfer $cap:ident canonical) => {
            /// A local whole-record copy's row: the source occurrence's
            /// exact geometry under an output-authored identity, born as
            /// its own ghost (the awakening transition is the command's
            /// one logged step). The interior starts opaque — a later
            /// explicit descent parses the retained source-backed bytes.
            const fn cloned_alias(&self, parent: Option<RowId>, next: Option<RowId>) -> Self {
                Self {
                    field: self.field,
                    at: self.at,
                    end: self.end,
                    parent,
                    next,
                    kids: NO_CHILD,
                    edit: Edit::SourceRecordDeleted,
                    kind: self.kind,
                    flags: FLAG_ALIAS,
                }
            }

            /// A transfer-authored record, born as its own ghost: a
            /// designated-payload insertion or an imported record, whose
            /// state carries the coordinates.
            const fn transfer_authored(
                field: FieldNumber,
                kind: RecordKind,
                parent: Option<RowId>,
                next: Option<RowId>,
                edit: Edit,
            ) -> Self {
                Self {
                    field,
                    at: None,
                    end: 0,
                    parent,
                    next,
                    kids: NO_CHILD,
                    edit,
                    kind,
                    flags: 0,
                }
            }
    };
    (@row_impl $cap:ident, acc: $acc:ident, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
        impl Row {
            $crate::revise::groupless::revising_machine!(@row_ctor $cap $acc, Machine: $Machine, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod);
            const fn dirty(&self) -> bool {
                self.flags & FLAG_DIRTY != 0
            }

            const fn dead(&self) -> bool {
                self.flags & FLAG_DEAD != 0
            }

            const fn set_dead(&mut self) {
                self.flags |= FLAG_DEAD;
            }

            const fn authored_zone(&self) -> bool {
                self.flags & FLAG_AUTHORED != 0
            }

            $crate::revise::groupless::revising_machine!(@row_alias $cap);

            const fn own_hist(&self) -> bool {
                self.flags & FLAG_OWN_HIST != 0
            }

            /// The subtree-history mark, read only by the lattice oracle
            /// (the maintenance climbs address flags through [`Mark`]).
            #[cfg(debug_assertions)]
            const fn hist(&self) -> bool {
                self.flags & FLAG_HIST != 0
            }

            const fn slot(&self) -> Slot {
                if self.flags & FLAG_OPENED != 0 {
                    // SAFETY: `set_slot` stores only minted layer ids under
                    // `FLAG_OPENED`.
                    Slot::Opened(unsafe { LayerId::new_unchecked(self.kids) })
                } else if self.flags & FLAG_FAULT != 0 {
                    Slot::Fault(self.kids)
                } else {
                    Slot::Unopened
                }
            }

            const fn set_slot(&mut self, slot: Slot) {
                self.flags &= !(FLAG_OPENED | FLAG_FAULT);
                match slot {
                    Slot::Unopened => self.kids = NO_CHILD,
                    Slot::Opened(layer) => {
                        self.flags |= FLAG_OPENED;
                        self.kids = layer.as_inner();
                    }
                    Slot::Fault(index) => {
                        self.flags |= FLAG_FAULT;
                        self.kids = index;
                    }
                }
            }
        }

    };
    (@witness_points $cap:ident, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
        /// The source offset of a scanned row — one whose edit sits
        /// outside the `Inserted` family. The proof spans two fields
        /// (`Row::edit` and `Row::at`) and neither type can carry it
        /// alone, so this is the invariant's single witness point;
        /// callers bind the offset here once and pass it onward.
        ///
        /// # Safety
        ///
        /// `row.edit` must lie outside the `Inserted` family (the caller
        /// has just matched that arm): command-authored rows are born
        /// `Inserted` and every edit transition is closed over the family,
        /// so such a row was pushed by the scan, which always records its
        /// offset.
        const unsafe fn scanned_at(row: &Row) -> At32 {
            match row.at {
                Some(at) => at,
                // SAFETY: the function's precondition — outside the
                // Inserted family means scan-pushed, and the scan records
                // offsets.
                None => unsafe { core::hint::unreachable_unchecked() },
            }
        }

        /// The source offset of a run row — the reverse index's witness
        /// point, sibling to [`scanned_at`]: callers bind the offset here
        /// once instead of re-testing an `Option` the run contract already
        /// proves on every bisection step.
        ///
        /// # Safety
        ///
        /// `row` must be a row of a published source run: run rows are
        /// pushed only by the scan through [`Row::scanned`], which always
        /// records an offset.
        const unsafe fn run_at(row: &Row) -> At32 {
            match row.at {
                Some(at) => at,
                // SAFETY: the function's precondition — run rows are
                // scan-pushed, and the scan records offsets.
                None => unsafe { core::hint::unreachable_unchecked() },
            }
        }

        $crate::revise::groupless::revising_machine!(@import_value_at $cap);

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
        enum LayerHalt {
            Wire(Fault),
            Refused(Refusal),
            Resource,
            Exhausted,
        }

        #[cold]
        const fn layer_wire(at: u32, kind: FaultKind) -> LayerHalt {
            LayerHalt::Wire(Fault { at, kind })
        }

        #[cold]
        const fn layer_refusal(refusal: Refusal) -> LayerHalt {
            LayerHalt::Refused(refusal)
        }

        #[cold]
        const fn layer_resource(_refused: TryReserveError) -> LayerHalt {
            LayerHalt::Resource
        }

        /// Reserves and mints the next row coordinate.
        fn mint_row(rows: &mut Vec<Row>) -> Result<RowId, LayerHalt> {
            rows.try_reserve(1).map_err(layer_resource)?;
            u32::try_from(rows.len()).ok().and_then(RowId::new).ok_or(LayerHalt::Exhausted)
        }

        /// The arena length as a run bound: every id was minted through
        /// the [`RowId`] judgment, so the length always fits.
        #[allow(clippy::as_conversions, reason = "row minting judged every id, bounding the length")]
        const fn arena_end(rows: &[Row]) -> u32 {
            rows.len() as u32
        }

    };
    (@len_witness tolerant) => {
        /// The scanned value's own offset: past the tag. The value's
        /// bytes follow it inside the sealed zone, so the sum stays
        /// below the zone's admitted end.
        const fn scanned_value_at(at: At32, tag_w: u32) -> At32 {
            // SAFETY: the scan bound `at` and the tag width to a record
            // whose value bytes follow the tag inside the sealed zone.
            unsafe { At32::new_unchecked(at.as_inner() + tag_w) }
        }

    };
    (@len_witness canonical) => {};
    (@row_alias plain) => {};
    (@row_alias $cap:ident) => {
            const fn alias(&self) -> bool {
                self.flags & FLAG_ALIAS != 0
            }
    };
    (@import_value_at plain) => {};
    (@import_value_at $cap:ident) => {
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
    (@head_width tolerant, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
    };
    (@head_width canonical, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
        /// The minimal width of a record's head tag.
        const fn head_width(field: FieldNumber, kind: RecordKind) -> u32 {
            encoded_len32(head_word(field, kind))
        }

    };
    (@scan tolerant, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
        /// Scans one flat layer of `bytes[start..end]` into provisional
        /// rows under `parent`; the layer's chain anchors are the return.
        /// Widths ride onto the rows as scanned — tolerant admission
        /// accepts padded framing, so nothing downstream may re-derive
        /// them from values. On any halt the caller discards the
        /// provisional tail; nothing here touches published state.
        fn scan_layer(
            rows: &mut Vec<Row>,
            bytes: &[u8],
            authored: bool,
            start: u32,
            end: u32,
            parent: Option<RowId>,
        ) -> Result<(Option<RowId>, Option<RowId>), LayerHalt> {
            debug_assert!(usize_of(end) <= bytes.len());
            let extent = usize_of(end);
            let mut first: Option<RowId> = None;
            // The previous sibling in the layer.
            let mut last: Option<RowId> = None;
            let mut pos = start;
            while pos < end {
                // SAFETY: the extent is bounded by the sealed zone's length
                // (the moved-in source, or the store's never-truncated byte
                // column), restated by the debug assertion above.
                let (word, tag_width) = unsafe { slice::tag_word_trusted(bytes, usize_of(pos), extent) }
                    .map_err(|fault| layer_wire(pos, FaultKind::Tag { fault }))?;
                let Some(field) = FieldNumber::from_word(word) else {
                    return Err(layer_wire(pos, FaultKind::FieldZero));
                };
                let low3 = Low3::from_word(word);
                let kind = match classify(low3) {
                    TagClass::Record(kind) => kind,
                    TagClass::GroupCode => {
                        return Err(layer_refusal(Refusal::GroupCode { at: pos, field, low3 }));
                    }
                    TagClass::Unassigned => {
                        return Err(layer_wire(pos, FaultKind::Unassigned { field, low3 }));
                    }
                };
                let value_at = pos + u32::from(tag_width);
                // SAFETY: framing words live in five-byte windows, so the
                // kernel's tag width is in the 1..=5 domain.
                let tag_width = unsafe { WordWidth::met_unchecked(tag_width) };
                let (delim_width, record_end) = match kind {
                    RecordKind::Varint => {
                        // SAFETY: same sealed extent as the tag read above.
                        let (_, width) =
                            unsafe { slice::value64_trusted(bytes, usize_of(value_at), extent) }
                                .map_err(|fault| layer_wire(value_at, FaultKind::Value { field, fault }))?;
                        (None, value_at + u32::from(width))
                    }
                    RecordKind::I32 | RecordKind::I64 => {
                        let need = if matches!(kind, RecordKind::I32) { 4 } else { 8 };
                        let have = end - value_at;
                        if have < need {
                            return Err(layer_wire(value_at, FaultKind::PayloadCut { field, need, have }));
                        }
                        (None, value_at + need)
                    }
                    RecordKind::Len => {
                        // SAFETY: same sealed extent as the tag read above.
                        let (len, width) =
                            unsafe { slice::len_word_trusted(bytes, usize_of(value_at), extent) }
                                .map_err(|fault| layer_wire(value_at, FaultKind::Len { field, fault }))?;
                        let body = value_at + u32::from(width);
                        if u64::from(body) + u64::from(len.as_inner()) > u64::from(end) {
                            return Err(layer_wire(
                                body,
                                FaultKind::PayloadCut { field, need: len.as_inner(), have: end - body },
                            ));
                        }
                        // SAFETY: length prefixes live in five-byte windows.
                        (Some(unsafe { WordWidth::met_unchecked(width) }), body + len.as_inner())
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
                // The reservation in `mint_row` covers this push.
                rows.push(Row::scanned(
                    field,
                    kind,
                    pos,
                    record_end,
                    tag_width,
                    delim_width,
                    parent,
                    authored,
                ));
                last = Some(id);
                pos = record_end;
            }
            Ok((first, last))
        }

    };
    (@scan canonical, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
        /// Scans one flat layer of `bytes[start..end]` into provisional
        /// rows under `parent`; the layer's chain anchors are the return.
        /// On any halt the caller discards the provisional tail; nothing
        /// here touches published state.
        fn scan_layer(
            rows: &mut Vec<Row>,
            bytes: &[u8],
            authored: bool,
            start: u32,
            end: u32,
            parent: Option<RowId>,
        ) -> Result<(Option<RowId>, Option<RowId>), LayerHalt> {
            debug_assert!(usize_of(end) <= bytes.len());
            let extent = usize_of(end);
            let mut first: Option<RowId> = None;
            // The previous sibling in the layer.
            let mut last: Option<RowId> = None;
            let mut pos = start;
            while pos < end {
                // SAFETY: the extent is bounded by the sealed zone's length
                // (the document seal, or the store's never-truncated byte
                // column), restated by the debug assertion above.
                let (word, tag_width) = unsafe { slice::tag_word_trusted(bytes, usize_of(pos), extent) }
                    .map_err(|fault| layer_wire(pos, FaultKind::Tag { fault }))?;
                if u32::from(tag_width) > encoded_len32(word) {
                    return Err(layer_refusal(Refusal::NonMinimalTag { at: pos, width: tag_width }));
                }
                let Some(field) = FieldNumber::from_word(word) else {
                    return Err(layer_wire(pos, FaultKind::FieldZero));
                };
                let low3 = Low3::from_word(word);
                let kind = match classify(low3) {
                    TagClass::Record(kind) => kind,
                    TagClass::GroupCode => {
                        return Err(layer_refusal(Refusal::GroupCode { at: pos, field, low3 }));
                    }
                    TagClass::Unassigned => {
                        return Err(layer_wire(pos, FaultKind::Unassigned { field, low3 }));
                    }
                };
                let value_at = pos + u32::from(tag_width);
                let record_end = match kind {
                    RecordKind::Varint => {
                        // SAFETY: same sealed extent as the tag read above.
                        let (value, width) =
                            unsafe { slice::value64_trusted(bytes, usize_of(value_at), extent) }
                                .map_err(|fault| layer_wire(value_at, FaultKind::Value { field, fault }))?;
                        if u32::from(width) > encoded_len64(value) {
                            return Err(layer_refusal(Refusal::NonMinimalValue {
                                at: value_at,
                                field,
                                width,
                            }));
                        }
                        value_at + u32::from(width)
                    }
                    RecordKind::I32 | RecordKind::I64 => {
                        let need = if matches!(kind, RecordKind::I32) { 4 } else { 8 };
                        let have = end - value_at;
                        if have < need {
                            return Err(layer_wire(value_at, FaultKind::PayloadCut { field, need, have }));
                        }
                        value_at + need
                    }
                    RecordKind::Len => {
                        // SAFETY: same sealed extent as the tag read above.
                        let (len, width) =
                            unsafe { slice::len_word_trusted(bytes, usize_of(value_at), extent) }
                                .map_err(|fault| layer_wire(value_at, FaultKind::Len { field, fault }))?;
                        if u32::from(width) > encoded_len32(len.as_inner()) {
                            return Err(layer_refusal(Refusal::NonMinimalLen {
                                at: value_at,
                                field,
                                width,
                            }));
                        }
                        let body = value_at + u32::from(width);
                        if u64::from(body) + u64::from(len.as_inner()) > u64::from(end) {
                            return Err(layer_wire(
                                body,
                                FaultKind::PayloadCut { field, need: len.as_inner(), have: end - body },
                            ));
                        }
                        body + len.as_inner()
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
                // The reservation in `mint_row` covers this push.
                rows.push(Row::scanned(field, kind, pos, record_end, parent, authored));
                last = Some(id);
                pos = record_end;
            }
            Ok((first, last))
        }

    };
    (@machine_helpers $src:ident, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
        // ─── the machine ───

        #[cold]
        const fn edit_resource(_refused: TryReserveError) -> EditFault {
            EditFault::Resource
        }

        #[cold]
        const fn edit_store_fault(fault: StoreFault) -> EditFault {
            match fault {
                StoreFault::Resource => EditFault::Resource,
                StoreFault::Exhausted => EditFault::IndexSpaceExhausted,
            }
        }

        #[cold]
        const fn save_alloc(_refused: TryReserveError) -> SaveFault {
            SaveFault::Resource
        }

        $crate::revise::groupless::revising_machine!(@open_resource $src);

        #[doc = concat!(" The arena gate: forged handles (coordinates the ", $noun, " never")]
        /// minted) panic right here on the index bound.
        #[track_caller]
        const fn gate(rows: &[Row], handle: Handle) -> &Row {
            &rows[handle.0.index()]
        }

        /// A live witness for value commands: the gated row is neither
        /// dead, authored-backed, shrouded, nor of another kind — the
        /// carried state is everything a setter may transition from.
        #[derive(Clone, Copy)]
        enum LiveEdit {
            Virgin,
            Replaced,
            Inserted,
        }

        impl LiveEdit {
            /// The state a fresh store value transitions this witness to.
            const fn set(self, value: ValueAt) -> Edit {
                match self {
                    Self::Virgin | Self::Replaced => Edit::Replaced(value),
                    Self::Inserted => Edit::Inserted(value),
                }
            }
        }

        /// An insertion's resolved splice point, proven before anything is
        /// occupied: the parent is an open container and the predecessor
        /// is a live chain member.
        #[derive(Clone, Copy)]
        struct InsertPlan {
            parent: Option<RowId>,
            prev: Option<RowId>,
        }

    };
    // The open doors' resource folding rides the buffered tenures:
    // a stream cell has no open door and no `OpenFault` to fold
    // into.
    (@open_resource stream) => {};
    (@open_resource $src:ident) => {
        #[cold]
        const fn open_resource(_refused: TryReserveError) -> OpenFault {
            OpenFault::Resource
        }
    };
    // The cross-save recipe link: a buffered cell names its own
    // crate module; a stream cell's buffered twin may be absent
    // from the build, so it points at the shared layer relatively.
    (@recipe_doc stream, $noun:literal) => {
        " cross-save identity recipe in [the shared layer](super) composes"
    };
    (@recipe_doc $src:ident, $noun:literal) => {
        concat!(" cross-save identity recipe in [`crate::", $noun, "`] composes")
    };
    (@word_enum tolerant, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
        /// An authored scalar value headed for the output, its emission
        /// width priced once.
        #[derive(Clone, Copy)]
        enum Word {
            /// A varint word, emitted minimally.
            Varint(u64),
            /// Four little-endian bytes.
            Bits32(u32),
            /// Eight little-endian bytes.
            Bits64(u64),
        }

        impl Word {
            /// The value's emission width in bytes.
            const fn width(self) -> u32 {
                match self {
                    Self::Varint(word) => encoded_len64(word),
                    Self::Bits32(_) => 4,
                    Self::Bits64(_) => 8,
                }
            }
        }

    };
    (@word_enum canonical, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
    };
    (@size_frame tolerant, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
        /// One frame of the size pass's container spine (this dialect's
        /// only containers are LENs).
        struct SizeFrame {
            /// Where the walk resumes after the close.
            next: Option<RowId>,
            /// The enclosing accumulator, restored at close.
            outer: u64,
            /// The body's slot in the size table.
            slot: usize,
            /// The source prefix's met width (the verbatim candidate);
            /// `None` on authored spines, which carry no source prefix.
            prefix_w: Option<WordWidth>,
            /// The source body length (the verbatim criterion). In the
            /// length class; `u32::MAX` on authored spines keeps the
            /// criterion from firing. It stays a raw word: the typed
            /// option's discriminant check costs the size walk a branch.
            src_len: u32,
            /// Source offset, for the over-cap fault; in [`At32`]'s
            /// domain (`0` stands in for authored spines, which have no
            /// source geometry).
            at: u32,
            /// The tag width (the tag rides verbatim): met on source and
            /// import spines (moved from row or import geometry),
            /// minimal on authored spines (minted from the head in
            /// hand).
            tag_w: WordWidth,
        }

    };
    (@size_frame canonical, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
        /// One frame of the size pass's container spine (this dialect's
        /// only containers are LENs).
        struct SizeFrame {
            /// Where the walk resumes after the close.
            next: Option<RowId>,
            /// The enclosing accumulator, restored at close.
            outer: u64,
            /// The dirty LEN's head word.
            head: u32,
            /// The body's slot in the size table.
            slot: usize,
            /// Source offset, for the over-cap fault.
            at: At32,
        }

    };
    (@arm_enum plain tolerant, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
        /// The save passes' verdict for one row, every value resolved at
        /// judgment time so neither pass re-derives anything. The Re arms
        /// are the fidelity contract's letter: a replaced record keeps its
        /// source tag bytes verbatim, and a LEN prefix rides verbatim
        /// while its body length is unchanged. Windows are scanned
        /// geometry: starts sit in [`At32`]'s domain, exclusive ends
        /// (`Clean.end` included) reach at most the zone cap
        /// (`At32::MAX + 1`), and `src_len` sits in the length class.
        /// The raw window words stay raw: a typed niche in these
        /// variants reorders their field layout and shifts the save
        /// walks' emitted code.
        enum Arm {
            /// Shrouded or ghost: contributes nothing.
            Skip,
            /// A clean scanned subtree: copied verbatim from the source.
            Clean { at: At32, end: u32 },
            /// A replaced scalar: source tag verbatim, then the value.
            ReValue { tag_at: u32, tag_end: u32, value: Word },
            /// An authored scalar: minimal head, then the value.
            NewValue { head: u32, value: Word },
            /// A replaced LEN: source tag verbatim; the prefix rides
            /// verbatim iff the authored payload keeps the source length.
            ReBody { tag_at: u32, tag_end: u32, prefix_end: u32, src_len: u32, value: ValueAt },
            /// An authored LEN: minimal head, prefix, payload.
            NewBody { head: u32, value: ValueAt },
            /// A source-framed LEN with an edited interior: recurse; the
            /// prefix rides verbatim iff the interior lands back on the
            /// source length.
            Spine { tag_at: u32, tag_end: u32, prefix_end: u32, src_len: u32, first: Option<RowId> },
        }

    };
    (@arm_enum plain canonical, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
        /// The save passes' verdict for one row, every value resolved at
        /// judgment time so neither pass re-derives anything.
        /// `Clean.end` is the row's exclusive end, at most the zone cap
        /// (`At32::MAX + 1`).
        enum Arm {
            /// Shrouded or ghost: contributes nothing.
            Skip,
            /// A clean scanned subtree: copied verbatim from the document.
            Clean { at: At32, end: u32 },
            /// A canonical varint record.
            Varint { head: u32, word: u64 },
            /// A canonical fixed 32-bit record.
            Bits32 { head: u32, bits: u32 },
            /// A canonical fixed 64-bit record.
            Bits64 { head: u32, bits: u64 },
            /// A LEN emitting an authored payload wholesale.
            Body { head: u32, value: ValueAt },
            /// A LEN with an edited interior: recurse; the body size is
            /// the size pass's obligation.
            Spine { head: u32, first: Option<RowId>, at: At32 },
        }

        /// Where a dirty row's value bytes come from: the store for
        /// authored values, the bound scan offset for source-backed ones.
        #[derive(Clone, Copy)]
        enum Src {
            /// An authored value in the store.
            Store(ValueAt),
            /// A scanned value at this document offset.
            Doc(At32),
        }

    };
    (@arm_enum transfer tolerant, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
        /// The save passes' verdict for one row, every value resolved at
        /// judgment time so neither pass re-derives anything. The Re arms
        /// are the fidelity contract's letter: a replaced record keeps its
        /// source tag bytes verbatim, and a LEN prefix rides verbatim
        /// while its body length is unchanged. Windows are scanned
        /// geometry over their zone (the source, or an import slot):
        /// starts sit in [`At32`]'s domain, exclusive ends (`Clean.end`
        /// included) reach at most the zone cap (`At32::MAX + 1`), and
        /// `src_len` sits in the length class. An alias pair (`at`,
        /// `len`) names a possibly-empty payload subspan: an empty
        /// subspan's `at` may equal the cap. The raw window words stay
        /// raw: a typed niche in these variants reorders their field
        /// layout and shifts the save walks' emitted code.
        enum Arm {
            /// Shrouded or ghost: contributes nothing.
            Skip,
            /// A clean scanned subtree: copied verbatim from the source.
            Clean { at: At32, end: u32 },
            /// A replaced scalar: source tag verbatim, then the value.
            ReValue { tag_at: u32, tag_end: u32, value: Word },
            /// An authored scalar: minimal head, then the value.
            NewValue { head: u32, value: Word },
            /// A replaced LEN: source tag verbatim; the prefix rides
            /// verbatim iff the authored payload keeps the source length.
            ReBody { tag_at: u32, tag_end: u32, prefix_end: u32, src_len: u32, value: ValueAt },
            /// An authored LEN: minimal head, prefix, payload.
            NewBody { head: u32, value: ValueAt },
            /// A source-framed LEN with an edited interior: recurse; the
            /// prefix rides verbatim iff the interior lands back on the
            /// source length.
            Spine { tag_at: u32, tag_end: u32, prefix_end: u32, src_len: u32, first: Option<RowId> },
            /// A LEN whose payload is a designated source interior, its
            /// own tag verbatim: the prefix rides verbatim iff the
            /// designated length keeps the source length.
            ReBodyAlias { tag_at: u32, tag_end: u32, prefix_end: u32, src_len: u32, at: u32, len: u32 },
            /// An authored LEN whose payload is a designated source
            /// interior: minimal head and prefix, the subspan verbatim.
            NewBodyAlias { head: u32, at: u32, len: u32 },
            /// An authored LEN over an edited designated interior:
            /// minimal head and prefix, then the walked body.
            NewSpine { head: u32, first: Option<RowId> },
            /// An imported external record with a clean interior: its
            /// store span's exact bytes emit whole — framing included,
            /// nothing re-encoded.
            Import { value: ValueAt },
            /// An imported record with interior edits: the zone tag
            /// rides verbatim, the prefix rides verbatim iff the walked
            /// body keeps the slot's length, and the walk recurses into
            /// the first-class interior rows. All offsets index the
            /// import zone.
            ImportSpine {
                /// The record tag's window in the import zone.
                tag_at: u32,
                /// One past the tag; the LEN prefix starts here.
                tag_end: u32,
                /// One past the slot's met LEN prefix.
                prefix_end: u32,
                /// The slot's met body length.
                src_len: u32,
                /// The import slot: the interior windows' zone witness.
                value: ValueAt,
                /// The interior's first row.
                first: Option<RowId>,
            },
        }

    };
    (@arm_enum $cap:ident tolerant, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
        /// The save passes' verdict for one row, every value resolved at
        /// judgment time so neither pass re-derives anything. The Re arms
        /// are the fidelity contract's letter: a replaced record keeps its
        /// source tag bytes verbatim, and a LEN prefix rides verbatim
        /// while its body length is unchanged. Windows are scanned
        /// geometry: starts sit in [`At32`]'s domain, exclusive ends
        /// (`Clean.end` included) reach at most the zone cap
        /// (`At32::MAX + 1`), and `src_len` sits in the length class. An
        /// alias pair (`at`, `len`) names a possibly-empty payload
        /// subspan: an empty subspan's `at` may equal the cap. The raw
        /// window words stay raw: a typed niche in these variants
        /// reorders their field layout and shifts the save walks'
        /// emitted code.
        enum Arm {
            /// Shrouded or ghost: contributes nothing.
            Skip,
            /// A clean scanned subtree: copied verbatim from the source.
            Clean { at: At32, end: u32 },
            /// A replaced scalar: source tag verbatim, then the value.
            ReValue { tag_at: u32, tag_end: u32, value: Word },
            /// An authored scalar: minimal head, then the value.
            NewValue { head: u32, value: Word },
            /// A replaced LEN: source tag verbatim; the prefix rides
            /// verbatim iff the authored payload keeps the source length.
            ReBody { tag_at: u32, tag_end: u32, prefix_end: u32, src_len: u32, value: ValueAt },
            /// An authored LEN: minimal head, prefix, payload.
            NewBody { head: u32, value: ValueAt },
            /// A source-framed LEN with an edited interior: recurse; the
            /// prefix rides verbatim iff the interior lands back on the
            /// source length.
            Spine { tag_at: u32, tag_end: u32, prefix_end: u32, src_len: u32, first: Option<RowId> },
            /// A LEN whose payload is a designated source interior, its
            /// own tag verbatim: the prefix rides verbatim iff the
            /// designated length keeps the source length.
            ReBodyAlias { tag_at: u32, tag_end: u32, prefix_end: u32, src_len: u32, at: u32, len: u32 },
            /// An authored LEN whose payload is a designated source
            /// interior: minimal head and prefix, the subspan verbatim.
            NewBodyAlias { head: u32, at: u32, len: u32 },
            /// An authored LEN over an edited designated interior:
            /// minimal head and prefix, then the walked body.
            NewSpine { head: u32, first: Option<RowId> },
            /// An imported external record: its store span's exact bytes
            /// emit whole — framing included, nothing re-encoded.
            Import { value: ValueAt },
        }

    };
    (@arm_enum transfer canonical, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
        /// The save passes' verdict for one row, every value resolved at
        /// judgment time so neither pass re-derives anything.
        /// `Clean.end` is the row's exclusive end, at most the zone cap
        /// (`At32::MAX + 1`). `Spine.at` is the scanned offset, or an
        /// import spine's zone base; `BodyAlias` names a possibly-empty
        /// payload subspan whose `at` may equal the cap when the
        /// subspan is empty.
        enum Arm {
            /// Shrouded or ghost: contributes nothing.
            Skip,
            /// A clean scanned subtree: copied verbatim from the document.
            Clean { at: At32, end: u32 },
            /// A canonical varint record.
            Varint { head: u32, word: u64 },
            /// A canonical fixed 32-bit record.
            Bits32 { head: u32, bits: u32 },
            /// A canonical fixed 64-bit record.
            Bits64 { head: u32, bits: u64 },
            /// A LEN emitting an authored payload wholesale.
            Body { head: u32, value: ValueAt },
            /// A LEN with an edited interior: recurse; the body size is
            /// the size pass's obligation.
            Spine { head: u32, first: Option<RowId>, at: At32 },
            /// A LEN whose payload is a designated source interior:
            /// minimal head and prefix, the subspan verbatim.
            BodyAlias { head: u32, at: u32, len: u32 },
            /// An imported external record: its store span's exact bytes
            /// emit whole — the designation proved them canonical.
            Import { value: ValueAt },
        }

        /// Where a dirty row's value bytes come from: the store for
        /// authored values, the bound scan offset for source-backed ones.
        #[derive(Clone, Copy)]
        enum Src {
            /// An authored value in the store.
            Store(ValueAt),
            /// A scanned value at this document offset.
            Doc(At32),
        }

    };
    (@arm_enum $cap:ident canonical, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
        /// The save passes' verdict for one row, every value resolved at
        /// judgment time so neither pass re-derives anything.
        /// `Clean.end` is the row's exclusive end, at most the zone cap
        /// (`At32::MAX + 1`); `BodyAlias` names a possibly-empty
        /// payload subspan whose `at` may equal the cap when the
        /// subspan is empty.
        enum Arm {
            /// Shrouded or ghost: contributes nothing.
            Skip,
            /// A clean scanned subtree: copied verbatim from the document.
            Clean { at: At32, end: u32 },
            /// A canonical varint record.
            Varint { head: u32, word: u64 },
            /// A canonical fixed 32-bit record.
            Bits32 { head: u32, bits: u32 },
            /// A canonical fixed 64-bit record.
            Bits64 { head: u32, bits: u64 },
            /// A LEN emitting an authored payload wholesale.
            Body { head: u32, value: ValueAt },
            /// A LEN with an edited interior: recurse; the body size is
            /// the size pass's obligation.
            Spine { head: u32, first: Option<RowId>, at: At32 },
            /// A LEN whose payload is a designated source interior:
            /// minimal head and prefix, the subspan verbatim.
            BodyAlias { head: u32, at: u32, len: u32 },
            /// An imported external record: its store span's exact bytes
            /// emit whole — the designation proved them canonical.
            Import { value: ValueAt },
        }

        /// Where a dirty row's value bytes come from: the store for
        /// authored values, the bound scan offset for source-backed ones.
        #[derive(Clone, Copy)]
        enum Src {
            /// An authored value in the store.
            Store(ValueAt),
            /// A scanned value at this document offset.
            Doc(At32),
        }

    };
    (@out_trait transfer tolerant vec, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
        /// One save emitter: the emit pass drives these faces, and the
        /// `Vec` and sink twins implement them — one walk shape, two
        /// output custodies. Verbatim windows name their zone — the
        /// document or an import slot's bytes — and a pending run
        /// merges only within one zone, so import interiors emit from
        /// their own backing without a copy.
        trait Out<'d> {
            /// Publishes the pending verbatim run, if any.
            fn flush(&mut self);
            /// Copies `at..end` of the document, merging contiguous runs.
            fn verbatim(&mut self, at: u32, end: u32);
            /// Copies `at..end` of `zone`, merging contiguous runs
            /// within one zone; a zone crossing publishes the pending
            /// run first.
            fn verbatim_in(&mut self, zone: &'d [u8], at: u32, end: u32);
            /// Emits one minimal head word.
            fn word(&mut self, word: u32);
            /// Emits one authored scalar value.
            fn value(&mut self, value: Word);
            /// Emits one minimal varint (re-authored LEN prefixes).
            fn varint(&mut self, value: u64);
            /// Emits authored payload bytes.
            fn bytes(&mut self, bytes: &[u8]);
        }

    };
    (@out_trait $cap:ident tolerant vec, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
        /// One save emitter: the emit pass drives these faces, and the
        /// `Vec` and sink twins implement them — one walk shape, two
        /// output custodies.
        trait Out {
            /// Publishes the pending verbatim run, if any.
            fn flush(&mut self);
            /// Copies `at..end` of the source, merging contiguous runs.
            fn verbatim(&mut self, at: u32, end: u32);
            /// Emits one minimal head word.
            fn word(&mut self, word: u32);
            /// Emits one authored scalar value.
            fn value(&mut self, value: Word);
            /// Emits one minimal varint (re-authored LEN prefixes).
            fn varint(&mut self, value: u64);
            /// Emits authored payload bytes.
            fn bytes(&mut self, bytes: &[u8]);
        }

    };
    (@out_trait transfer canonical vec, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
        /// One save emitter: the emit pass drives these faces, and the
        /// `Vec` and sink twins implement them — one walk shape, two
        /// output custodies. Verbatim windows name their zone — the
        /// document or an import slot's bytes — and a pending run
        /// merges only within one zone, so import interiors emit from
        /// their own backing without a copy.
        trait Out<'d> {
            /// Publishes the pending verbatim run, if any.
            fn flush(&mut self);
            /// Copies `at..end` of the document, merging contiguous runs.
            fn verbatim(&mut self, at: u32, end: u32);
            /// Copies `at..end` of `zone`, merging contiguous runs
            /// within one zone; a zone crossing publishes the pending
            /// run first.
            fn verbatim_in(&mut self, zone: &'d [u8], at: u32, end: u32);
            /// Emits one minimal head word.
            fn word(&mut self, word: u32);
            /// Emits one minimal varint (values and LEN prefixes).
            fn varint(&mut self, value: u64);
            /// Emits four little-endian bytes.
            fn bits32(&mut self, bits: u32);
            /// Emits eight little-endian bytes.
            fn bits64(&mut self, bits: u64);
            /// Emits authored payload bytes.
            fn bytes(&mut self, bytes: &[u8]);
        }

    };
    (@out_trait $cap:ident canonical vec, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
        /// One save emitter: the emit pass drives these faces, and the
        /// `Vec` and sink twins implement them — one walk shape, two
        /// output custodies.
        trait Out {
            /// Publishes the pending verbatim run, if any.
            fn flush(&mut self);
            /// Copies `at..end` of the source, merging contiguous runs.
            fn verbatim(&mut self, at: u32, end: u32);
            /// Emits one minimal head word.
            fn word(&mut self, word: u32);
            /// Emits one minimal varint (values and LEN prefixes).
            fn varint(&mut self, value: u64);
            /// Emits four little-endian bytes.
            fn bits32(&mut self, bits: u32);
            /// Emits eight little-endian bytes.
            fn bits64(&mut self, bits: u64);
            /// Emits authored payload bytes.
            fn bytes(&mut self, bytes: &[u8]);
        }

    };
    (@out_trait transfer canonical carrier, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
        /// One save emitter: the emit pass drives these faces, and the
        /// carrier and `Vec` twins implement them — one walk shape, two
        /// output custodies. Verbatim windows name their zone — the
        /// document or an import slot's bytes — and a pending run merges
        /// only within one zone, so import interiors emit from their own
        /// backing without a copy.
        trait Out<'d> {
            /// Publishes the pending verbatim run, if any.
            fn flush(&mut self);
            /// Copies `at..end` of the document, merging contiguous runs.
            fn verbatim(&mut self, at: u32, end: u32);
            /// Copies `at..end` of `zone`, merging contiguous runs
            /// within one zone; a zone crossing publishes the pending
            /// run first.
            fn verbatim_in(&mut self, zone: &'d [u8], at: u32, end: u32);
            /// Emits one minimal head word.
            fn word(&mut self, word: u32);
            /// Emits one minimal varint (values and LEN prefixes).
            fn varint(&mut self, value: u64);
            /// Emits four little-endian bytes.
            fn bits32(&mut self, bits: u32);
            /// Emits eight little-endian bytes.
            fn bits64(&mut self, bits: u64);
            /// Emits authored payload bytes.
            fn bytes(&mut self, bytes: &[u8]);
        }

    };
    (@out_trait $cap:ident canonical carrier, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
        /// One save emitter: the emit pass drives these faces, and the
        /// carrier and `Vec` twins implement them — one walk shape, two
        /// output custodies.
        trait Out {
            /// Publishes the pending verbatim run, if any.
            fn flush(&mut self);
            /// Copies `at..end` of the document, merging contiguous runs.
            fn verbatim(&mut self, at: u32, end: u32);
            /// Emits one minimal head word.
            fn word(&mut self, word: u32);
            /// Emits one minimal varint (values and LEN prefixes).
            fn varint(&mut self, value: u64);
            /// Emits four little-endian bytes.
            fn bits32(&mut self, bits: u32);
            /// Emits eight little-endian bytes.
            fn bits64(&mut self, bits: u64);
            /// Emits authored payload bytes.
            fn bytes(&mut self, bytes: &[u8]);
        }

    };
    (@emit_carrier $cap:ident vec, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
    };
    (@emit_carrier transfer carrier, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
        /// The forward emitter: a pending verbatim run rides between
        /// writes so contiguous clean records coalesce into one copy.
        struct Emit<'d> {
            out: RawDoc,
            doc: &'d [u8],
            run: Option<(&'d [u8], u32, u32)>,
        }

        impl<'d> Out<'d> for Emit<'d> {
            fn flush(&mut self) {
                if let Some((zone, from, to)) = self.run.take() {
                    // SAFETY: scanned spans lie within their sealed zone,
                    // and a run never crosses zones.
                    self.out.put_slice(unsafe { zone.get_unchecked(usize_of(from)..usize_of(to)) });
                }
            }

            fn verbatim(&mut self, at: u32, end: u32) {
                let doc = self.doc;
                self.verbatim_in(doc, at, end);
            }

            fn verbatim_in(&mut self, zone: &'d [u8], at: u32, end: u32) {
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
                self.out.put_varint(u64::from(word));
            }

            fn varint(&mut self, value: u64) {
                self.flush();
                self.out.put_varint(value);
            }

            fn bits32(&mut self, bits: u32) {
                self.flush();
                self.out.put_bits32(bits);
            }

            fn bits64(&mut self, bits: u64) {
                self.flush();
                self.out.put_bits64(bits);
            }

            fn bytes(&mut self, bytes: &[u8]) {
                self.flush();
                self.out.put_slice(bytes);
            }
        }

    };
    (@emit_carrier $cap:ident carrier, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
        /// The forward emitter: a pending verbatim run rides between
        /// writes so contiguous clean records coalesce into one copy.
        struct Emit<'d> {
            out: RawDoc,
            doc: &'d [u8],
            run: Option<(u32, u32)>,
        }

        impl Out for Emit<'_> {
            fn flush(&mut self) {
                if let Some((from, to)) = self.run.take() {
                    // SAFETY: scanned spans lie within the sealed document.
                    self.out.put_slice(unsafe { self.doc.get_unchecked(usize_of(from)..usize_of(to)) });
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
                self.out.put_varint(u64::from(word));
            }

            fn varint(&mut self, value: u64) {
                self.flush();
                self.out.put_varint(value);
            }

            fn bits32(&mut self, bits: u32) {
                self.flush();
                self.out.put_bits32(bits);
            }

            fn bits64(&mut self, bits: u64) {
                self.flush();
                self.out.put_bits64(bits);
            }

            fn bytes(&mut self, bytes: &[u8]) {
                self.flush();
                self.out.put_slice(bytes);
            }
        }

    };
    (@vec_emit transfer tolerant vec, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
        /// The buffered emitter: the walk appends to a `Vec` whose exact
        /// reservation `save_into` already paid, so the pushes never
        /// regrow it (the closing length assert pins the pairing). A
        /// pending verbatim run rides between writes so contiguous clean
        /// records coalesce into one copy; the run carries its zone, and
        /// a zone crossing publishes it first.
        struct VecEmit<'d, 'o> {
            out: &'o mut Vec<u8>,
            doc: &'d [u8],
            run: Option<(&'d [u8], u32, u32)>,
        }

        impl<'d> Out<'d> for VecEmit<'d, '_> {
            fn flush(&mut self) {
                if let Some((zone, from, to)) = self.run.take() {
                    // SAFETY: scanned spans lie within their sealed zone,
                    // and a run never crosses zones.
                    self.out
                        .extend_from_slice(unsafe { zone.get_unchecked(usize_of(from)..usize_of(to)) });
                }
            }

            fn verbatim(&mut self, at: u32, end: u32) {
                let doc = self.doc;
                self.verbatim_in(doc, at, end);
            }

            fn verbatim_in(&mut self, zone: &'d [u8], at: u32, end: u32) {
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

    };
    (@vec_emit $cap:ident tolerant vec, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
        /// The buffered emitter: the walk appends to a `Vec` whose exact
        /// reservation `save_into` already paid, so the pushes never
        /// regrow it (the closing length assert pins the pairing). A
        /// pending verbatim run rides between writes so contiguous clean
        /// records coalesce into one copy.
        struct VecEmit<'d, 'o> {
            out: &'o mut Vec<u8>,
            doc: &'d [u8],
            run: Option<(u32, u32)>,
        }

        impl Out for VecEmit<'_, '_> {
            fn flush(&mut self) {
                if let Some((from, to)) = self.run.take() {
                    // SAFETY: scanned spans lie within the sealed document.
                    self.out
                        .extend_from_slice(unsafe { self.doc.get_unchecked(usize_of(from)..usize_of(to)) });
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

    };
    (@vec_emit transfer canonical vec, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
        /// The buffered emitter: the walk appends to a `Vec` whose exact
        /// reservation `save_into` already paid, so the pushes never
        /// regrow it (the closing length assert pins the pairing). A
        /// pending verbatim run rides between writes so contiguous clean
        /// records coalesce into one copy, merging only within one zone.
        struct VecEmit<'d, 'o> {
            out: &'o mut Vec<u8>,
            doc: &'d [u8],
            run: Option<(&'d [u8], u32, u32)>,
        }

        impl<'d> Out<'d> for VecEmit<'d, '_> {
            fn flush(&mut self) {
                if let Some((zone, from, to)) = self.run.take() {
                    // SAFETY: scanned spans lie within their sealed zone,
                    // and a run never crosses zones.
                    self.out
                        .extend_from_slice(unsafe { zone.get_unchecked(usize_of(from)..usize_of(to)) });
                }
            }

            fn verbatim(&mut self, at: u32, end: u32) {
                let doc = self.doc;
                self.verbatim_in(doc, at, end);
            }

            fn verbatim_in(&mut self, zone: &'d [u8], at: u32, end: u32) {
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

            fn varint(&mut self, value: u64) {
                self.flush();
                push64(self.out, value);
            }

            fn bits32(&mut self, bits: u32) {
                self.flush();
                self.out.extend_from_slice(&bits.to_le_bytes());
            }

            fn bits64(&mut self, bits: u64) {
                self.flush();
                self.out.extend_from_slice(&bits.to_le_bytes());
            }

            fn bytes(&mut self, bytes: &[u8]) {
                self.flush();
                self.out.extend_from_slice(bytes);
            }
        }

    };
    (@vec_emit $cap:ident canonical vec, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
        /// The buffered emitter: the walk appends to a `Vec` whose exact
        /// reservation `save_into` already paid, so the pushes never
        /// regrow it (the closing length assert pins the pairing). A
        /// pending verbatim run rides between writes so contiguous clean
        /// records coalesce into one copy.
        struct VecEmit<'d, 'o> {
            out: &'o mut Vec<u8>,
            doc: &'d [u8],
            run: Option<(u32, u32)>,
        }

        impl Out for VecEmit<'_, '_> {
            fn flush(&mut self) {
                if let Some((from, to)) = self.run.take() {
                    // SAFETY: scanned spans lie within the sealed document.
                    self.out
                        .extend_from_slice(unsafe { self.doc.get_unchecked(usize_of(from)..usize_of(to)) });
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

            fn varint(&mut self, value: u64) {
                self.flush();
                push64(self.out, value);
            }

            fn bits32(&mut self, bits: u32) {
                self.flush();
                self.out.extend_from_slice(&bits.to_le_bytes());
            }

            fn bits64(&mut self, bits: u64) {
                self.flush();
                self.out.extend_from_slice(&bits.to_le_bytes());
            }

            fn bytes(&mut self, bytes: &[u8]) {
                self.flush();
                self.out.extend_from_slice(bytes);
            }
        }

    };
        (@vec_emit transfer canonical carrier, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
        /// [`Emit`]'s `Vec` twin: the same walk appends to a caller
        /// buffer whose exact reservation `save_into` already paid, so
        /// the pushes never regrow it (the closing length assert pins the
        /// pairing).
        struct VecEmit<'d, 'o> {
            out: &'o mut Vec<u8>,
            doc: &'d [u8],
            run: Option<(&'d [u8], u32, u32)>,
        }

        impl<'d> Out<'d> for VecEmit<'d, '_> {
            fn flush(&mut self) {
                if let Some((zone, from, to)) = self.run.take() {
                    // SAFETY: scanned spans lie within their sealed zone,
                    // and a run never crosses zones.
                    self.out
                        .extend_from_slice(unsafe { zone.get_unchecked(usize_of(from)..usize_of(to)) });
                }
            }

            fn verbatim(&mut self, at: u32, end: u32) {
                let doc = self.doc;
                self.verbatim_in(doc, at, end);
            }

            fn verbatim_in(&mut self, zone: &'d [u8], at: u32, end: u32) {
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

            fn varint(&mut self, value: u64) {
                self.flush();
                push64(self.out, value);
            }

            fn bits32(&mut self, bits: u32) {
                self.flush();
                self.out.extend_from_slice(&bits.to_le_bytes());
            }

            fn bits64(&mut self, bits: u64) {
                self.flush();
                self.out.extend_from_slice(&bits.to_le_bytes());
            }

            fn bytes(&mut self, bytes: &[u8]) {
                self.flush();
                self.out.extend_from_slice(bytes);
            }
        }

    };
    (@vec_emit $cap:ident canonical carrier, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
        /// [`Emit`]'s `Vec` twin: the same walk appends to a caller
        /// buffer whose exact reservation `save_into` already paid, so
        /// the pushes never regrow it (the closing length assert pins the
        /// pairing).
        struct VecEmit<'d, 'o> {
            out: &'o mut Vec<u8>,
            doc: &'d [u8],
            run: Option<(u32, u32)>,
        }

        impl Out for VecEmit<'_, '_> {
            fn flush(&mut self) {
                if let Some((from, to)) = self.run.take() {
                    // SAFETY: scanned spans lie within the sealed document.
                    self.out
                        .extend_from_slice(unsafe { self.doc.get_unchecked(usize_of(from)..usize_of(to)) });
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

            fn varint(&mut self, value: u64) {
                self.flush();
                push64(self.out, value);
            }

            fn bits32(&mut self, bits: u32) {
                self.flush();
                self.out.extend_from_slice(&bits.to_le_bytes());
            }

            fn bits64(&mut self, bits: u64) {
                self.flush();
                self.out.extend_from_slice(&bits.to_le_bytes());
            }

            fn bytes(&mut self, bytes: &[u8]) {
                self.flush();
                self.out.extend_from_slice(bytes);
            }
        }

    };
    (@sink_emit transfer tolerant vec, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
        /// [`VecEmit`]'s sink twin: the same walk hands borrowed slices to
        /// the caller's sink — clean runs as windows of their zone,
        /// authored words through a ten-byte stack window. The written
        /// count serves the seam pin the buffered twin reads off its
        /// buffer.
        struct SinkEmit<'d, 's, F> {
            doc: &'d [u8],
            sink: &'s mut F,
            run: Option<(&'d [u8], u32, u32)>,
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

        impl<'d, F: FnMut(&[u8])> Out<'d> for SinkEmit<'d, '_, F> {
            fn flush(&mut self) {
                if let Some((zone, from, to)) = self.run.take() {
                    // SAFETY: scanned spans lie within their sealed zone,
                    // and a run never crosses zones.
                    self.hand(unsafe { zone.get_unchecked(usize_of(from)..usize_of(to)) });
                }
            }

            fn verbatim(&mut self, at: u32, end: u32) {
                let doc = self.doc;
                self.verbatim_in(doc, at, end);
            }

            fn verbatim_in(&mut self, zone: &'d [u8], at: u32, end: u32) {
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
    (@sink_emit $cap:ident tolerant vec, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
        /// [`VecEmit`]'s sink twin: the same walk hands borrowed slices to
        /// the caller's sink — clean runs as windows of the moved-in
        /// source, authored words through a ten-byte stack window. The
        /// written count serves the seam pin the buffered twin reads off
        /// its buffer.
        struct SinkEmit<'d, 's, F> {
            doc: &'d [u8],
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
                    let doc = self.doc;
                    // SAFETY: scanned spans lie within the sealed document.
                    self.hand(unsafe { doc.get_unchecked(usize_of(from)..usize_of(to)) });
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
    (@sink_emit transfer canonical vec, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
        /// [`VecEmit`]'s sink twin: the same walk hands borrowed slices to
        /// the caller's sink — clean runs as windows of their zone,
        /// authored words through a ten-byte stack window. The written
        /// count serves the seam pin the buffered twin reads off its
        /// buffer.
        struct SinkEmit<'d, 's, F> {
            doc: &'d [u8],
            sink: &'s mut F,
            run: Option<(&'d [u8], u32, u32)>,
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

        impl<'d, F: FnMut(&[u8])> Out<'d> for SinkEmit<'d, '_, F> {
            fn flush(&mut self) {
                if let Some((zone, from, to)) = self.run.take() {
                    // SAFETY: scanned spans lie within their sealed zone,
                    // and a run never crosses zones.
                    self.hand(unsafe { zone.get_unchecked(usize_of(from)..usize_of(to)) });
                }
            }

            fn verbatim(&mut self, at: u32, end: u32) {
                let doc = self.doc;
                self.verbatim_in(doc, at, end);
            }

            fn verbatim_in(&mut self, zone: &'d [u8], at: u32, end: u32) {
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

            fn varint(&mut self, value: u64) {
                self.flush();
                self.hand_varint(value);
            }

            fn bits32(&mut self, bits: u32) {
                self.flush();
                self.hand(&bits.to_le_bytes());
            }

            fn bits64(&mut self, bits: u64) {
                self.flush();
                self.hand(&bits.to_le_bytes());
            }

            fn bytes(&mut self, bytes: &[u8]) {
                self.flush();
                self.hand(bytes);
            }
        }

    };
    (@sink_emit $cap:ident canonical vec, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
        /// [`VecEmit`]'s sink twin: the same walk hands borrowed slices to
        /// the caller's sink — clean runs as windows of the source,
        /// authored words through a ten-byte stack window. The written
        /// count serves the seam pin the buffered twin reads off its
        /// buffer.
        struct SinkEmit<'d, 's, F> {
            doc: &'d [u8],
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
                    let doc = self.doc;
                    // SAFETY: scanned spans lie within the sealed document.
                    self.hand(unsafe { doc.get_unchecked(usize_of(from)..usize_of(to)) });
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

            fn varint(&mut self, value: u64) {
                self.flush();
                self.hand_varint(value);
            }

            fn bits32(&mut self, bits: u32) {
                self.flush();
                self.hand(&bits.to_le_bytes());
            }

            fn bits64(&mut self, bits: u64) {
                self.flush();
                self.hand(&bits.to_le_bytes());
            }

            fn bytes(&mut self, bytes: &[u8]) {
                self.flush();
                self.hand(bytes);
            }
        }

    };
        (@sink_emit transfer canonical carrier, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
        /// [`Emit`]'s sink twin: the same walk hands borrowed slices to
        /// the caller's sink — clean runs as windows of the sealed
        /// document, authored words through a ten-byte stack window. The
        /// written count serves the seam pin the buffered twins read off
        /// their buffers.
        struct SinkEmit<'d, 's, F> {
            doc: &'d [u8],
            sink: &'s mut F,
            run: Option<(&'d [u8], u32, u32)>,
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

        impl<'d, F: FnMut(&[u8])> Out<'d> for SinkEmit<'d, '_, F> {
            fn flush(&mut self) {
                if let Some((zone, from, to)) = self.run.take() {
                    // SAFETY: scanned spans lie within their sealed zone,
                    // and a run never crosses zones.
                    self.hand(unsafe { zone.get_unchecked(usize_of(from)..usize_of(to)) });
                }
            }

            fn verbatim(&mut self, at: u32, end: u32) {
                let doc = self.doc;
                self.verbatim_in(doc, at, end);
            }

            fn verbatim_in(&mut self, zone: &'d [u8], at: u32, end: u32) {
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

            fn varint(&mut self, value: u64) {
                self.flush();
                self.hand_varint(value);
            }

            fn bits32(&mut self, bits: u32) {
                self.flush();
                self.hand(&bits.to_le_bytes());
            }

            fn bits64(&mut self, bits: u64) {
                self.flush();
                self.hand(&bits.to_le_bytes());
            }

            fn bytes(&mut self, bytes: &[u8]) {
                self.flush();
                self.hand(bytes);
            }
        }

    };
    (@sink_emit $cap:ident canonical carrier, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
        /// [`Emit`]'s sink twin: the same walk hands borrowed slices to
        /// the caller's sink — clean runs as windows of the sealed
        /// document, authored words through a ten-byte stack window. The
        /// written count serves the seam pin the buffered twins read off
        /// their buffers.
        struct SinkEmit<'d, 's, F> {
            doc: &'d [u8],
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
                    let doc = self.doc;
                    // SAFETY: scanned spans lie within the sealed document.
                    self.hand(unsafe { doc.get_unchecked(usize_of(from)..usize_of(to)) });
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

            fn varint(&mut self, value: u64) {
                self.flush();
                self.hand_varint(value);
            }

            fn bits32(&mut self, bits: u32) {
                self.flush();
                self.hand(&bits.to_le_bytes());
            }

            fn bits64(&mut self, bits: u64) {
                self.flush();
                self.hand(&bits.to_le_bytes());
            }

            fn bytes(&mut self, bytes: &[u8]) {
                self.flush();
                self.hand(bytes);
            }
        }

    };
    (@machine_struct $Machine:ident $(<$($lt:lifetime),+>)?, store: $store_ty:ty, src_ty: $src_ty:ty, $(#[$mdoc:meta])*) => {
        $(#[$mdoc])*
        pub struct $Machine$(<$($lt),+>)? {
            source: $src_ty,
            rows: Vec<Row>,
            store: $store_ty,
            faults: Vec<SlotFault>,
            log: Vec<Transition>,
            /// The top layer's descriptor: chain anchors, aggregate
            /// counts, and the root source run.
            root: Layer,
            /// Interior-layer descriptors, minted at descend.
            layers: Vec<Layer>,
            /// Bisectable row ranges, one per source scan.
            source_runs: Vec<SourceRun>,
        }

    };
    (@snapshot tolerant, Machine: $Machine:ident) => {
            /// The private construction snapshot the cross-cell
            /// differential judges compare: row order, links, widths,
            /// edit state, layer anchors, and the source runs.
            /// Test-only.
            #[cfg(test)]
            #[allow(
                dead_code,
                reason = "the cross-cell differential judges consume each twin's \
                          snapshot; cells outside those judges keep the face their \
                          shared core emits; expect is unusable here: judge-bearing \
                          cells fulfil the lint and non-judge cells do not, within \
                          one build"
            )]
            #[allow(
                clippy::type_complexity,
                reason = "a structural tuple, shared across modules by shape alone \
                          so twin snapshots stay comparable without a shared type"
            )]
            pub(crate) fn construction_snapshot(
                &self,
            ) -> (
                Vec<(u32, Option<u32>, u32, Option<u32>, Option<u32>, u32, bool, u8, u8, u32, u32)>,
                (Option<u32>, Option<u32>, u32, u32, Option<u32>),
                Vec<(Option<u32>, Option<u32>, u32, u32, Option<u32>)>,
                Vec<(u32, u32)>,
                usize,
            ) {
                let layer = |layer: &Layer| {
                    (
                        layer.first.map(RowId::as_inner),
                        layer.last.map(RowId::as_inner),
                        layer.dirty_kids,
                        layer.history_kids,
                        layer.source.map(SourceRunId::as_inner),
                    )
                };
                let rows = self
                    .rows
                    .iter()
                    .map(|row| {
                        (
                            row.field.as_inner(),
                            row.at.map(At32::as_inner),
                            row.end,
                            row.parent.map(RowId::as_inner),
                            row.next.map(RowId::as_inner),
                            row.kids,
                            matches!(row.edit, Edit::Intact),
                            match row.kind {
                                RecordKind::Varint => 0u8,
                                RecordKind::I64 => 1,
                                RecordKind::Len => 2,
                                RecordKind::I32 => 5,
                            },
                            row.flags,
                            row.tag_w(),
                            row.delim_w(),
                        )
                    })
                    .collect();
                (
                    rows,
                    layer(&self.root),
                    self.layers.iter().map(layer).collect(),
                    self.source_runs.iter().map(|run| (run.first.as_inner(), run.end)).collect(),
                    self.log.len(),
                )
            }
    };
    (@snapshot canonical, Machine: $Machine:ident) => {};
    (@doors stream tolerant $(<$lt:lifetime>)?, store: $Store:ident, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            // ── the sealed source ──

            /// The ingested source bytes: every fed chunk,
            /// concatenated in arrival order and sealed at `finish`.
            #[inline]
            #[must_use]
            pub fn source(&self) -> &[u8] {
                &self.source
            }

            /// Releases the source buffer — the ingest doors'
            /// inverse, zero copies. Pending edits and the revision
            /// log are discarded with the machine, and the bytes come
            /// back exactly as the feeds delivered them.
            ///
            /// # Examples
            ///
            /// ```
            #[doc = concat!(" use ", $doc_mod, "::", stringify!($Machine), ";")]
            ///
            /// let msg = [0x08, 0x2A];
            #[doc = concat!(" let mut ", $noun, " = ", $door, ".unwrap();")]
            #[doc = concat!(" let first = ", $noun, ".top().next().unwrap();")]
            #[doc = concat!(" ", $noun, ".set_varint(first, 7).unwrap(); // staged, never saved")]
            #[doc = concat!(" assert_eq!(", $noun, ".into_source(), [0x08, 0x2A]);")]
            /// ```
            #[inline]
            #[must_use]
            pub fn into_source(self) -> Vec<u8> {
                self.source
            }

    };
    (@doors vec tolerant $(<$lt:lifetime>)?, store: $Store:ident, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            // ── opening ──

            /// Takes tenure of `source` and scans its top layer: zero
            /// bytes are copied (the buffer moves in), and LEN payloads
            #[doc = concat!(" wait for [`", stringify!($Machine), "::descend`].")]
            ///
            /// # Errors
            ///
            /// The refusal returns the buffer intact beside its fault —
            /// transactional tenure: [`OpenFault::TooLarge`] beyond the
            /// coordinate class (`i32::MAX` bytes), [`OpenFault::Wire`]
            /// when the root layer violates the wire grammar,
            /// [`OpenFault::Refused`] when it carries a group code, and
            /// [`OpenFault::Resource`] when the allocator refuses the
            #[doc = concat!(" ", $noun, "'s working storage or the root scan.")]
            ///
            /// # Examples
            ///
            /// Group codes are well-formed wire outside this dialect — a
            /// refusal, typed apart from grammar faults, and the buffer
            /// rides back untouched:
            ///
            /// ```
            #[doc = concat!(" use ", $doc_mod, "::{", stringify!($Machine), ", OpenFault, Refusal};")]
            ///
            /// let group = vec![0x0B, 0x0C];
            #[doc = concat!(" let Err((back, fault)) = ", stringify!($Machine), "::open(group) else { unreachable!() };")]
            /// assert!(matches!(fault, OpenFault::Refused(Refusal::GroupCode { at: 0, .. })));
            /// assert_eq!(back, [0x0B, 0x0C]);
            /// ```
            pub fn open(source: Vec<u8>) -> Result<Self, (Vec<u8>, OpenFault)> {
                let Some(len) = admit(source.len()) else {
                    let len = source.len();
                    return Err((source, OpenFault::TooLarge { len }));
                };
                let store = $Store::new();
                let mut rows = Vec::new();
                let (first, last) = match scan_layer(&mut rows, &source, false, 0, len, None) {
                    Ok(anchors) => anchors,
                    Err(halt) => {
                        let fault = match halt {
                            LayerHalt::Wire(fault) => OpenFault::Wire(fault),
                            LayerHalt::Refused(refusal) => OpenFault::Refused(refusal),
                            // Root records occupy at least two bytes each,
                            // so a capped document cannot spend the row
                            // space: only the allocator refuses here.
                            LayerHalt::Resource | LayerHalt::Exhausted => OpenFault::Resource,
                        };
                        return Err((source, fault));
                    }
                };
                let mut source_runs = Vec::new();
                let run = match first {
                    Some(run_first) => {
                        if source_runs.try_reserve(1).is_err() {
                            return Err((source, OpenFault::Resource));
                        }
                        source_runs.push(SourceRun { first: run_first, end: arena_end(&rows) });
                        Some(SourceRunId::MIN)
                    }
                    None => None,
                };
                Ok(Self {
                    source,
                    rows,
                    store,
                    faults: Vec::new(),
                    log: Vec::new(),
                    root: Layer { first, last, dirty_kids: 0, history_kids: 0, source: run },
                    layers: Vec::new(),
                    source_runs,
                })
            }

            /// Copies `bytes` into a fresh buffer and opens it — the
            /// borrowed door for callers who keep their slice.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::open`], without the buffer (the caller keeps")]
            /// theirs): [`OpenFault::TooLarge`] beyond the coordinate
            /// class, [`OpenFault::Wire`], [`OpenFault::Refused`], and
            /// [`OpenFault::Resource`] — the copy's own allocation refusal
            /// folds into the latter.
            ///
            /// # Examples
            ///
            /// A group code is well-formed wire outside this dialect's
            /// language — the capability refusal:
            ///
            /// ```
            #[doc = concat!(" use ", $doc_mod, "::{", stringify!($Machine), ", OpenFault, Refusal};")]
            ///
            /// // An empty group of field 1.
            /// assert!(matches!(
            #[doc = concat!("     ", stringify!($Machine), "::open_copy(&[0x0B, 0x0C]).err(),")]
            ///     Some(OpenFault::Refused(Refusal::GroupCode { at: 0, .. }))
            /// ));
            /// ```
            #[inline]
            pub fn open_copy(bytes: &[u8]) -> Result<Self, OpenFault> {
                if admit(bytes.len()).is_none() {
                    return Err(OpenFault::TooLarge { len: bytes.len() });
                }
                let mut source = Vec::new();
                source.try_reserve_exact(bytes.len()).map_err(open_resource)?;
                source.extend_from_slice(bytes);
                Self::open(source).map_err(|(_, fault)| fault)
            }

            /// The moved-in source bytes.
            #[inline]
            #[must_use]
            pub fn source(&self) -> &[u8] {
                &self.source
            }

            /// Releases the source buffer — the open door's inverse, zero
            /// copies. Pending edits and the revision log are discarded
            /// with the machine, and the bytes come back exactly as they
            /// moved in.
            ///
            /// # Examples
            ///
            /// ```
            #[doc = concat!(" use ", $doc_mod, "::", stringify!($Machine), ";")]
            ///
            #[doc = concat!(" let mut ", $noun, " = ", stringify!($Machine), "::open(vec![0x08, 0x2A]).unwrap();")]
            #[doc = concat!(" let first = ", $noun, ".top().next().unwrap();")]
            #[doc = concat!(" ", $noun, ".set_varint(first, 7).unwrap(); // staged, never saved")]
            #[doc = concat!(" assert_eq!(", $noun, ".into_source(), [0x08, 0x2A]);")]
            /// ```
            #[inline]
            #[must_use]
            pub fn into_source(self) -> Vec<u8> {
                self.source
            }

    };
    (@doors borrow tolerant <$lt:lifetime>, store: $Store:ident, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            // ── opening ──

            /// Borrows `source` and scans its top layer: zero bytes are
            /// copied (the caller keeps the buffer), and LEN payloads
            #[doc = concat!(" wait for [`", stringify!($Machine), "::descend`].")]
            ///
            /// # Errors
            ///
            /// [`OpenFault::TooLarge`] beyond the coordinate class
            /// (`i32::MAX` bytes), [`OpenFault::Wire`] when the root
            /// layer violates the wire grammar, [`OpenFault::Refused`]
            /// when it carries a group code, and [`OpenFault::Resource`]
            #[doc = concat!(" when the allocator refuses the ", $noun, "'s working storage or")]
            /// the root scan.
            ///
            /// # Examples
            ///
            /// Group codes are well-formed wire outside this dialect — a
            /// refusal, typed apart from grammar faults, and the caller's
            /// buffer was never touched:
            ///
            /// ```
            #[doc = concat!(" use ", $doc_mod, "::{", stringify!($Machine), ", OpenFault, Refusal};")]
            ///
            /// // An empty group of field 1.
            /// let group = [0x0B, 0x0C];
            /// assert!(matches!(
            #[doc = concat!("     ", stringify!($Machine), "::open(&group).err(),")]
            ///     Some(OpenFault::Refused(Refusal::GroupCode { at: 0, .. }))
            /// ));
            /// ```
            pub fn open(source: &$lt [u8]) -> Result<Self, OpenFault> {
                let len = admit(source.len()).ok_or(OpenFault::TooLarge { len: source.len() })?;
                let store = $Store::new();
                let mut rows = Vec::new();
                let (first, last) = scan_layer(&mut rows, source, false, 0, len, None)
                    .map_err(|halt| {
                        match halt {
                            LayerHalt::Wire(fault) => OpenFault::Wire(fault),
                            LayerHalt::Refused(refusal) => OpenFault::Refused(refusal),
                            // Root records occupy at least two bytes each,
                            // so a capped document cannot spend the row
                            // space: only the allocator refuses here.
                            LayerHalt::Resource | LayerHalt::Exhausted => OpenFault::Resource,
                        }
                    })?;
                let mut source_runs = Vec::new();
                let run = match first {
                    Some(run_first) => {
                        source_runs.try_reserve(1).map_err(open_resource)?;
                        source_runs.push(SourceRun { first: run_first, end: arena_end(&rows) });
                        Some(SourceRunId::MIN)
                    }
                    None => None,
                };
                Ok(Self {
                    source,
                    rows,
                    store,
                    faults: Vec::new(),
                    log: Vec::new(),
                    root: Layer { first, last, dirty_kids: 0, history_kids: 0, source: run },
                    layers: Vec::new(),
                    source_runs,
                })
            }

            /// The borrowed source bytes, at the borrow's full lifetime.
            #[inline]
            #[must_use]
            pub const fn source(&self) -> &$lt [u8] {
                self.source
            }

    };
    (@doors borrow canonical <$lt:lifetime>, store: $Store:ident, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            // ── opening ──

            /// Borrows `source` and scans its top layer: zero bytes are
            /// copied (the caller keeps the buffer), and LEN payloads
            #[doc = concat!(" wait for [`", stringify!($Machine), "::descend`].")]
            ///
            /// # Errors
            ///
            /// [`OpenFault::TooLarge`] beyond the coordinate class
            /// (`i32::MAX` bytes), [`OpenFault::Wire`] when the root
            /// layer violates the wire grammar, [`OpenFault::Refused`]
            #[doc = concat!(" when it is lawful wire outside this ", $noun, "'s policy (padding")]
            /// or a group code), and [`OpenFault::Resource`] when the
            #[doc = concat!(" allocator refuses the ", $noun, "'s working storage or the root")]
            /// scan.
            ///
            /// # Examples
            ///
            /// Padding is lawful wire outside the canonical-minimal
            /// policy — a refusal, typed apart from grammar faults, and
            /// the caller's buffer was never touched:
            ///
            /// ```
            #[doc = concat!(" use ", $doc_mod, "::{", stringify!($Machine), ", OpenFault, Refusal};")]
            ///
            /// // varint f1=1, its tag padded to two bytes.
            /// let padded = [0x88, 0x00, 0x01];
            /// assert!(matches!(
            #[doc = concat!("     ", stringify!($Machine), "::open(&padded).err(),")]
            ///     Some(OpenFault::Refused(Refusal::NonMinimalTag { at: 0, .. }))
            /// ));
            /// ```
            pub fn open(source: &$lt [u8]) -> Result<Self, OpenFault> {
                let len = admit(source.len()).ok_or(OpenFault::TooLarge { len: source.len() })?;
                let store = $Store::new();
                let mut rows = Vec::new();
                let (first, last) = scan_layer(&mut rows, source, false, 0, len, None)
                    .map_err(|halt| {
                        match halt {
                            LayerHalt::Wire(fault) => OpenFault::Wire(fault),
                            LayerHalt::Refused(refusal) => OpenFault::Refused(refusal),
                            // Root records occupy at least two bytes each,
                            // so a capped document cannot spend the row
                            // space: only the allocator refuses here.
                            LayerHalt::Resource | LayerHalt::Exhausted => OpenFault::Resource,
                        }
                    })?;
                let mut source_runs = Vec::new();
                let run = match first {
                    Some(run_first) => {
                        source_runs.try_reserve(1).map_err(open_resource)?;
                        source_runs.push(SourceRun { first: run_first, end: arena_end(&rows) });
                        Some(SourceRunId::MIN)
                    }
                    None => None,
                };
                Ok(Self {
                    source,
                    rows,
                    store,
                    faults: Vec::new(),
                    log: Vec::new(),
                    root: Layer { first, last, dirty_kids: 0, history_kids: 0, source: run },
                    layers: Vec::new(),
                    source_runs,
                })
            }

            /// The borrowed source bytes, at the borrow's full lifetime.
            #[inline]
            #[must_use]
            pub const fn source(&self) -> &$lt [u8] {
                self.source
            }

    };
    (@doors carrier canonical $(<$lt:lifetime>)?, store: $Store:ident, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            // ── opening ──

            /// Opens a sealed document without copying.
            ///
            /// # Errors
            ///
            /// [`OpenFault::Wire`] when the root layer violates the wire
            /// grammar, [`OpenFault::Refused`] when it is lawful wire
            #[doc = concat!(" outside this ", $noun, "'s policy (padding or a group code),")]
            /// and [`OpenFault::Resource`] when the allocator refuses the
            #[doc = concat!(" ", $noun, "'s working storage or the root scan.")]
            pub fn open(doc: DocBytes) -> Result<Self, OpenFault> {
                let store = $Store::new();
                let mut rows = Vec::new();
                let (first, last) = scan_layer(&mut rows, doc.as_slice(), false, 0, doc.len(), None)
                    .map_err(|halt| {
                        match halt {
                            LayerHalt::Wire(fault) => OpenFault::Wire(fault),
                            LayerHalt::Refused(refusal) => OpenFault::Refused(refusal),
                            // Root records occupy at least two bytes each,
                            // so a capped document cannot spend the row
                            // space: only the allocator refuses here.
                            LayerHalt::Resource | LayerHalt::Exhausted => OpenFault::Resource,
                        }
                    })?;
                let mut source_runs = Vec::new();
                let source = match first {
                    Some(run_first) => {
                        source_runs.try_reserve(1).map_err(open_resource)?;
                        source_runs.push(SourceRun { first: run_first, end: arena_end(&rows) });
                        Some(SourceRunId::MIN)
                    }
                    None => None,
                };
                Ok(Self {
                    source: doc,
                    rows,
                    store,
                    faults: Vec::new(),
                    log: Vec::new(),
                    root: Layer { first, last, dirty_kids: 0, history_kids: 0, source },
                    layers: Vec::new(),
                    source_runs,
                })
            }

            /// Copies `bytes` into a fresh carrier and opens it.
            ///
            /// # Errors
            ///
            /// [`OpenFault::TooLarge`] when `bytes` exceeds
            /// [`DocBytes::CAP`], [`OpenFault::Wire`] when the root layer
            /// violates the wire grammar, [`OpenFault::Refused`] when it is
            #[doc = concat!(" lawful wire outside this ", $noun, "'s policy, and")]
            /// [`OpenFault::Resource`] when the allocator refuses the copy
            #[doc = concat!(" ([`LoadFault::Resource`], folded), the ", $noun, "'s working")]
            /// storage, or the root scan. The open judgment itself is
            #[doc = concat!(" [`", stringify!($Machine), "::open`]'s.")]
            ///
            /// # Examples
            ///
            /// A group code is well-formed wire outside this dialect's
            /// language — the capability refusal:
            ///
            /// ```
            #[doc = concat!(" use ", $doc_mod, "::{OpenFault, Refusal, ", stringify!($Machine), "};")]
            ///
            /// // An empty group of field 1.
            /// assert!(matches!(
            #[doc = concat!("     ", stringify!($Machine), "::open_copy(&[0x0B, 0x0C]).err(),")]
            ///     Some(OpenFault::Refused(Refusal::GroupCode { at: 0, .. }))
            /// ));
            /// ```
            #[inline]
            pub fn open_copy(bytes: &[u8]) -> Result<Self, OpenFault> {
                let doc = DocBytes::load(bytes).map_err(|fault| match fault {
                    LoadFault::TooLarge { len } => OpenFault::TooLarge { len },
                    LoadFault::Resource => OpenFault::Resource,
                })?;
                Self::open(doc)
            }

    };
    (@backing $cap:ident copy vec, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// The backing zone a row's scanned bytes live in.
            fn backing(&self, row: &Row) -> &[u8] {
                if row.authored_zone() { self.store.zone() } else { &self.source }
            }

    };
    (@backing $cap:ident copy stream, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// The backing zone a row's scanned bytes live in.
            fn backing(&self, row: &Row) -> &[u8] {
                if row.authored_zone() { self.store.zone() } else { &self.source }
            }

    };
    (@backing $cap:ident copy borrow, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// The backing zone a row's scanned bytes live in.
            fn backing(&self, row: &Row) -> &[u8] {
                if row.authored_zone() { self.store.zone() } else { self.source }
            }

    };
    (@backing $cap:ident copy carrier, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// The backing zone a row's scanned bytes live in.
            fn backing(&self, row: &Row) -> &[u8] {
                if row.authored_zone() { self.store.zone() } else { self.source.as_slice() }
            }

    };
    (@backing plain borrow $src:ident, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// The backing zone a row's scanned bytes live in: the
            /// document for source rows; for rows scanned out of an
            /// authored payload, the borrowed slot their tree was
            /// installed with — each slot is its own sealed zone, so
            /// authored-row offsets are relative to it.
            fn backing(&self, row: &Row) -> &[u8] {
                if row.authored_zone() {
                    self.store.span_bytes(Self::zone_slot(&self.rows, row))
                } else {
                    $crate::revise::groupless::revising_machine!(@doc_zone $src, self)
                }
            }

            /// The payload slot owning an authored row's zone: the first
            /// non-authored ancestor is the container whose install
            /// scanned the tree, and its effective value names the slot.
            /// The witness holds because rows under an authored backing
            /// accept no edits — the tree stays `Intact` — and clearing
            /// or re-setting the container orphans the whole tree before
            /// its slot coordinate can move, so a live authored row
            /// always climbs to the install that minted its bytes.
            fn zone_slot(rows: &[Row], row: &Row) -> ValueAt {
                debug_assert!(row.authored_zone());
                let mut cur = row;
                loop {
                    let parent = match cur.parent {
                        // SAFETY: authored rows are scanned under a
                        // descended container, so the parent chain
                        // reaches one before the root.
                        None => unsafe {
                            debug_assert!(false, "authored rows sit under a container");
                            core::hint::unreachable_unchecked()
                        },
                        // SAFETY: parent coordinates were minted by this
                        // machine's scans and the arena never shrinks.
                        Some(id) => unsafe { rows.get_unchecked(id.index()) },
                    };
                    if !parent.authored_zone() {
                        match parent.edit.effective() {
                            Some(value) => return value,
                            // SAFETY: the tree root's install set an
                            // effective value, and every transition off
                            // it re-seals the slot and orphans this row
                            // first (a dead row never reaches a zone
                            // read).
                            None => unsafe {
                                debug_assert!(false, "an authored tree's root names its slot");
                                core::hint::unreachable_unchecked()
                            },
                        }
                    }
                    cur = parent;
                }
            }

    };
    (@backing $cap:ident borrow $src:ident, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// The backing zone a row's scanned bytes live in: the
            /// document for source rows; for rows scanned out of an
            /// authored payload, the borrowed slot their tree was
            /// installed with — each slot is its own sealed zone, so
            /// authored-row offsets are relative to it.
            fn backing(&self, row: &Row) -> &[u8] {
                if row.authored_zone() {
                    self.store.span_bytes(Self::zone_slot(&self.rows, row))
                } else {
                    $crate::revise::groupless::revising_machine!(@doc_zone $src, self)
                }
            }

            /// The payload slot owning an authored row's zone: the
            /// nearest slot-bearing ancestor is the payload or import
            /// whose install scanned this tree, and its state names the
            /// slot. The witness holds because every transition that
            /// could move a slot coordinate orphans the subtree under it
            /// first, so a live authored row always climbs to the
            /// install that minted its bytes.
            fn zone_slot(rows: &[Row], row: &Row) -> ValueAt {
                debug_assert!(row.authored_zone());
                let mut cur = row;
                loop {
                    let parent = match cur.parent {
                        // SAFETY: authored rows are scanned under a
                        // descended container, so the parent chain
                        // reaches one before the root.
                        None => unsafe {
                            debug_assert!(false, "authored rows sit under a container");
                            core::hint::unreachable_unchecked()
                        },
                        // SAFETY: parent coordinates were minted by this
                        // machine's scans and the arena never shrinks.
                        Some(id) => unsafe { rows.get_unchecked(id.index()) },
                    };
                    match parent.edit {
                        Edit::Replaced(value)
                        | Edit::Deleted(Some(value))
                        | Edit::Inserted(value)
                        | Edit::InsertedDeleted(value)
                        | Edit::Imported(value)
                        | Edit::ImportedDeleted(value) => return value,
                        _ => {
                            debug_assert!(
                                parent.authored_zone(),
                                "an authored tree's root names its slot"
                            );
                            cur = parent;
                        }
                    }
                }
            }

    };
    (@backing plain mixed $src:ident, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// The backing zone a row's scanned bytes live in: the
            /// document for source rows; for rows scanned out of an
            /// authored payload, the payload slot their tree was
            /// installed with — the borrowed slice or the copied
            /// extent, each slot its own sealed zone, so authored-row
            /// offsets are relative to it.
            fn backing(&self, row: &Row) -> &[u8] {
                if row.authored_zone() {
                    self.store.span_bytes(Self::zone_slot(&self.rows, row))
                } else {
                    $crate::revise::groupless::revising_machine!(@doc_zone $src, self)
                }
            }

            /// The payload slot owning an authored row's zone: the first
            /// non-authored ancestor is the container whose install
            /// scanned the tree, and its effective value names the slot.
            /// The witness holds because rows under an authored backing
            /// accept no edits — the tree stays `Intact` — and clearing
            /// or re-setting the container orphans the whole tree before
            /// its slot coordinate can move, so a live authored row
            /// always climbs to the install that minted its bytes,
            /// whichever backing the slot names.
            fn zone_slot(rows: &[Row], row: &Row) -> ValueAt {
                debug_assert!(row.authored_zone());
                let mut cur = row;
                loop {
                    let parent = match cur.parent {
                        // SAFETY: authored rows are scanned under a
                        // descended container, so the parent chain
                        // reaches one before the root.
                        None => unsafe {
                            debug_assert!(false, "authored rows sit under a container");
                            core::hint::unreachable_unchecked()
                        },
                        // SAFETY: parent coordinates were minted by this
                        // machine's scans and the arena never shrinks.
                        Some(id) => unsafe { rows.get_unchecked(id.index()) },
                    };
                    if !parent.authored_zone() {
                        match parent.edit.effective() {
                            Some(value) => return value,
                            // SAFETY: the tree root's install set an
                            // effective value, and every transition off
                            // it re-seals the slot and orphans this row
                            // first (a dead row never reaches a zone
                            // read).
                            None => unsafe {
                                debug_assert!(false, "an authored tree's root names its slot");
                                core::hint::unreachable_unchecked()
                            },
                        }
                    }
                    cur = parent;
                }
            }

    };
    (@backing $cap:ident mixed $src:ident, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// The backing zone a row's scanned bytes live in: the
            /// document for source rows; for rows scanned out of an
            /// authored payload, the payload slot their tree was
            /// installed with — the borrowed slice or the copied
            /// extent, each slot its own sealed zone, so authored-row
            /// offsets are relative to it.
            fn backing(&self, row: &Row) -> &[u8] {
                if row.authored_zone() {
                    self.store.span_bytes(Self::zone_slot(&self.rows, row))
                } else {
                    $crate::revise::groupless::revising_machine!(@doc_zone $src, self)
                }
            }

            /// The payload slot owning an authored row's zone: the first
            /// non-authored ancestor is the container whose install
            /// scanned the tree, and its effective value names the slot.
            /// The witness holds because rows under an authored backing
            /// accept no edits — the tree stays `Intact` — and clearing
            /// or re-setting the container orphans the whole tree before
            /// its slot coordinate can move, so a live authored row
            /// always climbs to the install that minted its bytes,
            /// whichever backing the slot names.
            fn zone_slot(rows: &[Row], row: &Row) -> ValueAt {
                debug_assert!(row.authored_zone());
                let mut cur = row;
                loop {
                    let parent = match cur.parent {
                        // SAFETY: authored rows are scanned under a
                        // descended container, so the parent chain
                        // reaches one before the root.
                        None => unsafe {
                            debug_assert!(false, "authored rows sit under a container");
                            core::hint::unreachable_unchecked()
                        },
                        // SAFETY: parent coordinates were minted by this
                        // machine's scans and the arena never shrinks.
                        Some(id) => unsafe { rows.get_unchecked(id.index()) },
                    };
                    if !parent.authored_zone() {
                        match parent.edit {
                            Edit::Replaced(value)
                            | Edit::Deleted(Some(value))
                            | Edit::Inserted(value)
                            | Edit::InsertedDeleted(value)
                            | Edit::Imported(value)
                            | Edit::ImportedDeleted(value) => return value,
                            // SAFETY: the tree root's install named its
                            // slot, and every transition off it re-seals
                            // the slot and orphans this row first (a dead
                            // row never reaches a zone read).
                            _ => unsafe {
                                debug_assert!(false, "an authored tree's root names its slot");
                                core::hint::unreachable_unchecked()
                            },
                        }
                    }
                    cur = parent;
                }
            }

    };
    (@doc_zone stream, $this:tt) => {
        &$this.source
    };
    (@doc_zone vec, $this:tt) => {
        &$this.source
    };
    (@doc_zone borrow, $this:tt) => {
        $this.source
    };
    (@doc_zone carrier, $this:tt) => {
        $this.source.as_slice()
    };
    (@descend plain copy, src: $src:ident, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// Parses a LEN payload into its interior layer, once: later
            /// calls project the stored outcome, and a wire fault or a
            /// refusal inside the payload (a group code included) is a
            #[doc = concat!(" resident verdict, not ", $a_noun, " stop.")]
            ///
            /// # Errors
            ///
            /// [`EditFault::DeadHandle`] for an orphaned row,
            /// [`EditFault::KindMismatch`] off the LEN kind,
            /// [`EditFault::Resource`]/[`EditFault::IndexSpaceExhausted`] when the
            /// interior scan cannot be stored — the slot stays unopened
            /// and the call may be retried.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the")]
            /// arena index contract).
            #[track_caller]
            pub fn descend(&mut self, handle: Handle) -> Result<Descent<'_>, EditFault> {
                let row = *self.live(handle)?;
                if !matches!(row.kind, RecordKind::Len) {
                    return Err(EditFault::KindMismatch { have: row.kind });
                }
                let id = handle.0;
                match row.slot() {
                    Slot::Opened(layer) => {
                        Ok(Descent::Opened { first: self.layer(layer).first.map(Handle) })
                    }
                    Slot::Fault(index) => Ok(project(&self.faults, index)),
                    Slot::Unopened => {
                        let (authored, start, len) = match row.edit.effective() {
                            Some(value) => {
                                let (at, len) = self.store.span(value);
                                (true, at, len)
                            }
                            None => {
                                // SAFETY: this arm matched an edit outside
                                // the Inserted family.
                                let (at, len) = self.len_geometry(&row, unsafe { scanned_at(&row) });
                                (row.authored_zone(), at, len)
                            }
                        };
                        let end = start + len;
                        let rows_mark = self.rows.len();
                        let runs_mark = self.source_runs.len();
                $crate::revise::groupless::revising_machine!(@seal_zone $src, self, zone, authored);
                        let halt = match scan_layer(&mut self.rows, zone, authored, start, end, Some(id)) {
                            Ok((first, last)) => match self.seal_scan(id, first, last, authored) {
                                Ok(()) => return Ok(Descent::Opened { first: first.map(Handle) }),
                                Err(fault) => {
                                    // Discard the provisional tables: the
                                    // slot publishes whole or not at all,
                                    // and the refusal is retryable.
                                    self.rows.truncate(rows_mark);
                                    self.source_runs.truncate(runs_mark);
                                    return Err(fault);
                                }
                            },
                            Err(halt) => halt,
                        };
                        // Discard the provisional rows: the slot publishes
                        // whole or not at all.
                        self.rows.truncate(rows_mark);
                        let fault = match halt {
                            LayerHalt::Wire(fault) => SlotFault::Wire(fault),
                            LayerHalt::Refused(refusal) => SlotFault::Refused(refusal),
                            LayerHalt::Resource => return Err(EditFault::Resource),
                            LayerHalt::Exhausted => return Err(EditFault::IndexSpaceExhausted),
                        };
                        let index = self.push_fault(fault)?;
                        self.row_mut(id).set_slot(Slot::Fault(index));
                        Ok(project(&self.faults, index))
                    }
                }
            }

    };
    (@descend $cap:ident copy, src: $src:ident, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// Parses a LEN payload into its interior layer, once: later
            /// calls project the stored outcome, and a wire fault or a
            /// refusal inside the payload (a group code included) is a
            #[doc = concat!(" resident verdict, not ", $a_noun, " stop.")]
            ///
            /// An imported record's interior descends too: its rows are
            /// first-class — readable and editable like scanned rows —
            /// over the import's own bytes, and verdict and fault
            /// offsets inside them index the import's own byte zone,
            /// not this machine's source.
            ///
            /// # Errors
            ///
            /// [`EditFault::DeadHandle`] for an orphaned row,
            /// [`EditFault::KindMismatch`] off the LEN kind,
            /// [`EditFault::Resource`]/[`EditFault::IndexSpaceExhausted`] when the
            /// interior scan cannot be stored — the slot stays unopened
            /// and the call may be retried.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the")]
            /// arena index contract).
            #[track_caller]
            pub fn descend(&mut self, handle: Handle) -> Result<Descent<'_>, EditFault> {
                let row = *self.live(handle)?;
                if !matches!(row.kind, RecordKind::Len) {
                    return Err(EditFault::KindMismatch { have: row.kind });
                }
                let id = handle.0;
                match row.slot() {
                    Slot::Opened(layer) => {
                        Ok(Descent::Opened { first: self.layer(layer).first.map(Handle) })
                    }
                    Slot::Fault(index) => Ok(project(&self.faults, index)),
                    Slot::Unopened => {
                        // Which zone backs the interior, whether its rows
                        // are browse-only authored bytes or first-class
                        // alias rows, and whether a reverse-lookup run may
                        // mint (original document interiors alone).
                        let (authored, alias, start, len) = match row.edit {
                            Edit::Replaced(value)
                            | Edit::Deleted(Some(value))
                            | Edit::Inserted(value)
                            | Edit::InsertedDeleted(value) => {
                                let (at, len) = self.store.span(value);
                                (true, false, at, len)
                            }
                            // A transfer's retained interior parses from
                            // the designated document subspan; its rows
                            // are output-authored and editable.
                            Edit::SourcePayload(src)
                            | Edit::SourcePayloadDeleted(src)
                            | Edit::SourceInserted(src)
                            | Edit::SourceInsertedDeleted(src) => {
                                let (at, len) = self.designated_payload(src);
                                (false, true, at, len)
                            }
                            // An imported record's interior parses inside
                            // its own slot extent of the store zone as
                            // first-class alias rows.
                            Edit::Imported(value) | Edit::ImportedDeleted(value) => {
                                let (slot_at, _) = self.store.span(value);
                                let bytes = self.import_slot(value);
                                let at = import_value_at(bytes);
                                match slice::len_word(bytes, at, bytes.len()) {
                                    Ok((len, width)) => {
                                        let body =
                                            crate::admission::admitted_u32(at + usize::from(width));
                                        (
                                            true,
                                            $crate::revise::groupless::revising_machine!(@import_first_class $cap),
                                            slot_at + body,
                                            len.as_inner(),
                                        )
                                    }
                                    Err(_) => unreachable!(
                                        "imported records are structurally complete"
                                    ),
                                }
                            }
                            Edit::SourceRecord | Edit::SourceRecordDeleted => {
                                // SAFETY: clone-minted rows carry their
                                // source geometry.
                                let (at, len) = self.len_geometry(&row, unsafe { scanned_at(&row) });
                                (false, true, at, len)
                            }
                            Edit::Intact | Edit::Deleted(None) | Edit::Moved { .. } => {
                                // SAFETY: this arm sits outside the
                                // Inserted and Imported families.
                                let (at, len) = self.len_geometry(&row, unsafe { scanned_at(&row) });
                                (row.authored_zone(), false, at, len)
                            }
                        };
                        let alias = alias || row.alias();
                        let end = start + len;
                        let rows_mark = self.rows.len();
                        let runs_mark = self.source_runs.len();
                $crate::revise::groupless::revising_machine!(@seal_zone $src, self, zone, authored);
                        let halt = match scan_layer(&mut self.rows, zone, authored, start, end, Some(id)) {
                            Ok((first, last)) => {
                                if alias {
                                    for interior in &mut self.rows[rows_mark..] {
                                        interior.flags |= FLAG_ALIAS;
                                    }
                                }
                                match self.seal_scan(id, first, last, !authored && !alias) {
                                    Ok(()) => {
                                        return Ok(Descent::Opened { first: first.map(Handle) });
                                    }
                                    Err(fault) => {
                                        // Discard the provisional tables:
                                        // the slot publishes whole or not
                                        // at all, and the refusal is
                                        // retryable.
                                        self.rows.truncate(rows_mark);
                                        self.source_runs.truncate(runs_mark);
                                        return Err(fault);
                                    }
                                }
                            }
                            Err(halt) => halt,
                        };
                        // Discard the provisional rows: the slot publishes
                        // whole or not at all.
                        self.rows.truncate(rows_mark);
                        let fault = match halt {
                            LayerHalt::Wire(fault) => SlotFault::Wire(fault),
                            LayerHalt::Refused(refusal) => SlotFault::Refused(refusal),
                            LayerHalt::Resource => return Err(EditFault::Resource),
                            LayerHalt::Exhausted => return Err(EditFault::IndexSpaceExhausted),
                        };
                        let index = self.push_fault(fault)?;
                        self.row_mut(id).set_slot(Slot::Fault(index));
                        Ok(project(&self.faults, index))
                    }
                }
            }

    };
    (@set_payload copy $(<$lt:lifetime>)?, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// Replaces a LEN record's payload wholesale, orphaning any
            /// interior rows parsed out of the old payload. The payload's
            /// interior is the caller's declaration: it lands as opaque
            /// bytes, judged only if an explicit descend later commits it
            /// as a message.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::set_varint`], plus")]
            /// [`EditFault::EditedInterior`] while the interior carries
            /// edits or history and [`EditFault::PayloadTooLarge`] beyond
            /// the length class.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the")]
            /// arena index contract).
            #[inline]
            #[track_caller]
            pub fn set_payload(&mut self, handle: Handle, payload: &[u8]) -> Result<(), EditFault> {
                let witness = self.value_gate(handle, RecordKind::Len)?;
                self.interior_gate(handle.0)?;
                if payload.len() > usize_of(PayloadLen::MAX.as_inner()) {
                    return Err(EditFault::PayloadTooLarge { len: payload.len() });
                }
                self.log.try_reserve(1).map_err(edit_resource)?;
                let at = self.store.push_bytes(payload).map_err(edit_store_fault)?;
                self.apply_edit(handle.0, witness.set(at));
                Ok(())
            }

    };
    (@set_payload borrow <$lt:lifetime>, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// Replaces a LEN record's payload with a borrowed slice,
            /// orphaning any interior rows parsed out of the old payload.
            /// The slice is retained — not copied — as a fresh immutable
            #[doc = concat!(" slot the ", $noun, " reads until it drops, so its owner must")]
            #[doc = concat!(" outlive the ", $noun, "; earlier installs keep their own slots,")]
            /// which is what lets a revert restore the exact prior
            /// payload. The payload's interior is the caller's
            /// declaration: it lands as opaque bytes, judged only if an
            /// explicit descend later commits it as a message.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::set_varint`], plus")]
            /// [`EditFault::EditedInterior`] while the interior carries
            /// edits or history and [`EditFault::PayloadTooLarge`] beyond
            /// the length class.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the")]
            /// arena index contract).
            #[inline]
            #[track_caller]
            pub fn set_payload(&mut self, handle: Handle, payload: &$lt [u8]) -> Result<(), EditFault> {
                let witness = self.value_gate(handle, RecordKind::Len)?;
                self.interior_gate(handle.0)?;
                if payload.len() > usize_of(PayloadLen::MAX.as_inner()) {
                    return Err(EditFault::PayloadTooLarge { len: payload.len() });
                }
                self.log.try_reserve(1).map_err(edit_resource)?;
                let at = self.store.push_slot(payload).map_err(edit_store_fault)?;
                self.apply_edit(handle.0, witness.set(at));
                Ok(())
            }

    };
    (@set_payload mixed <$lt:lifetime>, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// Replaces a LEN record's payload with a borrowed slice,
            /// orphaning any interior rows parsed out of the old payload.
            /// The slice is retained — not copied — as a fresh immutable
            #[doc = concat!(" slot the ", $noun, " reads until it drops, so its owner must")]
            #[doc = concat!(" outlive the ", $noun, " (the escape hatch for temporaries is")]
            #[doc = concat!(" [`", stringify!($Machine), "::set_payload_copy`]); earlier installs keep their")]
            /// own slots, whichever backing they chose, which is what
            /// lets a revert restore the exact prior payload. The
            /// payload's interior is the caller's declaration: it lands
            /// as opaque bytes, judged only if an explicit descend later
            /// commits it as a message.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::set_varint`], plus")]
            /// [`EditFault::EditedInterior`] while the interior carries
            /// edits or history and [`EditFault::PayloadTooLarge`] beyond
            /// the length class.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the")]
            /// arena index contract).
            #[inline]
            #[track_caller]
            pub fn set_payload(&mut self, handle: Handle, payload: &$lt [u8]) -> Result<(), EditFault> {
                let witness = self.value_gate(handle, RecordKind::Len)?;
                self.interior_gate(handle.0)?;
                if payload.len() > usize_of(PayloadLen::MAX.as_inner()) {
                    return Err(EditFault::PayloadTooLarge { len: payload.len() });
                }
                self.log.try_reserve(1).map_err(edit_resource)?;
                let at = self.store.push_slot(payload).map_err(edit_store_fault)?;
                self.apply_edit(handle.0, witness.set(at));
                Ok(())
            }

            #[doc = concat!(" [`", stringify!($Machine), "::set_payload`]'s copying twin: the payload is")]
            #[doc = concat!(" copied into the ", $noun, "'s store at the command, so a")]
            /// transient owner may die right after the call — no
            /// payload lifetime binds the install. Everything else is
            /// the unsuffixed face's contract: one fresh immutable
            /// slot, the old interior orphaned, the interior opaque
            /// until an explicit descend.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::set_payload`].")]
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the")]
            /// arena index contract).
            #[inline]
            #[track_caller]
            pub fn set_payload_copy(&mut self, handle: Handle, payload: &[u8]) -> Result<(), EditFault> {
                let witness = self.value_gate(handle, RecordKind::Len)?;
                self.interior_gate(handle.0)?;
                if payload.len() > usize_of(PayloadLen::MAX.as_inner()) {
                    return Err(EditFault::PayloadTooLarge { len: payload.len() });
                }
                self.log.try_reserve(1).map_err(edit_resource)?;
                let at = self.store.push_bytes(payload).map_err(edit_store_fault)?;
                self.apply_edit(handle.0, witness.set(at));
                Ok(())
            }

    };
    (@insert_payload copy $(<$lt:lifetime>)?, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// Inserts a LEN record with an authored payload at the
            /// anchor. The payload's interior is the caller's declaration:
            /// it lands as opaque bytes, judged only if an explicit descend
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
            ///
            /// # Examples
            ///
            /// ```
            /// use protobuf_edit::FieldNumber;
            #[doc = concat!(" use ", $doc_mod, "::{InsertAt, ", stringify!($Machine), "};")]
            ///
            /// let msg = [0x08, 0x2A];
            #[doc = concat!(" let mut ", $noun, " = ", $door, ".unwrap();")]
            /// let field = FieldNumber::new(2).unwrap();
            /// let record =
            #[doc = concat!("     ", $noun, ".insert_payload(InsertAt::TailOf(None), field, &[0x01, 0x02]).unwrap();")]
            #[doc = concat!(" assert_eq!(", $noun, ".payload_bytes(record).unwrap(), [0x01, 0x02]);")]
            #[doc = concat!(" assert_eq!(", $noun, ".save().unwrap()[..], [0x08, 0x2A, 0x12, 0x02, 0x01, 0x02]);")]
            /// ```
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
                self.rows.try_reserve(1).map_err(edit_resource)?;
                self.log.try_reserve(1).map_err(edit_resource)?;
                let value = self.store.push_bytes(payload).map_err(edit_store_fault)?;
                self.apply_insert(&plan, id, field, RecordKind::Len, value);
                Ok(Handle(id))
            }

    };
    (@insert_payload borrow <$lt:lifetime>, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// Inserts a LEN record with a borrowed authored payload at
            /// the anchor. The slice is retained — not copied — as a
            #[doc = concat!(" fresh immutable slot the ", $noun, " reads until it drops, so")]
            #[doc = concat!(" its owner must outlive the ", $noun, ". The payload's interior")]
            /// is the caller's declaration: it lands as opaque bytes,
            /// judged only if an explicit descend later commits it as a
            /// message.
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
            ///
            /// # Examples
            ///
            /// ```
            /// use protobuf_edit::FieldNumber;
            #[doc = concat!(" use ", $doc_mod, "::{InsertAt, ", stringify!($Machine), "};")]
            ///
            /// let msg = [0x08, 0x2A];
            /// let payload = [0x01, 0x02];
            #[doc = concat!(" let mut ", $noun, " = ", $door, ".unwrap();")]
            /// let field = FieldNumber::new(2).unwrap();
            /// let record =
            #[doc = concat!("     ", $noun, ".insert_payload(InsertAt::TailOf(None), field, &payload).unwrap();")]
            #[doc = concat!(" assert_eq!(", $noun, ".payload_bytes(record).unwrap(), [0x01, 0x02]);")]
            #[doc = concat!(" assert_eq!(", $noun, ".save().unwrap()[..], [0x08, 0x2A, 0x12, 0x02, 0x01, 0x02]);")]
            /// ```
            #[inline]
            #[track_caller]
            pub fn insert_payload(
                &mut self,
                at: InsertAt,
                field: FieldNumber,
                payload: &$lt [u8],
            ) -> Result<Handle, EditFault> {
                let plan = self.resolve_anchor(at)?;
                let id = self.mint_insert()?;
                if payload.len() > usize_of(PayloadLen::MAX.as_inner()) {
                    return Err(EditFault::PayloadTooLarge { len: payload.len() });
                }
                self.rows.try_reserve(1).map_err(edit_resource)?;
                self.log.try_reserve(1).map_err(edit_resource)?;
                let value = self.store.push_slot(payload).map_err(edit_store_fault)?;
                self.apply_insert(&plan, id, field, RecordKind::Len, value);
                Ok(Handle(id))
            }

    };
    (@insert_payload mixed <$lt:lifetime>, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// Inserts a LEN record with a borrowed authored payload at
            /// the anchor. The slice is retained — not copied — as a
            #[doc = concat!(" fresh immutable slot the ", $noun, " reads until it drops, so")]
            #[doc = concat!(" its owner must outlive the ", $noun, " (the escape hatch for")]
            #[doc = concat!(" temporaries is [`", stringify!($Machine), "::insert_payload_copy`]). The")]
            /// payload's interior is the caller's declaration: it lands
            /// as opaque bytes, judged only if an explicit descend later
            /// commits it as a message.
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
            ///
            /// # Examples
            ///
            /// ```
            /// use protobuf_edit::FieldNumber;
            #[doc = concat!(" use ", $doc_mod, "::{InsertAt, ", stringify!($Machine), "};")]
            ///
            /// let msg = [0x08, 0x2A];
            /// let payload = [0x01, 0x02];
            #[doc = concat!(" let mut ", $noun, " = ", $door, ".unwrap();")]
            /// let field = FieldNumber::new(2).unwrap();
            /// let record =
            #[doc = concat!("     ", $noun, ".insert_payload(InsertAt::TailOf(None), field, &payload).unwrap();")]
            #[doc = concat!(" assert_eq!(", $noun, ".payload_bytes(record).unwrap(), [0x01, 0x02]);")]
            #[doc = concat!(" assert_eq!(", $noun, ".save().unwrap()[..], [0x08, 0x2A, 0x12, 0x02, 0x01, 0x02]);")]
            /// ```
            #[inline]
            #[track_caller]
            pub fn insert_payload(
                &mut self,
                at: InsertAt,
                field: FieldNumber,
                payload: &$lt [u8],
            ) -> Result<Handle, EditFault> {
                let plan = self.resolve_anchor(at)?;
                let id = self.mint_insert()?;
                if payload.len() > usize_of(PayloadLen::MAX.as_inner()) {
                    return Err(EditFault::PayloadTooLarge { len: payload.len() });
                }
                self.rows.try_reserve(1).map_err(edit_resource)?;
                self.log.try_reserve(1).map_err(edit_resource)?;
                let value = self.store.push_slot(payload).map_err(edit_store_fault)?;
                self.apply_insert(&plan, id, field, RecordKind::Len, value);
                Ok(Handle(id))
            }

            #[doc = concat!(" [`", stringify!($Machine), "::insert_payload`]'s copying twin: the payload")]
            #[doc = concat!(" is copied into the ", $noun, "'s store at the command, so a")]
            /// transient owner may die right after the call — no
            /// payload lifetime binds the install. Everything else is
            /// the unsuffixed face's contract: one fresh immutable
            /// slot, one authored row, the interior opaque until an
            /// explicit descend.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::insert_payload`].")]
            ///
            /// # Panics
            ///
            /// Panics if a handle inside the anchor was not minted by this
            #[doc = concat!(" ", $noun, " (the arena index contract).")]
            ///
            /// # Examples
            ///
            /// ```
            /// use protobuf_edit::FieldNumber;
            #[doc = concat!(" use ", $doc_mod, "::{InsertAt, ", stringify!($Machine), "};")]
            ///
            /// let msg = [0x08, 0x2A];
            #[doc = concat!(" let mut ", $noun, " = ", $door, ".unwrap();")]
            /// let field = FieldNumber::new(2).unwrap();
            /// let record = {
            ///     // The owner dies right after the call: the bytes were copied.
            ///     let transient = vec![0x01, 0x02];
            #[doc = concat!("     ", $noun, ".insert_payload_copy(InsertAt::TailOf(None), field, &transient).unwrap()")]
            /// };
            #[doc = concat!(" assert_eq!(", $noun, ".payload_bytes(record).unwrap(), [0x01, 0x02]);")]
            #[doc = concat!(" assert_eq!(", $noun, ".save().unwrap()[..], [0x08, 0x2A, 0x12, 0x02, 0x01, 0x02]);")]
            /// ```
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
                self.rows.try_reserve(1).map_err(edit_resource)?;
                self.log.try_reserve(1).map_err(edit_resource)?;
                let value = self.store.push_bytes(payload).map_err(edit_store_fault)?;
                self.apply_insert(&plan, id, field, RecordKind::Len, value);
                Ok(Handle(id))
            }

    };
    (@transfer_import copy tolerant $(<$lt:lifetime>)?, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// Copies one designated external record to the anchor: the
            /// designation's exact bytes — met tag spelling and framing
            /// widths included — contribute whole at save, nothing
            /// re-encoded; one exact record-length copy lands in the
            /// store at the command, so no designation lifetime binds
            #[doc = concat!(" the ", $noun, ". The imported record is output-authored: its")]
            /// status reads `Inserted`, it answers no source span, and
            /// it does not designate onward; its interior is the
            /// source's opaque declaration, browsable after an explicit
            /// descent. One command, one pending step.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::insert_payload`]'s anchor and resource")]
            #[doc = concat!(" gates. On any `Err` the ", $noun, " is unchanged.")]
            ///
            /// # Panics
            ///
            /// Panics if a handle inside the anchor was not minted by
            #[doc = concat!(" this ", $noun, " (the arena index contract).")]
            #[track_caller]
            pub fn copy_record_from(
                &mut self,
                source: crate::source::groupless::RecordRef<'_>,
                at: InsertAt,
            ) -> Result<Handle, EditFault> {
                let plan = self.resolve_anchor(at)?;
                let id = self.mint_insert()?;
                self.rows.try_reserve(1).map_err(edit_resource)?;
                self.log.try_reserve(1).map_err(edit_resource)?;
                let value = self.store.push_bytes(source.as_bytes()).map_err(edit_store_fault)?;
                let next = self.plan_next(&plan);
                self.apply_transfer(
                    &plan,
                    id,
                    Row::transfer_authored(
                        source.field(),
                        source.kind(),
                        plan.parent,
                        next,
                        Edit::ImportedDeleted(value),
                    ),
                    Edit::Imported(value),
                );
                Ok(Handle(id))
            }
    };
    (@transfer_import copy canonical $(<$lt:lifetime>)?, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// Copies one designated external record to the anchor: the
            /// designation's exact bytes contribute whole at save,
            /// nothing re-encoded; one exact record-length copy lands in
            /// the store at the command, so no designation lifetime
            #[doc = concat!(" binds the ", $noun, ". This host admits canonically, so the")]
            /// argument is the proof-carrying form — a tolerant
            /// designation upgrades through `try_canonical`, which
            /// refuses padded framing before any mutation. The imported
            /// record is output-authored: its status reads `Inserted`,
            /// it answers no source span, and it does not designate
            /// onward; its interior is the source's opaque declaration,
            /// browsable after an explicit descent. One command, one
            /// pending step.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::insert_payload`]'s anchor and resource")]
            #[doc = concat!(" gates. On any `Err` the ", $noun, " is unchanged.")]
            ///
            /// # Panics
            ///
            /// Panics if a handle inside the anchor was not minted by
            #[doc = concat!(" this ", $noun, " (the arena index contract).")]
            #[track_caller]
            pub fn copy_record_from(
                &mut self,
                source: crate::source::groupless::CanonicalRecordRef<'_>,
                at: InsertAt,
            ) -> Result<Handle, EditFault> {
                let plan = self.resolve_anchor(at)?;
                let id = self.mint_insert()?;
                self.rows.try_reserve(1).map_err(edit_resource)?;
                self.log.try_reserve(1).map_err(edit_resource)?;
                let value = self.store.push_bytes(source.as_bytes()).map_err(edit_store_fault)?;
                let next = self.plan_next(&plan);
                self.apply_transfer(
                    &plan,
                    id,
                    Row::transfer_authored(
                        source.field(),
                        source.kind(),
                        plan.parent,
                        next,
                        Edit::ImportedDeleted(value),
                    ),
                    Edit::Imported(value),
                );
                Ok(Handle(id))
            }
    };
    (@transfer_import borrow tolerant <$lt:lifetime>, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// Copies one designated external record to the anchor: the
            /// designation's exact bytes — met tag spelling and framing
            /// widths included — contribute whole at save, nothing
            /// re-encoded. The record bytes are retained, not copied: an
            #[doc = concat!(" immutable slot the ", $noun, " reads until it drops, so the")]
            /// designation's backing must outlive it (earlier installs
            /// keep their slots, which is what lets a revert restore the
            /// exact prior state). The imported record is
            /// output-authored: its status reads `Inserted`, it answers
            /// no source span, and it does not designate onward; its
            /// interior is the source's opaque declaration, browsable
            /// after an explicit descent. One command, one pending step.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::insert_payload`]'s anchor and resource")]
            #[doc = concat!(" gates. On any `Err` the ", $noun, " is unchanged.")]
            ///
            /// # Panics
            ///
            /// Panics if a handle inside the anchor was not minted by
            #[doc = concat!(" this ", $noun, " (the arena index contract).")]
            #[track_caller]
            pub fn copy_record_from(
                &mut self,
                source: crate::source::groupless::RecordRef<$lt>,
                at: InsertAt,
            ) -> Result<Handle, EditFault> {
                let plan = self.resolve_anchor(at)?;
                let id = self.mint_insert()?;
                self.rows.try_reserve(1).map_err(edit_resource)?;
                self.log.try_reserve(1).map_err(edit_resource)?;
                let value = self.store.push_slot(source.as_bytes()).map_err(edit_store_fault)?;
                let next = self.plan_next(&plan);
                self.apply_transfer(
                    &plan,
                    id,
                    Row::transfer_authored(
                        source.field(),
                        source.kind(),
                        plan.parent,
                        next,
                        Edit::ImportedDeleted(value),
                    ),
                    Edit::Imported(value),
                );
                Ok(Handle(id))
            }
    };
    (@transfer_import borrow canonical <$lt:lifetime>, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// Copies one designated external record to the anchor: the
            /// designation's exact bytes contribute whole at save,
            /// nothing re-encoded. This host admits canonically, so the
            /// argument is the proof-carrying form — a tolerant
            /// designation upgrades through `try_canonical`, which
            /// refuses padded framing before any mutation. The record
            /// bytes are retained, not copied: an immutable slot the
            #[doc = concat!(" ", $noun, " reads until it drops, so the designation's backing")]
            /// must outlive it. The imported record is output-authored:
            /// its status reads `Inserted`, it answers no source span,
            /// and it does not designate onward; its interior is the
            /// source's opaque declaration, browsable after an explicit
            /// descent. One command, one pending step.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::insert_payload`]'s anchor and resource")]
            #[doc = concat!(" gates. On any `Err` the ", $noun, " is unchanged.")]
            ///
            /// # Panics
            ///
            /// Panics if a handle inside the anchor was not minted by
            #[doc = concat!(" this ", $noun, " (the arena index contract).")]
            #[track_caller]
            pub fn copy_record_from(
                &mut self,
                source: crate::source::groupless::CanonicalRecordRef<$lt>,
                at: InsertAt,
            ) -> Result<Handle, EditFault> {
                let plan = self.resolve_anchor(at)?;
                let id = self.mint_insert()?;
                self.rows.try_reserve(1).map_err(edit_resource)?;
                self.log.try_reserve(1).map_err(edit_resource)?;
                let value = self.store.push_slot(source.as_bytes()).map_err(edit_store_fault)?;
                let next = self.plan_next(&plan);
                self.apply_transfer(
                    &plan,
                    id,
                    Row::transfer_authored(
                        source.field(),
                        source.kind(),
                        plan.parent,
                        next,
                        Edit::ImportedDeleted(value),
                    ),
                    Edit::Imported(value),
                );
                Ok(Handle(id))
            }
    };
    (@transfer_import mixed tolerant <$lt:lifetime>, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// Copies one designated external record to the anchor: the
            /// designation's exact bytes — met tag spelling and framing
            /// widths included — contribute whole at save, nothing
            /// re-encoded. The record bytes are retained, not copied: an
            #[doc = concat!(" immutable borrowed slot the ", $noun, " reads until it drops,")]
            /// so the designation's backing must outlive it under `'p`
            /// like every unsuffixed payload install (earlier installs
            /// keep their slots, which is what lets a revert restore
            /// the exact prior state). The imported record is
            /// output-authored: its status reads `Inserted`, it answers
            /// no source span, and it does not designate onward; its
            /// interior is the source's opaque declaration, browsable
            /// after an explicit descent. One command, one pending step.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::insert_payload`]'s anchor and resource")]
            #[doc = concat!(" gates. On any `Err` the ", $noun, " is unchanged.")]
            ///
            /// # Panics
            ///
            /// Panics if a handle inside the anchor was not minted by
            #[doc = concat!(" this ", $noun, " (the arena index contract).")]
            #[track_caller]
            pub fn copy_record_from(
                &mut self,
                source: crate::source::groupless::RecordRef<$lt>,
                at: InsertAt,
            ) -> Result<Handle, EditFault> {
                let plan = self.resolve_anchor(at)?;
                let id = self.mint_insert()?;
                self.rows.try_reserve(1).map_err(edit_resource)?;
                self.log.try_reserve(1).map_err(edit_resource)?;
                let value = self.store.push_slot(source.as_bytes()).map_err(edit_store_fault)?;
                let next = self.plan_next(&plan);
                self.apply_transfer(
                    &plan,
                    id,
                    Row::transfer_authored(
                        source.field(),
                        source.kind(),
                        plan.parent,
                        next,
                        Edit::ImportedDeleted(value),
                    ),
                    Edit::Imported(value),
                );
                Ok(Handle(id))
            }
    };
    (@transfer_import mixed canonical <$lt:lifetime>, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// Copies one designated external record to the anchor: the
            /// designation's exact bytes contribute whole at save,
            /// nothing re-encoded. This host admits canonically, so the
            /// argument is the proof-carrying form — a tolerant
            /// designation upgrades through `try_canonical`, which
            /// refuses padded framing before any mutation. The record
            /// bytes are retained, not copied: an immutable borrowed
            #[doc = concat!(" slot the ", $noun, " reads until it drops, so the designation's")]
            /// backing must outlive it under `'p` like every unsuffixed
            /// payload install. The imported record is output-authored:
            /// its status reads `Inserted`, it answers no source span,
            /// and it does not designate onward; its interior is the
            /// source's opaque declaration, browsable after an explicit
            /// descent. One command, one pending step.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::insert_payload`]'s anchor and resource")]
            #[doc = concat!(" gates. On any `Err` the ", $noun, " is unchanged.")]
            ///
            /// # Panics
            ///
            /// Panics if a handle inside the anchor was not minted by
            #[doc = concat!(" this ", $noun, " (the arena index contract).")]
            #[track_caller]
            pub fn copy_record_from(
                &mut self,
                source: crate::source::groupless::CanonicalRecordRef<$lt>,
                at: InsertAt,
            ) -> Result<Handle, EditFault> {
                let plan = self.resolve_anchor(at)?;
                let id = self.mint_insert()?;
                self.rows.try_reserve(1).map_err(edit_resource)?;
                self.log.try_reserve(1).map_err(edit_resource)?;
                let value = self.store.push_slot(source.as_bytes()).map_err(edit_store_fault)?;
                let next = self.plan_next(&plan);
                self.apply_transfer(
                    &plan,
                    id,
                    Row::transfer_authored(
                        source.field(),
                        source.kind(),
                        plan.parent,
                        next,
                        Edit::ImportedDeleted(value),
                    ),
                    Edit::Imported(value),
                );
                Ok(Handle(id))
            }
    };
    (@frame_doors copy $(<$lt:lifetime>)?, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            // ── the staged payload frame ──

            /// Opens a staged replacement of the LEN record's payload:
            #[doc = concat!(" chunks copy into the ", $noun, "'s store through the returned")]
            /// frame, and exactly one logged transition applies at
            /// [`finish`](PayloadFrame::finish) — before it, no row or log
            /// state changes, so a revert can never see a half-staged
            /// command. The gates judge here, so the frame itself cannot
            /// discover a refused target.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::set_payload`]'s gates. On `Err` the ", $noun)]
            /// is unchanged.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the")]
            /// arena index contract).
            ///
            /// # Examples
            ///
            /// ```
            #[doc = concat!(" use ", $doc_mod, "::", stringify!($Machine), ";")]
            ///
            /// // LEN f2 "hi" — replaced from two transient chunks, one
            /// // undo step.
            /// let msg = [0x12, 0x02, 0x68, 0x69];
            #[doc = concat!(" let mut ", $noun, " = ", $door, ".unwrap();")]
            #[doc = concat!(" let record = ", $noun, ".top().next().unwrap();")]
            ///
            #[doc = concat!(" let mut frame = ", $noun, ".begin_set_payload(record).unwrap();")]
            /// frame.write(&[0x61]).unwrap();
            /// frame.write(&[0x62, 0x63]).unwrap();
            /// frame.finish().unwrap();
            #[doc = concat!(" assert_eq!(", $noun, ".pending(), 1);")]
            #[doc = concat!(" assert_eq!(", $noun, ".save().unwrap()[..], [0x12, 0x03, 0x61, 0x62, 0x63]);")]
            ///
            #[doc = concat!(" ", $noun, ".revert();")]
            #[doc = concat!(" assert_eq!(", $noun, ".save().unwrap()[..], [0x12, 0x02, 0x68, 0x69]);")]
            /// ```
            #[track_caller]
            pub fn begin_set_payload(&mut self, handle: Handle) -> Result<PayloadFrame<'_ $(, $lt)?>, EditFault> {
                let witness = self.value_gate(handle, RecordKind::Len)?;
                self.interior_gate(handle.0)?;
                let mark = self.store.stage_mark();
                Ok(PayloadFrame { machine: self, op: FrameOp::Set { handle, witness }, mark })
            }

            /// Opens a staged insertion of a fresh LEN record at the
            #[doc = concat!(" anchor: chunks copy into the ", $noun, "'s store through the")]
            /// returned frame, and exactly one row splices — with its one
            /// logged transition — at [`finish`](PayloadFrame::finish)
            #[doc = concat!(" ([`", stringify!($Machine), "::begin_set_payload`]'s frame contract). The")]
            /// anchor resolves here; the frame's exclusive borrow keeps it
            /// valid through the close.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::insert_payload`]'s anchor gates. On `Err` the")]
            #[doc = concat!(" ", $noun, " is unchanged.")]
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
            ) -> Result<PayloadFrame<'_ $(, $lt)?>, EditFault> {
                let plan = self.resolve_anchor(at)?;
                let mark = self.store.stage_mark();
                Ok(PayloadFrame { machine: self, op: FrameOp::Insert { plan, field }, mark })
            }

            /// Judges a length-class declaration into the store's byte
            /// column and reserves its bytes exactly once — the sized
            /// doors' shared suffix. Both judgments precede the fallible
            /// reservation, so a refusal allocates nothing.
            fn stage_declare(&mut self, len: usize) -> Result<u32, EditFault> {
                if len > usize_of(PayloadLen::MAX.as_inner()) {
                    return Err(EditFault::PayloadTooLarge { len });
                }
                self.store.stage_reserve(len).map_err(edit_store_fault)?;
                #[allow(
                    clippy::cast_possible_truncation,
                    clippy::as_conversions,
                    reason = "just judged against the length class, which is below u32::MAX"
                )]
                Ok(len as u32)
            }

            #[doc = concat!(" [`begin_set_payload`](", stringify!($Machine), "::begin_set_payload)'s")]
            /// declared-length twin: the caller states the payload's exact
            /// byte length up front, so the class judgment lands here —
            /// zero allocation on refusal — and the store's byte column
            /// reserves exactly once, fallibly. The frame is held to its
            /// word: a write past the declaration refuses
            /// [`FrameFault::OverDeclared`], a finish short of it refuses
            /// [`FrameFault::UnderDeclared`], and either fault leaves the
            #[doc = concat!(" ", $noun, " unchanged (the undeclared frame's contract). The")]
            /// undeclared door serves callers streaming an unknown total.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::begin_set_payload`]'s gates, plus")]
            /// [`EditFault::PayloadTooLarge`] when `len` exceeds the
            /// length class — judged before anything is reserved —
            /// [`EditFault::IndexSpaceExhausted`] when the store's byte
            /// column cannot hold `len` more bytes, and
            /// [`EditFault::Resource`] when the allocator refuses the
            #[doc = concat!(" reservation. On `Err` the ", $noun, " is unchanged.")]
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the")]
            /// arena index contract).
            ///
            /// # Examples
            ///
            /// ```
            #[doc = concat!(" use ", $doc_mod, "::", stringify!($Machine), ";")]
            ///
            /// // LEN f2 "hi" — replaced from two chunks of a declared
            /// // five, one undo step.
            /// let msg = [0x12, 0x02, 0x68, 0x69];
            #[doc = concat!(" let mut ", $noun, " = ", $door, ".unwrap();")]
            #[doc = concat!(" let record = ", $noun, ".top().next().unwrap();")]
            ///
            #[doc = concat!(" let mut frame = ", $noun, ".begin_set_payload_sized(record, 5).unwrap();")]
            /// frame.write(b"wor").unwrap();
            /// frame.write(b"ld").unwrap();
            /// frame.finish().unwrap();
            #[doc = concat!(" assert_eq!(", $noun, ".pending(), 1);")]
            #[doc = concat!(" assert_eq!(", $noun, ".save().unwrap()[..], [0x12, 0x05, 0x77, 0x6F, 0x72, 0x6C, 0x64]);")]
            /// ```
            #[track_caller]
            pub fn begin_set_payload_sized(
                &mut self,
                handle: Handle,
                len: usize,
            ) -> Result<SizedPayloadFrame<'_ $(, $lt)?>, EditFault> {
                let witness = self.value_gate(handle, RecordKind::Len)?;
                self.interior_gate(handle.0)?;
                let declared = self.stage_declare(len)?;
                let mark = self.store.stage_mark();
                Ok(SizedPayloadFrame {
                    inner: PayloadFrame { machine: self, op: FrameOp::Set { handle, witness }, mark },
                    declared,
                })
            }

            #[doc = concat!(" [`begin_insert_payload`](", stringify!($Machine), "::begin_insert_payload)'s")]
            /// declared-length twin
            #[doc = concat!(" ([`", stringify!($Machine), "::begin_set_payload_sized`]'s door contract, at")]
            /// an anchor).
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::begin_insert_payload`]'s anchor gates, plus")]
            /// the sized door's judgments: [`EditFault::PayloadTooLarge`]
            /// when `len` exceeds the length class — judged before
            /// anything is reserved — [`EditFault::IndexSpaceExhausted`]
            /// when the store's byte column cannot hold `len` more bytes,
            /// and [`EditFault::Resource`] when the allocator refuses the
            #[doc = concat!(" reservation. On `Err` the ", $noun, " is unchanged.")]
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
            ) -> Result<SizedPayloadFrame<'_ $(, $lt)?>, EditFault> {
                let plan = self.resolve_anchor(at)?;
                let declared = self.stage_declare(len)?;
                let mark = self.store.stage_mark();
                Ok(SizedPayloadFrame {
                    inner: PayloadFrame { machine: self, op: FrameOp::Insert { plan, field }, mark },
                    declared,
                })
            }

    };
    (@frame_doors borrow $(<$($lt:lifetime),+>)?, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
    };
    (@frame_doors mixed <$($lt:lifetime),+>, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            // ── the staged payload frame ──

            /// Opens a staged replacement of the LEN record's payload:
            #[doc = concat!(" chunks copy into the ", $noun, "'s store through the returned")]
            /// frame — a frame necessarily owns its transient chunks, so
            /// the doors carry no `_copy` suffix — and exactly one
            /// logged transition applies at
            /// [`finish`](MixPayloadFrame::finish) — before it, no row
            /// or log state changes, so a revert can never see a
            /// half-staged command. The gates judge here, so the frame
            /// itself cannot discover a refused target.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::set_payload`]'s gates. On `Err` the ", $noun)]
            /// is unchanged.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the")]
            /// arena index contract).
            ///
            /// # Examples
            ///
            /// ```
            #[doc = concat!(" use ", $doc_mod, "::", stringify!($Machine), ";")]
            ///
            /// // LEN f2 "hi" — replaced from two transient chunks, one
            /// // undo step.
            /// let msg = [0x12, 0x02, 0x68, 0x69];
            #[doc = concat!(" let mut ", $noun, " = ", $door, ".unwrap();")]
            #[doc = concat!(" let record = ", $noun, ".top().next().unwrap();")]
            ///
            #[doc = concat!(" let mut frame = ", $noun, ".begin_set_payload(record).unwrap();")]
            /// frame.write(&[0x61]).unwrap();
            /// frame.write(&[0x62, 0x63]).unwrap();
            /// frame.finish().unwrap();
            #[doc = concat!(" assert_eq!(", $noun, ".pending(), 1);")]
            #[doc = concat!(" assert_eq!(", $noun, ".save().unwrap()[..], [0x12, 0x03, 0x61, 0x62, 0x63]);")]
            ///
            #[doc = concat!(" ", $noun, ".revert();")]
            #[doc = concat!(" assert_eq!(", $noun, ".save().unwrap()[..], [0x12, 0x02, 0x68, 0x69]);")]
            /// ```
            #[track_caller]
            pub fn begin_set_payload(&mut self, handle: Handle) -> Result<MixPayloadFrame<'_, $($lt),+>, EditFault> {
                let witness = self.value_gate(handle, RecordKind::Len)?;
                self.interior_gate(handle.0)?;
                let mark = self.store.stage_mark();
                Ok(MixPayloadFrame { machine: self, op: FrameOp::Set { handle, witness }, mark })
            }

            /// Opens a staged insertion of a fresh LEN record at the
            #[doc = concat!(" anchor: chunks copy into the ", $noun, "'s store through the")]
            /// returned frame, and exactly one row splices — with its one
            /// logged transition — at [`finish`](MixPayloadFrame::finish)
            #[doc = concat!(" ([`", stringify!($Machine), "::begin_set_payload`]'s frame contract). The")]
            /// anchor resolves here; the frame's exclusive borrow keeps it
            /// valid through the close.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::insert_payload`]'s anchor gates. On `Err` the")]
            #[doc = concat!(" ", $noun, " is unchanged.")]
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
            ) -> Result<MixPayloadFrame<'_, $($lt),+>, EditFault> {
                let plan = self.resolve_anchor(at)?;
                let mark = self.store.stage_mark();
                Ok(MixPayloadFrame { machine: self, op: FrameOp::Insert { plan, field }, mark })
            }

            /// Judges a length-class declaration into the store's byte
            /// column and reserves its bytes exactly once — the sized
            /// doors' shared suffix. Both judgments precede the fallible
            /// reservation, so a refusal allocates nothing.
            fn stage_declare(&mut self, len: usize) -> Result<u32, EditFault> {
                if len > usize_of(PayloadLen::MAX.as_inner()) {
                    return Err(EditFault::PayloadTooLarge { len });
                }
                self.store.stage_reserve(len).map_err(edit_store_fault)?;
                #[allow(
                    clippy::cast_possible_truncation,
                    clippy::as_conversions,
                    reason = "just judged against the length class, which is below u32::MAX"
                )]
                Ok(len as u32)
            }

            #[doc = concat!(" [`begin_set_payload`](", stringify!($Machine), "::begin_set_payload)'s")]
            /// declared-length twin: the caller states the payload's exact
            /// byte length up front, so the class judgment lands here —
            /// zero allocation on refusal — and the store's byte column
            /// reserves exactly once, fallibly. The frame is held to its
            /// word: a write past the declaration refuses
            /// [`FrameFault::OverDeclared`], a finish short of it refuses
            /// [`FrameFault::UnderDeclared`], and either fault leaves the
            #[doc = concat!(" ", $noun, " unchanged (the undeclared frame's contract). The")]
            /// undeclared door serves callers streaming an unknown total.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::begin_set_payload`]'s gates, plus")]
            /// [`EditFault::PayloadTooLarge`] when `len` exceeds the
            /// length class — judged before anything is reserved —
            /// [`EditFault::IndexSpaceExhausted`] when the store's byte
            /// column cannot hold `len` more bytes, and
            /// [`EditFault::Resource`] when the allocator refuses the
            #[doc = concat!(" reservation. On `Err` the ", $noun, " is unchanged.")]
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the")]
            /// arena index contract).
            ///
            /// # Examples
            ///
            /// ```
            #[doc = concat!(" use ", $doc_mod, "::", stringify!($Machine), ";")]
            ///
            /// // LEN f2 "hi" — replaced from two chunks of a declared
            /// // five, one undo step.
            /// let msg = [0x12, 0x02, 0x68, 0x69];
            #[doc = concat!(" let mut ", $noun, " = ", $door, ".unwrap();")]
            #[doc = concat!(" let record = ", $noun, ".top().next().unwrap();")]
            ///
            #[doc = concat!(" let mut frame = ", $noun, ".begin_set_payload_sized(record, 5).unwrap();")]
            /// frame.write(b"wor").unwrap();
            /// frame.write(b"ld").unwrap();
            /// frame.finish().unwrap();
            #[doc = concat!(" assert_eq!(", $noun, ".pending(), 1);")]
            #[doc = concat!(" assert_eq!(", $noun, ".save().unwrap()[..], [0x12, 0x05, 0x77, 0x6F, 0x72, 0x6C, 0x64]);")]
            /// ```
            #[track_caller]
            pub fn begin_set_payload_sized(
                &mut self,
                handle: Handle,
                len: usize,
            ) -> Result<MixSizedPayloadFrame<'_, $($lt),+>, EditFault> {
                let witness = self.value_gate(handle, RecordKind::Len)?;
                self.interior_gate(handle.0)?;
                let declared = self.stage_declare(len)?;
                let mark = self.store.stage_mark();
                Ok(MixSizedPayloadFrame {
                    inner: MixPayloadFrame { machine: self, op: FrameOp::Set { handle, witness }, mark },
                    declared,
                })
            }

            #[doc = concat!(" [`begin_insert_payload`](", stringify!($Machine), "::begin_insert_payload)'s")]
            /// declared-length twin
            #[doc = concat!(" ([`", stringify!($Machine), "::begin_set_payload_sized`]'s door contract, at")]
            /// an anchor).
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::begin_insert_payload`]'s anchor gates, plus")]
            /// the sized door's judgments: [`EditFault::PayloadTooLarge`]
            /// when `len` exceeds the length class — judged before
            /// anything is reserved — [`EditFault::IndexSpaceExhausted`]
            /// when the store's byte column cannot hold `len` more bytes,
            /// and [`EditFault::Resource`] when the allocator refuses the
            #[doc = concat!(" reservation. On `Err` the ", $noun, " is unchanged.")]
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
            ) -> Result<MixSizedPayloadFrame<'_, $($lt),+>, EditFault> {
                let plan = self.resolve_anchor(at)?;
                let declared = self.stage_declare(len)?;
                let mark = self.store.stage_mark();
                Ok(MixSizedPayloadFrame {
                    inner: MixPayloadFrame { machine: self, op: FrameOp::Insert { plan, field }, mark },
                    declared,
                })
            }

    };
    (@descend plain borrow, src: $src:ident, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// Parses a LEN payload into its interior layer, once: later
            /// calls project the stored outcome, and a wire fault or a
            /// refusal inside the payload (a group code included) is a
            #[doc = concat!(" resident verdict, not ", $a_noun, " stop.")]
            ///
            /// An authored payload scans inside its own slot: the
            /// borrowed slice is the interior's whole zone, immutable
            /// for the machine's life, so the minted rows' offsets are
            /// relative to it.
            ///
            /// # Errors
            ///
            /// [`EditFault::DeadHandle`] for an orphaned row,
            /// [`EditFault::KindMismatch`] off the LEN kind,
            /// [`EditFault::Resource`]/[`EditFault::IndexSpaceExhausted`] when the
            /// interior scan cannot be stored — the slot stays unopened
            /// and the call may be retried.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the")]
            /// arena index contract).
            #[track_caller]
            pub fn descend(&mut self, handle: Handle) -> Result<Descent<'_>, EditFault> {
                let row = *self.live(handle)?;
                if !matches!(row.kind, RecordKind::Len) {
                    return Err(EditFault::KindMismatch { have: row.kind });
                }
                let id = handle.0;
                match row.slot() {
                    Slot::Opened(layer) => {
                        Ok(Descent::Opened { first: self.layer(layer).first.map(Handle) })
                    }
                    Slot::Fault(index) => Ok(project(&self.faults, index)),
                    Slot::Unopened => {
                        let (slot, start, len) = match row.edit.effective() {
                            Some(value) => {
                                let (at, len) = self.store.span(value);
                                (Some(value), at, len)
                            }
                            None => {
                                // SAFETY: this arm matched an edit outside
                                // the Inserted family.
                                let (at, len) = self.len_geometry(&row, unsafe { scanned_at(&row) });
                                let slot = if row.authored_zone() {
                                    Some(Self::zone_slot(&self.rows, &row))
                                } else {
                                    None
                                };
                                (slot, at, len)
                            }
                        };
                        let authored = slot.is_some();
                        let end = start + len;
                        let rows_mark = self.rows.len();
                        let runs_mark = self.source_runs.len();
                        let zone: &[u8] = match slot {
                            Some(value) => self.store.span_bytes(value),
                            None => $crate::revise::groupless::revising_machine!(@doc_zone $src, self),
                        };
                        let halt = match scan_layer(&mut self.rows, zone, authored, start, end, Some(id)) {
                            Ok((first, last)) => match self.seal_scan(id, first, last, authored) {
                                Ok(()) => return Ok(Descent::Opened { first: first.map(Handle) }),
                                Err(fault) => {
                                    // Discard the provisional tables: the
                                    // slot publishes whole or not at all,
                                    // and the refusal is retryable.
                                    self.rows.truncate(rows_mark);
                                    self.source_runs.truncate(runs_mark);
                                    return Err(fault);
                                }
                            },
                            Err(halt) => halt,
                        };
                        // Discard the provisional rows: the slot publishes
                        // whole or not at all.
                        self.rows.truncate(rows_mark);
                        let fault = match halt {
                            LayerHalt::Wire(fault) => SlotFault::Wire(fault),
                            LayerHalt::Refused(refusal) => SlotFault::Refused(refusal),
                            LayerHalt::Resource => return Err(EditFault::Resource),
                            LayerHalt::Exhausted => return Err(EditFault::IndexSpaceExhausted),
                        };
                        let index = self.push_fault(fault)?;
                        self.row_mut(id).set_slot(Slot::Fault(index));
                        Ok(project(&self.faults, index))
                    }
                }
            }

    };
    (@descend $cap:ident borrow, src: $src:ident, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// Parses a LEN payload into its interior layer, once: later
            /// calls project the stored outcome, and a wire fault or a
            /// refusal inside the payload (a group code included) is a
            #[doc = concat!(" resident verdict, not ", $a_noun, " stop.")]
            ///
            /// An imported record's interior descends too: its rows are
            /// first-class — readable and editable like scanned rows —
            /// over the import's own bytes, and verdict and fault
            /// offsets inside them index the import's own byte zone,
            /// not this machine's source.
            ///
            /// An authored payload scans inside its own slot: the
            /// borrowed slice is the interior's whole zone, immutable
            /// for the machine's life, so the minted rows' offsets are
            /// relative to it.
            ///
            /// # Errors
            ///
            /// [`EditFault::DeadHandle`] for an orphaned row,
            /// [`EditFault::KindMismatch`] off the LEN kind,
            /// [`EditFault::Resource`]/[`EditFault::IndexSpaceExhausted`] when the
            /// interior scan cannot be stored — the slot stays unopened
            /// and the call may be retried.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the")]
            /// arena index contract).
            #[track_caller]
            pub fn descend(&mut self, handle: Handle) -> Result<Descent<'_>, EditFault> {
                let row = *self.live(handle)?;
                if !matches!(row.kind, RecordKind::Len) {
                    return Err(EditFault::KindMismatch { have: row.kind });
                }
                let id = handle.0;
                match row.slot() {
                    Slot::Opened(layer) => {
                        Ok(Descent::Opened { first: self.layer(layer).first.map(Handle) })
                    }
                    Slot::Fault(index) => Ok(project(&self.faults, index)),
                    Slot::Unopened => {
                        // Which zone backs the interior (a borrowed slot
                        // is its own zone with relative offsets), whether
                        // its rows are browse-only authored bytes or
                        // first-class alias rows, and whether a
                        // reverse-lookup run may mint (original document
                        // interiors alone).
                        let (slot, alias, start, len) = match row.edit {
                            Edit::Replaced(value)
                            | Edit::Deleted(Some(value))
                            | Edit::Inserted(value)
                            | Edit::InsertedDeleted(value) => {
                                let (at, len) = self.store.span(value);
                                (Some(value), false, at, len)
                            }
                            // A transfer's retained interior parses from
                            // the designated document subspan; its rows
                            // are output-authored and editable.
                            Edit::SourcePayload(src)
                            | Edit::SourcePayloadDeleted(src)
                            | Edit::SourceInserted(src)
                            | Edit::SourceInsertedDeleted(src) => {
                                let (at, len) = self.designated_payload(src);
                                (None, true, at, len)
                            }
                            // An imported record's interior parses inside
                            // its own slot zone at slot-relative offsets
                            // as first-class alias rows.
                            Edit::Imported(value) | Edit::ImportedDeleted(value) => {
                                let bytes = self.import_slot(value);
                                let at = import_value_at(bytes);
                                match slice::len_word(bytes, at, bytes.len()) {
                                    Ok((len, width)) => {
                                        let body =
                                            crate::admission::admitted_u32(at + usize::from(width));
                                        (
                                            Some(value),
                                            $crate::revise::groupless::revising_machine!(@import_first_class $cap),
                                            body,
                                            len.as_inner(),
                                        )
                                    }
                                    Err(_) => unreachable!(
                                        "imported records are structurally complete"
                                    ),
                                }
                            }
                            Edit::SourceRecord | Edit::SourceRecordDeleted => {
                                // SAFETY: clone-minted rows carry their
                                // source geometry.
                                let (at, len) = self.len_geometry(&row, unsafe { scanned_at(&row) });
                                (None, true, at, len)
                            }
                            Edit::Intact | Edit::Deleted(None) | Edit::Moved { .. } => {
                                // SAFETY: this arm sits outside the
                                // Inserted and Imported families.
                                let (at, len) = self.len_geometry(&row, unsafe { scanned_at(&row) });
                                let slot = if row.authored_zone() {
                                    Some(Self::zone_slot(&self.rows, &row))
                                } else {
                                    None
                                };
                                (slot, false, at, len)
                            }
                        };
                        let alias = alias || row.alias();
                        let authored = slot.is_some();
                        let end = start + len;
                        let rows_mark = self.rows.len();
                        let runs_mark = self.source_runs.len();
                        let zone: &[u8] = match slot {
                            Some(value) => self.store.span_bytes(value),
                            None => $crate::revise::groupless::revising_machine!(@doc_zone $src, self),
                        };
                        let halt = match scan_layer(&mut self.rows, zone, authored, start, end, Some(id)) {
                            Ok((first, last)) => {
                                if alias {
                                    for interior in &mut self.rows[rows_mark..] {
                                        interior.flags |= FLAG_ALIAS;
                                    }
                                }
                                match self.seal_scan(id, first, last, !authored && !alias) {
                                    Ok(()) => {
                                        return Ok(Descent::Opened { first: first.map(Handle) });
                                    }
                                    Err(fault) => {
                                        // Discard the provisional tables:
                                        // the slot publishes whole or not
                                        // at all, and the refusal is
                                        // retryable.
                                        self.rows.truncate(rows_mark);
                                        self.source_runs.truncate(runs_mark);
                                        return Err(fault);
                                    }
                                }
                            }
                            Err(halt) => halt,
                        };
                        // Discard the provisional rows: the slot publishes
                        // whole or not at all.
                        self.rows.truncate(rows_mark);
                        let fault = match halt {
                            LayerHalt::Wire(fault) => SlotFault::Wire(fault),
                            LayerHalt::Refused(refusal) => SlotFault::Refused(refusal),
                            LayerHalt::Resource => return Err(EditFault::Resource),
                            LayerHalt::Exhausted => return Err(EditFault::IndexSpaceExhausted),
                        };
                        let index = self.push_fault(fault)?;
                        self.row_mut(id).set_slot(Slot::Fault(index));
                        Ok(project(&self.faults, index))
                    }
                }
            }

    };
    (@descend plain mixed, src: $src:ident, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// Parses a LEN payload into its interior layer, once: later
            /// calls project the stored outcome, and a wire fault or a
            /// refusal inside the payload (a group code included) is a
            #[doc = concat!(" resident verdict, not ", $a_noun, " stop.")]
            ///
            /// An authored payload scans inside its own slot: the
            /// payload slot — the borrowed slice or the copied extent —
            /// is the interior's whole zone, immutable for the
            /// machine's life, so the minted rows' offsets are relative
            /// to it, whichever backing the install chose.
            ///
            /// # Errors
            ///
            /// [`EditFault::DeadHandle`] for an orphaned row,
            /// [`EditFault::KindMismatch`] off the LEN kind,
            /// [`EditFault::Resource`]/[`EditFault::IndexSpaceExhausted`] when the
            /// interior scan cannot be stored — the slot stays unopened
            /// and the call may be retried.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the")]
            /// arena index contract).
            #[track_caller]
            pub fn descend(&mut self, handle: Handle) -> Result<Descent<'_>, EditFault> {
                let row = *self.live(handle)?;
                if !matches!(row.kind, RecordKind::Len) {
                    return Err(EditFault::KindMismatch { have: row.kind });
                }
                let id = handle.0;
                match row.slot() {
                    Slot::Opened(layer) => {
                        Ok(Descent::Opened { first: self.layer(layer).first.map(Handle) })
                    }
                    Slot::Fault(index) => Ok(project(&self.faults, index)),
                    Slot::Unopened => {
                        let (slot, start, len) = match row.edit.effective() {
                            Some(value) => {
                                let (at, len) = self.store.span(value);
                                (Some(value), at, len)
                            }
                            None => {
                                // SAFETY: this arm matched an edit outside
                                // the Inserted family.
                                let (at, len) = self.len_geometry(&row, unsafe { scanned_at(&row) });
                                let slot = if row.authored_zone() {
                                    Some(Self::zone_slot(&self.rows, &row))
                                } else {
                                    None
                                };
                                (slot, at, len)
                            }
                        };
                        let authored = slot.is_some();
                        let end = start + len;
                        let rows_mark = self.rows.len();
                        let runs_mark = self.source_runs.len();
                        let zone: &[u8] = match slot {
                            Some(value) => self.store.span_bytes(value),
                            None => $crate::revise::groupless::revising_machine!(@doc_zone $src, self),
                        };
                        let halt = match scan_layer(&mut self.rows, zone, authored, start, end, Some(id)) {
                            Ok((first, last)) => match self.seal_scan(id, first, last, authored) {
                                Ok(()) => return Ok(Descent::Opened { first: first.map(Handle) }),
                                Err(fault) => {
                                    // Discard the provisional tables: the
                                    // slot publishes whole or not at all,
                                    // and the refusal is retryable.
                                    self.rows.truncate(rows_mark);
                                    self.source_runs.truncate(runs_mark);
                                    return Err(fault);
                                }
                            },
                            Err(halt) => halt,
                        };
                        // Discard the provisional rows: the slot publishes
                        // whole or not at all.
                        self.rows.truncate(rows_mark);
                        let fault = match halt {
                            LayerHalt::Wire(fault) => SlotFault::Wire(fault),
                            LayerHalt::Refused(refusal) => SlotFault::Refused(refusal),
                            LayerHalt::Resource => return Err(EditFault::Resource),
                            LayerHalt::Exhausted => return Err(EditFault::IndexSpaceExhausted),
                        };
                        let index = self.push_fault(fault)?;
                        self.row_mut(id).set_slot(Slot::Fault(index));
                        Ok(project(&self.faults, index))
                    }
                }
            }

    };
    (@descend $cap:ident mixed, src: $src:ident, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// Parses a LEN payload into its interior layer, once: later
            /// calls project the stored outcome, and a wire fault or a
            /// refusal inside the payload (a group code included) is a
            #[doc = concat!(" resident verdict, not ", $a_noun, " stop.")]
            ///
            /// An imported record's interior descends too: its rows are
            /// first-class — readable and editable like scanned rows —
            /// over the import's own bytes, and verdict and fault
            /// offsets inside them index the import's own byte zone,
            /// not this machine's source.
            ///
            /// An authored payload scans inside its own slot: the
            /// payload slot — the borrowed slice or the copied extent —
            /// is the interior's whole zone, immutable for the
            /// machine's life, so the minted rows' offsets are relative
            /// to it, whichever backing the install chose.
            ///
            /// # Errors
            ///
            /// [`EditFault::DeadHandle`] for an orphaned row,
            /// [`EditFault::KindMismatch`] off the LEN kind,
            /// [`EditFault::Resource`]/[`EditFault::IndexSpaceExhausted`] when the
            /// interior scan cannot be stored — the slot stays unopened
            /// and the call may be retried.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the")]
            /// arena index contract).
            #[track_caller]
            pub fn descend(&mut self, handle: Handle) -> Result<Descent<'_>, EditFault> {
                let row = *self.live(handle)?;
                if !matches!(row.kind, RecordKind::Len) {
                    return Err(EditFault::KindMismatch { have: row.kind });
                }
                let id = handle.0;
                match row.slot() {
                    Slot::Opened(layer) => {
                        Ok(Descent::Opened { first: self.layer(layer).first.map(Handle) })
                    }
                    Slot::Fault(index) => Ok(project(&self.faults, index)),
                    Slot::Unopened => {
                        // Which zone backs the interior (a payload slot
                        // is its own zone with relative offsets), whether
                        // its rows are browse-only authored bytes or
                        // first-class alias rows, and whether a
                        // reverse-lookup run may mint (original document
                        // interiors alone).
                        let (slot, alias, start, len) = match row.edit {
                            Edit::Replaced(value)
                            | Edit::Deleted(Some(value))
                            | Edit::Inserted(value)
                            | Edit::InsertedDeleted(value) => {
                                let (at, len) = self.store.span(value);
                                (Some(value), false, at, len)
                            }
                            // A transfer's retained interior parses from
                            // the designated document subspan; its rows
                            // are output-authored and editable.
                            Edit::SourcePayload(src)
                            | Edit::SourcePayloadDeleted(src)
                            | Edit::SourceInserted(src)
                            | Edit::SourceInsertedDeleted(src) => {
                                let (at, len) = self.designated_payload(src);
                                (None, true, at, len)
                            }
                            // An imported record's interior parses inside
                            // its own slot zone at slot-relative offsets
                            // as first-class alias rows.
                            Edit::Imported(value) | Edit::ImportedDeleted(value) => {
                                let bytes = self.import_slot(value);
                                let at = import_value_at(bytes);
                                match slice::len_word(bytes, at, bytes.len()) {
                                    Ok((len, width)) => {
                                        let body =
                                            crate::admission::admitted_u32(at + usize::from(width));
                                        (
                                            Some(value),
                                            $crate::revise::groupless::revising_machine!(@import_first_class $cap),
                                            body,
                                            len.as_inner(),
                                        )
                                    }
                                    Err(_) => unreachable!(
                                        "imported records are structurally complete"
                                    ),
                                }
                            }
                            Edit::SourceRecord | Edit::SourceRecordDeleted => {
                                // SAFETY: clone-minted rows carry their
                                // source geometry.
                                let (at, len) = self.len_geometry(&row, unsafe { scanned_at(&row) });
                                (None, true, at, len)
                            }
                            Edit::Intact | Edit::Deleted(None) | Edit::Moved { .. } => {
                                // SAFETY: this arm sits outside the
                                // Inserted and Imported families.
                                let (at, len) = self.len_geometry(&row, unsafe { scanned_at(&row) });
                                let slot = if row.authored_zone() {
                                    Some(Self::zone_slot(&self.rows, &row))
                                } else {
                                    None
                                };
                                (slot, false, at, len)
                            }
                        };
                        let alias = alias || row.alias();
                        let authored = slot.is_some();
                        let end = start + len;
                        let rows_mark = self.rows.len();
                        let runs_mark = self.source_runs.len();
                        let zone: &[u8] = match slot {
                            Some(value) => self.store.span_bytes(value),
                            None => $crate::revise::groupless::revising_machine!(@doc_zone $src, self),
                        };
                        let halt = match scan_layer(&mut self.rows, zone, authored, start, end, Some(id)) {
                            Ok((first, last)) => {
                                if alias {
                                    for interior in &mut self.rows[rows_mark..] {
                                        interior.flags |= FLAG_ALIAS;
                                    }
                                }
                                match self.seal_scan(id, first, last, !authored && !alias) {
                                    Ok(()) => {
                                        return Ok(Descent::Opened { first: first.map(Handle) });
                                    }
                                    Err(fault) => {
                                        // Discard the provisional tables:
                                        // the slot publishes whole or not
                                        // at all, and the refusal is
                                        // retryable.
                                        self.rows.truncate(rows_mark);
                                        self.source_runs.truncate(runs_mark);
                                        return Err(fault);
                                    }
                                }
                            }
                            Err(halt) => halt,
                        };
                        // Discard the provisional rows: the slot publishes
                        // whole or not at all.
                        self.rows.truncate(rows_mark);
                        let fault = match halt {
                            LayerHalt::Wire(fault) => SlotFault::Wire(fault),
                            LayerHalt::Refused(refusal) => SlotFault::Refused(refusal),
                            LayerHalt::Resource => return Err(EditFault::Resource),
                            LayerHalt::Exhausted => return Err(EditFault::IndexSpaceExhausted),
                        };
                        let index = self.push_fault(fault)?;
                        self.row_mut(id).set_slot(Slot::Fault(index));
                        Ok(project(&self.faults, index))
                    }
                }
            }

    };
    (@zone_readers tolerant, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// Re-reads a scanned varint row's value from its bound offset.
            fn scan_varint(&self, row: &Row, at: At32) -> u64 {
                let at = at.as_inner() + row.tag_w();
                // SAFETY: admission judged a terminating in-class varint
                // inside the sealed zone right after the tag, and the
                // stored tag width binds that value's offset — a padded
                // read assembles to the same word the scan admitted.
                unsafe { slice::value64_unchecked(self.backing(row), usize_of(at)) }
            }

            /// Re-reads a scanned fixed 32-bit row's value from its bound
            /// offset.
            fn scan_bits32(&self, row: &Row, at: At32) -> u32 {
                let at = at.as_inner() + row.tag_w();
                // SAFETY: admission judged four value bytes inside the
                // sealed zone's extent, right after the stored tag width.
                let raw =
                    unsafe { self.backing(row).as_ptr().add(usize_of(at)).cast::<u32>().read_unaligned() };
                u32::from_le(raw)
            }

            /// Re-reads a scanned fixed 64-bit row's value from its bound
            /// offset.
            fn scan_bits64(&self, row: &Row, at: At32) -> u64 {
                let at = at.as_inner() + row.tag_w();
                // SAFETY: admission judged eight value bytes inside the
                // sealed zone's extent, right after the stored tag width.
                let raw =
                    unsafe { self.backing(row).as_ptr().add(usize_of(at)).cast::<u64>().read_unaligned() };
                u64::from_le(raw)
            }

            /// Payload geometry of a scanned LEN row: offset and length in
            /// its backing zone. Both framing widths are stored input
            /// facts — tolerant admission accepts padded framing, so
            /// nothing here re-derives a width from a value.
            fn len_geometry(&self, row: &Row, at: At32) -> (u32, u32) {
                let payload_at = at.as_inner() + row.tag_w() + row.delim_w();
                (payload_at, row.end - payload_at)
            }

    };
    (@zone_readers canonical, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// Re-reads a scanned varint row's value from its bound offset.
            fn scan_varint(&self, row: &Row, at: At32) -> u64 {
                let at = at.as_inner() + head_width(row.field, RecordKind::Varint);
                // SAFETY: admission judged a terminating in-class varint
                // inside the sealed zone right after the tag, and the
                // canonical-minimal gate makes the tag's width exactly its
                // word's encoded length — so `at` is that value's offset.
                unsafe { slice::value64_unchecked(self.backing(row), usize_of(at)) }
            }

            /// Re-reads a scanned fixed 32-bit row's value from its bound
            /// offset.
            fn scan_bits32(&self, row: &Row, at: At32) -> u32 {
                let at = at.as_inner() + head_width(row.field, RecordKind::I32);
                // SAFETY: admission judged four value bytes inside the
                // sealed zone's extent, right after a tag whose width the
                // canonical gate pins to its word's encoded length.
                let raw =
                    unsafe { self.backing(row).as_ptr().add(usize_of(at)).cast::<u32>().read_unaligned() };
                u32::from_le(raw)
            }

            /// Re-reads a scanned fixed 64-bit row's value from its bound
            /// offset.
            fn scan_bits64(&self, row: &Row, at: At32) -> u64 {
                let at = at.as_inner() + head_width(row.field, RecordKind::I64);
                // SAFETY: admission judged eight value bytes inside the
                // sealed zone's extent, right after a tag whose width the
                // canonical gate pins to its word's encoded length.
                let raw =
                    unsafe { self.backing(row).as_ptr().add(usize_of(at)).cast::<u64>().read_unaligned() };
                u64::from_le(raw)
            }

            /// Payload geometry of a scanned LEN row: offset and length in
            /// its backing zone. The prefix width is derived from the
            /// length value — canonical admission makes the bytes a pure
            /// function of it.
            fn len_geometry(&self, row: &Row, at: At32) -> (u32, u32) {
                self.len_geometry_at(row, at.as_inner() + head_width(row.field, RecordKind::Len))
            }

            /// [`len_geometry`](Self::len_geometry) from the length
            /// prefix's own offset (the tag end) — the face for callers
            /// that already derived the tag's width.
            fn len_geometry_at(&self, row: &Row, prefix_at: u32) -> (u32, u32) {
                // SAFETY: admission judged a terminating in-class length
                // word right after the tag, whose width the canonical gate
                // pins to its word's encoded length — so `prefix_at` is the
                // prefix's offset inside the sealed zone.
                let word = unsafe { slice::value64_unchecked(self.backing(row), usize_of(prefix_at)) };
                let payload_at = prefix_at + encoded_len64(word);
                (payload_at, row.end - payload_at)
            }

    };
    (@record_ref plain tolerant, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// Designates the record for cross-machine transfer: the
            /// exact source record bytes bound to their proved field,
            /// kind, and framing geometry. The designation names the
            /// original admitted occurrence — a pending replacement does
            /// not ride, and rows without a live source occurrence
            /// (authored, shrouded, suppressed, or orphaned ones)
            /// refuse.
            ///
            /// # Errors
            ///
            /// [`Fault::NotSourceBacked`](crate::source::groupless::Fault::NotSourceBacked)
            /// for rows without a live source occurrence.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the")]
            /// arena index contract).
            #[track_caller]
            pub fn record_ref(
                &self,
                handle: Handle,
            ) -> Result<crate::source::groupless::RecordRef<'_>, crate::source::groupless::Fault>
            {
                let row = gate(&self.rows, handle);
                if row.dead()
                    || row.authored_zone()
                    || !matches!(row.edit, Edit::Intact | Edit::Replaced(_))
                {
                    return Err(crate::source::groupless::Fault::NotSourceBacked);
                }
                // SAFETY: the matched arms are outside the Inserted
                // family.
                let at = unsafe { scanned_at(row) }.as_inner();
                let (tag_width, delim_width) = match row.tag_width {
                    Some(w) => (w, row.delim_width),
                    // SAFETY: `scanned_at`'s precondition — outside the
                    // Inserted family means scan-pushed, and the scan
                    // stores its met width columns.
                    None => unsafe { core::hint::unreachable_unchecked() },
                };
                let tag_w = tag_width.w();
                let delim_w = delim_width.map_or(0, WordWidth::w);
                Ok(crate::source::groupless::RecordRef::mint(
                    // SAFETY: scanned spans lie within the sealed zone.
                    unsafe { self.backing(row).get_unchecked(usize_of(at)..usize_of(row.end)) },
                    row.field,
                    row.kind,
                    tag_width,
                    delim_width,
                    row.end - at - tag_w - delim_w,
                    false,
                ))
            }
    };
    (@record_ref plain canonical, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// Designates the record for cross-machine transfer: the
            /// exact source record bytes bound to their proved field,
            /// kind, and framing geometry, carrying this machine's
            /// canonical-admission proof. The designation names the
            /// original admitted occurrence — a pending replacement does
            /// not ride, and rows without a live source occurrence
            /// (authored, shrouded, suppressed, or orphaned ones)
            /// refuse.
            ///
            /// # Errors
            ///
            /// [`Fault::NotSourceBacked`](crate::source::groupless::Fault::NotSourceBacked)
            /// for rows without a live source occurrence.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the")]
            /// arena index contract).
            #[track_caller]
            pub fn record_ref(
                &self,
                handle: Handle,
            ) -> Result<crate::source::groupless::RecordRef<'_>, crate::source::groupless::Fault>
            {
                let row = gate(&self.rows, handle);
                if row.dead()
                    || row.authored_zone()
                    || !matches!(row.edit, Edit::Intact | Edit::Replaced(_))
                {
                    return Err(crate::source::groupless::Fault::NotSourceBacked);
                }
                // SAFETY: the matched arms are outside the Inserted
                // family.
                let at = unsafe { scanned_at(row) };
                let start = at.as_inner();
                let tag_width = WordWidth::minimal_of(head_word(row.field, row.kind));
                let tag_w = tag_width.w();
                let (delim_width, payload_len) = if matches!(row.kind, RecordKind::Len) {
                    // The prefix's word is the body length, in hand from
                    // the geometry read; canonical admission spells every
                    // framing word minimally.
                    let (_, len) = self.len_geometry(row, at);
                    (Some(WordWidth::minimal_of(len)), len)
                } else {
                    (None, row.end - start - tag_w)
                };
                Ok(crate::source::groupless::RecordRef::mint(
                    // SAFETY: scanned spans lie within the sealed zone.
                    unsafe {
                        self.backing(row).get_unchecked(usize_of(start)..usize_of(row.end))
                    },
                    row.field,
                    row.kind,
                    tag_width,
                    delim_width,
                    payload_len,
                    true,
                ))
            }
    };
    (@record_ref $cap:ident tolerant, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// Designates the record for cross-machine transfer: the
            /// exact source record bytes bound to their proved field,
            /// kind, and framing geometry. The designation names the
            /// original admitted occurrence — a pending replacement does
            /// not ride, and rows without a live source occurrence
            /// (authored, shrouded, suppressed, or orphaned ones)
            /// refuse.
            ///
            /// # Errors
            ///
            /// [`Fault::NotSourceBacked`](crate::source::groupless::Fault::NotSourceBacked)
            /// for rows without a live source occurrence.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the")]
            /// arena index contract).
            #[track_caller]
            pub fn record_ref(
                &self,
                handle: Handle,
            ) -> Result<crate::source::groupless::RecordRef<'_>, crate::source::groupless::Fault>
            {
                let row = gate(&self.rows, handle);
                if row.dead()
                    || row.authored_zone()
                    || row.alias()
                    || !matches!(row.edit, Edit::Intact | Edit::Replaced(_) | Edit::SourcePayload(_))
                {
                    return Err(crate::source::groupless::Fault::NotSourceBacked);
                }
                // SAFETY: the matched arms are outside the Inserted
                // family.
                let at = unsafe { scanned_at(row) }.as_inner();
                let (tag_width, delim_width) = match row.tag_width {
                    Some(w) => (w, row.delim_width),
                    // SAFETY: `scanned_at`'s precondition — outside the
                    // Inserted family means scan-pushed, and the scan
                    // stores its met width columns.
                    None => unsafe { core::hint::unreachable_unchecked() },
                };
                let tag_w = tag_width.w();
                let delim_w = delim_width.map_or(0, WordWidth::w);
                Ok(crate::source::groupless::RecordRef::mint(
                    // SAFETY: scanned spans lie within the sealed zone.
                    unsafe { self.backing(row).get_unchecked(usize_of(at)..usize_of(row.end)) },
                    row.field,
                    row.kind,
                    tag_width,
                    delim_width,
                    row.end - at - tag_w - delim_w,
                    false,
                ))
            }
    };
    (@record_ref $cap:ident canonical, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// Designates the record for cross-machine transfer: the
            /// exact source record bytes bound to their proved field,
            /// kind, and framing geometry, carrying this machine's
            /// canonical-admission proof. The designation names the
            /// original admitted occurrence — a pending replacement does
            /// not ride, and rows without a live source occurrence
            /// (authored, shrouded, suppressed, or orphaned ones)
            /// refuse.
            ///
            /// # Errors
            ///
            /// [`Fault::NotSourceBacked`](crate::source::groupless::Fault::NotSourceBacked)
            /// for rows without a live source occurrence.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the")]
            /// arena index contract).
            #[track_caller]
            pub fn record_ref(
                &self,
                handle: Handle,
            ) -> Result<crate::source::groupless::RecordRef<'_>, crate::source::groupless::Fault>
            {
                let row = gate(&self.rows, handle);
                if row.dead()
                    || row.authored_zone()
                    || row.alias()
                    || !matches!(row.edit, Edit::Intact | Edit::Replaced(_) | Edit::SourcePayload(_))
                {
                    return Err(crate::source::groupless::Fault::NotSourceBacked);
                }
                // SAFETY: the matched arms are outside the Inserted
                // family.
                let at = unsafe { scanned_at(row) };
                let start = at.as_inner();
                let tag_width = WordWidth::minimal_of(head_word(row.field, row.kind));
                let tag_w = tag_width.w();
                let (delim_width, payload_len) = if matches!(row.kind, RecordKind::Len) {
                    // The prefix's word is the body length, in hand from
                    // the geometry read; canonical admission spells every
                    // framing word minimally.
                    let (_, len) = self.len_geometry(row, at);
                    (Some(WordWidth::minimal_of(len)), len)
                } else {
                    (None, row.end - start - tag_w)
                };
                Ok(crate::source::groupless::RecordRef::mint(
                    // SAFETY: scanned spans lie within the sealed zone.
                    unsafe {
                        self.backing(row).get_unchecked(usize_of(start)..usize_of(row.end))
                    },
                    row.field,
                    row.kind,
                    tag_width,
                    delim_width,
                    payload_len,
                    true,
                ))
            }
    };
    (@observe_head vec, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
    };
    (@observe_head stream, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
    };
    (@observe_head borrow, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
    };
    (@observe_head carrier, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            #[doc = concat!(" The sealed document this ", $noun, " opened.")]
            #[inline]
            #[must_use]
            pub const fn doc(&self) -> &DocBytes {
                &self.source
            }

    };
    (@source_spans $cap:ident tolerant, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// Source-document geometry of the record (`None` for rows
            /// without source bytes). The segments partition the record's
            /// span, at the widths the scan actually met — padded framing
            /// reports its padded extents.
            ///
            /// # Errors
            ///
            /// [`EditFault::DeadHandle`] for an orphaned row.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the")]
            /// arena index contract).
            ///
            /// # Examples
            ///
            /// ```
            #[doc = concat!(" use ", $doc_mod, "::{", stringify!($Machine), ", RecordSpans};")]
            ///
            /// // LEN f2 "hi", its prefix padded to two bytes: tag at 0,
            /// // prefix at 1..3, payload at 3..5.
            /// let msg = [0x12, 0x82, 0x00, 0x68, 0x69];
            #[doc = concat!(" let ", $noun, " = ", $door, ".unwrap();")]
            #[doc = concat!(" let record = ", $noun, ".top().next().unwrap();")]
            /// let Some(RecordSpans::Len { tag, prefix, payload }) =
            #[doc = concat!("     ", $noun, ".source_spans(record).unwrap()")]
            /// else {
            ///     unreachable!()
            /// };
            /// assert_eq!((tag.start(), tag.end()), (0, 1));
            /// assert_eq!((prefix.start(), prefix.end()), (1, 3));
            /// assert_eq!((payload.start(), payload.end()), (3, 5));
            /// ```
            #[inline]
            #[track_caller]
            pub fn source_spans(&self, handle: Handle) -> Result<Option<RecordSpans>, EditFault> {
                let row = self.live(handle)?;
                if $crate::revise::groupless::revising_machine!(@authored_identity $cap, row) {
                    return Ok(None);
                }
                let Some(src) = row.at else {
                    return Ok(None);
                };
                let at = src.as_inner();
                let value_at = at + row.tag_w();
                let tag = Span::new(at, value_at);
                Ok(Some(match row.kind {
                    RecordKind::Varint => RecordSpans::Varint { tag, value: Span::new(value_at, row.end) },
                    RecordKind::I32 => RecordSpans::I32 { tag, value: Span::new(value_at, row.end) },
                    RecordKind::I64 => RecordSpans::I64 { tag, value: Span::new(value_at, row.end) },
                    RecordKind::Len => {
                        let payload_at = value_at + row.delim_w();
                        RecordSpans::Len {
                            tag,
                            prefix: Span::new(value_at, payload_at),
                            payload: Span::new(payload_at, row.end),
                        }
                    }
                }))
            }

    };
    (@source_spans $cap:ident canonical, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// Source-document geometry of the record (`None` for rows
            /// without source bytes). The segments partition the record's
            /// span; coordinates assume the canonically-admitted source.
            ///
            /// # Errors
            ///
            /// [`EditFault::DeadHandle`] for an orphaned row.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the")]
            /// arena index contract).
            ///
            /// # Examples
            ///
            /// ```
            #[doc = concat!(" use ", $doc_mod, "::{RecordSpans, ", stringify!($Machine), "};")]
            ///
            /// // LEN f2 "hi": tag at 0, prefix at 1, payload at 2..4.
            /// let msg = [0x12, 0x02, 0x68, 0x69];
            #[doc = concat!(" let ", $noun, " = ", $door, ".unwrap();")]
            #[doc = concat!(" let record = ", $noun, ".top().next().unwrap();")]
            /// let Some(RecordSpans::Len { tag, prefix, payload }) =
            #[doc = concat!("     ", $noun, ".source_spans(record).unwrap()")]
            /// else {
            ///     unreachable!()
            /// };
            /// assert_eq!((tag.start(), tag.end()), (0, 1));
            /// assert_eq!((prefix.start(), prefix.end()), (1, 2));
            /// assert_eq!((payload.start(), payload.end()), (2, 4));
            /// ```
            #[inline]
            #[track_caller]
            pub fn source_spans(&self, handle: Handle) -> Result<Option<RecordSpans>, EditFault> {
                let row = self.live(handle)?;
                if $crate::revise::groupless::revising_machine!(@authored_identity $cap, row) {
                    return Ok(None);
                }
                let Some(src) = row.at else {
                    return Ok(None);
                };
                let at = src.as_inner();
                let value_at = at + head_width(row.field, row.kind);
                let tag = Span::new(at, value_at);
                Ok(Some(match row.kind {
                    RecordKind::Varint => RecordSpans::Varint { tag, value: Span::new(value_at, row.end) },
                    RecordKind::I32 => RecordSpans::I32 { tag, value: Span::new(value_at, row.end) },
                    RecordKind::I64 => RecordSpans::I64 { tag, value: Span::new(value_at, row.end) },
                    RecordKind::Len => {
                        let (payload_at, _) = self.len_geometry_at(row, value_at);
                        RecordSpans::Len {
                            tag,
                            prefix: Span::new(value_at, payload_at),
                            payload: Span::new(payload_at, row.end),
                        }
                    }
                }))
            }

    };
    (@authored_identity plain, $row:ident) => { $row.authored_zone() };
    (@authored_identity $cap:ident, $row:ident) => { ($row.authored_zone() || $row.alias()) };
    (@seal_zone vec, $this:tt, $zone:ident, $authored:ident) => {
                        let $zone: &[u8] = if $authored { $this.store.zone() } else { &$this.source };
    };
    (@seal_zone stream, $this:tt, $zone:ident, $authored:ident) => {
                        let $zone: &[u8] = if $authored { $this.store.zone() } else { &$this.source };
    };
    (@seal_zone borrow, $this:tt, $zone:ident, $authored:ident) => {
                        let $zone: &[u8] = if $authored { $this.store.zone() } else { $this.source };
    };
    (@seal_zone carrier, $this:tt, $zone:ident, $authored:ident) => {
                        let $zone: &[u8] = if $authored { $this.store.zone() } else { $this.source.as_slice() };
    };
    (@settle plain tolerant, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// The save passes' verdict for one row, values resolved once
            /// — the fidelity dispatch: replaced records keep their source
            /// tag bytes verbatim, LEN prefixes ride verbatim while the
            /// body length is unchanged, and only command-authored records
            /// emit minimally.
            fn settle(&self, row: &Row) -> Arm {
                match row.edit {
                    Edit::Deleted(_) | Edit::InsertedDeleted(_) => Arm::Skip,
                    Edit::Intact => {
                        // SAFETY: the Intact arm is outside the Inserted
                        // family.
                        let at = unsafe { scanned_at(row) };
                        if !row.dirty() {
                            return Arm::Clean { at, end: row.end };
                        }
                        match row.kind {
                            RecordKind::Len if matches!(row.slot(), Slot::Opened(_)) => {
                                let tag_at = at.as_inner();
                                let tag_end = tag_at + row.tag_w();
                                let prefix_end = tag_end + row.delim_w();
                                Arm::Spine {
                                    tag_at,
                                    tag_end,
                                    prefix_end,
                                    src_len: row.end - prefix_end,
                                    first: self.slot_first(row.slot()),
                                }
                            }
                            // A dirty Intact row is an opened container
                            // with interior edits; the scalar arm here is
                            // untouched-only in practice — it stays for
                            // totality (settle is shared with both walks).
                            _ => Arm::Clean { at, end: row.end },
                        }
                    }
                    Edit::Replaced(value) => {
                        // SAFETY: Replaced is outside the Inserted family.
                        let at = unsafe { scanned_at(row) };
                        let tag_at = at.as_inner();
                        let tag_end = tag_at + row.tag_w();
                        match row.kind {
                            RecordKind::Varint => Arm::ReValue {
                                tag_at,
                                tag_end,
                                value: Word::Varint(self.store.varint(value)),
                            },
                            RecordKind::I32 => Arm::ReValue {
                                tag_at,
                                tag_end,
                                value: Word::Bits32(self.store.bits32(value)),
                            },
                            RecordKind::I64 => Arm::ReValue {
                                tag_at,
                                tag_end,
                                value: Word::Bits64(self.store.bits64(value)),
                            },
                            RecordKind::Len => {
                                let prefix_end = tag_end + row.delim_w();
                                Arm::ReBody {
                                    tag_at,
                                    tag_end,
                                    prefix_end,
                                    src_len: row.end - prefix_end,
                                    value,
                                }
                            }
                        }
                    }
                    Edit::Inserted(value) => {
                        let head = head_word(row.field, row.kind);
                        match row.kind {
                            RecordKind::Varint => {
                                Arm::NewValue { head, value: Word::Varint(self.store.varint(value)) }
                            }
                            RecordKind::I32 => {
                                Arm::NewValue { head, value: Word::Bits32(self.store.bits32(value)) }
                            }
                            RecordKind::I64 => {
                                Arm::NewValue { head, value: Word::Bits64(self.store.bits64(value)) }
                            }
                            RecordKind::Len => Arm::NewBody { head, value },
                        }
                    }
                }
            }

    };
    (@settle plain canonical, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// The save passes' verdict for one row, values resolved once.
            /// A dirty scanned row's offset is bound here and rides the
            /// source down to the byte readers.
            fn settle(&self, row: &Row) -> Arm {
                let source = match row.edit {
                    Edit::Deleted(_) | Edit::InsertedDeleted(_) => return Arm::Skip,
                    Edit::Replaced(value) | Edit::Inserted(value) => Src::Store(value),
                    Edit::Intact => {
                        // SAFETY: the Intact arm is outside the Inserted
                        // family.
                        let at = unsafe { scanned_at(row) };
                        if !row.dirty() {
                            return Arm::Clean { at, end: row.end };
                        }
                        Src::Doc(at)
                    }
                };
                let head = head_word(row.field, row.kind);
                match row.kind {
                    RecordKind::Varint => Arm::Varint {
                        head,
                        word: match source {
                            Src::Store(v) => self.store.varint(v),
                            Src::Doc(at) => self.scan_varint(row, at),
                        },
                    },
                    RecordKind::I32 => Arm::Bits32 {
                        head,
                        bits: match source {
                            Src::Store(v) => self.store.bits32(v),
                            Src::Doc(at) => self.scan_bits32(row, at),
                        },
                    },
                    RecordKind::I64 => Arm::Bits64 {
                        head,
                        bits: match source {
                            Src::Store(v) => self.store.bits64(v),
                            Src::Doc(at) => self.scan_bits64(row, at),
                        },
                    },
                    RecordKind::Len => match source {
                        Src::Store(value) => Arm::Body { head, value },
                        Src::Doc(at) => {
                            Arm::Spine { head, first: self.slot_first(row.slot()), at }
                        }
                    },
                }
            }

    };
    (@settle transfer tolerant, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// The save passes' verdict for one row, values resolved once
            /// — the fidelity dispatch: replaced records keep their source
            /// tag bytes verbatim, LEN prefixes ride verbatim while the
            /// body length is unchanged, and only command-authored records
            /// emit minimally.
            fn settle(&self, row: &Row) -> Arm {
                match row.edit {
                    Edit::Deleted(_)
                    | Edit::InsertedDeleted(_)
                    | Edit::Moved { .. }
                    | Edit::SourceRecordDeleted
                    | Edit::SourcePayloadDeleted(_)
                    | Edit::SourceInsertedDeleted(_)
                    | Edit::ImportedDeleted(_) => Arm::Skip,
                    // A live copy is dirt by state (it emits at a new
                    // position), so interior dirt is the layer count's
                    // question: clean interiors ride the whole cloned
                    // span verbatim.
                    Edit::SourceRecord => {
                        // SAFETY: clone-minted rows carry their source
                        // geometry.
                        let at = unsafe { scanned_at(row) };
                        match row.slot() {
                            Slot::Opened(layer) if self.layer(layer).dirty_kids > 0 => {
                                let tag_at = at.as_inner();
                                let tag_end = tag_at + row.tag_w();
                                let prefix_end = tag_end + row.delim_w();
                                Arm::Spine {
                                    tag_at,
                                    tag_end,
                                    prefix_end,
                                    src_len: row.end - prefix_end,
                                    first: self.slot_first(row.slot()),
                                }
                            }
                            Slot::Opened(_) | Slot::Unopened | Slot::Fault(_) => {
                                Arm::Clean { at, end: row.end }
                            }
                        }
                    }
                    Edit::SourcePayload(src) => {
                        // SAFETY: SourcePayload lands on scanned rows.
                        let at = unsafe { scanned_at(row) };
                        let tag_at = at.as_inner();
                        let tag_end = tag_at + row.tag_w();
                        let prefix_end = tag_end + row.delim_w();
                        // An edited designated interior walks like any
                        // edited subtree; untouched it rides the subspan
                        // whole.
                        match row.slot() {
                            Slot::Opened(layer) if self.layer(layer).dirty_kids > 0 => Arm::Spine {
                                tag_at,
                                tag_end,
                                prefix_end,
                                src_len: row.end - prefix_end,
                                first: self.slot_first(row.slot()),
                            },
                            Slot::Opened(_) | Slot::Unopened | Slot::Fault(_) => {
                                let (payload_at, len) = self.designated_payload(src);
                                Arm::ReBodyAlias {
                                    tag_at,
                                    tag_end,
                                    prefix_end,
                                    src_len: row.end - prefix_end,
                                    at: payload_at,
                                    len,
                                }
                            }
                        }
                    }
                    Edit::SourceInserted(src) => match row.slot() {
                        Slot::Opened(layer) if self.layer(layer).dirty_kids > 0 => Arm::NewSpine {
                            head: head_word(row.field, row.kind),
                            first: self.layer(layer).first,
                        },
                        Slot::Opened(_) | Slot::Unopened | Slot::Fault(_) => {
                            let (payload_at, len) = self.designated_payload(src);
                            Arm::NewBodyAlias {
                                head: head_word(row.field, row.kind),
                                at: payload_at,
                                len,
                            }
                        }
                    },
                    // A clean import emits its slot's exact bytes whole;
                    // interior edits walk the first-class rows instead,
                    // re-deriving the prefix from the walked body while
                    // the zone tag rides verbatim.
                    Edit::Imported(value) => match row.slot() {
                        Slot::Opened(layer) if self.layer(layer).dirty_kids > 0 => {
                            let (_, base) = self.import_zone(value);
                            let bytes = self.import_slot(value);
                            let at = import_value_at(bytes);
                            match slice::len_word(bytes, at, bytes.len()) {
                                Ok((len, width)) => {
                                    let tag_end = base + crate::admission::admitted_u32(at);
                                    Arm::ImportSpine {
                                        tag_at: base,
                                        tag_end,
                                        prefix_end: tag_end + u32::from(width),
                                        src_len: len.as_inner(),
                                        value,
                                        first: self.slot_first(row.slot()),
                                    }
                                }
                                Err(_) => unreachable!(
                                    "imported records are structurally complete"
                                ),
                            }
                        }
                        Slot::Opened(_) | Slot::Unopened | Slot::Fault(_) => {
                            Arm::Import { value }
                        }
                    },
                    Edit::Intact => {
                        // SAFETY: the Intact arm is outside the Inserted
                        // family.
                        let at = unsafe { scanned_at(row) };
                        if !row.dirty() {
                            return Arm::Clean { at, end: row.end };
                        }
                        match row.kind {
                            RecordKind::Len if matches!(row.slot(), Slot::Opened(_)) => {
                                let tag_at = at.as_inner();
                                let tag_end = tag_at + row.tag_w();
                                let prefix_end = tag_end + row.delim_w();
                                Arm::Spine {
                                    tag_at,
                                    tag_end,
                                    prefix_end,
                                    src_len: row.end - prefix_end,
                                    first: self.slot_first(row.slot()),
                                }
                            }
                            // A dirty Intact row is an opened container
                            // with interior edits; the scalar arm here is
                            // untouched-only in practice — it stays for
                            // totality (settle is shared with both walks).
                            _ => Arm::Clean { at, end: row.end },
                        }
                    }
                    Edit::Replaced(value) => {
                        // SAFETY: Replaced is outside the Inserted family.
                        let at = unsafe { scanned_at(row) };
                        let tag_at = at.as_inner();
                        let tag_end = tag_at + row.tag_w();
                        match row.kind {
                            RecordKind::Varint => Arm::ReValue {
                                tag_at,
                                tag_end,
                                value: Word::Varint(self.store.varint(value)),
                            },
                            RecordKind::I32 => Arm::ReValue {
                                tag_at,
                                tag_end,
                                value: Word::Bits32(self.store.bits32(value)),
                            },
                            RecordKind::I64 => Arm::ReValue {
                                tag_at,
                                tag_end,
                                value: Word::Bits64(self.store.bits64(value)),
                            },
                            RecordKind::Len => {
                                let prefix_end = tag_end + row.delim_w();
                                Arm::ReBody {
                                    tag_at,
                                    tag_end,
                                    prefix_end,
                                    src_len: row.end - prefix_end,
                                    value,
                                }
                            }
                        }
                    }
                    Edit::Inserted(value) => {
                        let head = head_word(row.field, row.kind);
                        match row.kind {
                            RecordKind::Varint => {
                                Arm::NewValue { head, value: Word::Varint(self.store.varint(value)) }
                            }
                            RecordKind::I32 => {
                                Arm::NewValue { head, value: Word::Bits32(self.store.bits32(value)) }
                            }
                            RecordKind::I64 => {
                                Arm::NewValue { head, value: Word::Bits64(self.store.bits64(value)) }
                            }
                            RecordKind::Len => Arm::NewBody { head, value },
                        }
                    }
                }
            }

    };
    (@settle $cap:ident tolerant, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// The save passes' verdict for one row, values resolved once
            /// — the fidelity dispatch: replaced records keep their source
            /// tag bytes verbatim, LEN prefixes ride verbatim while the
            /// body length is unchanged, and only command-authored records
            /// emit minimally.
            fn settle(&self, row: &Row) -> Arm {
                match row.edit {
                    Edit::Deleted(_)
                    | Edit::InsertedDeleted(_)
                    | Edit::Moved { .. }
                    | Edit::SourceRecordDeleted
                    | Edit::SourcePayloadDeleted(_)
                    | Edit::SourceInsertedDeleted(_)
                    | Edit::ImportedDeleted(_) => Arm::Skip,
                    // A live copy is dirt by state (it emits at a new
                    // position), so interior dirt is the layer count's
                    // question: clean interiors ride the whole cloned
                    // span verbatim.
                    Edit::SourceRecord => {
                        // SAFETY: clone-minted rows carry their source
                        // geometry.
                        let at = unsafe { scanned_at(row) };
                        match row.slot() {
                            Slot::Opened(layer) if self.layer(layer).dirty_kids > 0 => {
                                let tag_at = at.as_inner();
                                let tag_end = tag_at + row.tag_w();
                                let prefix_end = tag_end + row.delim_w();
                                Arm::Spine {
                                    tag_at,
                                    tag_end,
                                    prefix_end,
                                    src_len: row.end - prefix_end,
                                    first: self.slot_first(row.slot()),
                                }
                            }
                            Slot::Opened(_) | Slot::Unopened | Slot::Fault(_) => {
                                Arm::Clean { at, end: row.end }
                            }
                        }
                    }
                    Edit::SourcePayload(src) => {
                        // SAFETY: SourcePayload lands on scanned rows.
                        let at = unsafe { scanned_at(row) };
                        let tag_at = at.as_inner();
                        let tag_end = tag_at + row.tag_w();
                        let prefix_end = tag_end + row.delim_w();
                        // An edited designated interior walks like any
                        // edited subtree; untouched it rides the subspan
                        // whole.
                        match row.slot() {
                            Slot::Opened(layer) if self.layer(layer).dirty_kids > 0 => Arm::Spine {
                                tag_at,
                                tag_end,
                                prefix_end,
                                src_len: row.end - prefix_end,
                                first: self.slot_first(row.slot()),
                            },
                            Slot::Opened(_) | Slot::Unopened | Slot::Fault(_) => {
                                let (payload_at, len) = self.designated_payload(src);
                                Arm::ReBodyAlias {
                                    tag_at,
                                    tag_end,
                                    prefix_end,
                                    src_len: row.end - prefix_end,
                                    at: payload_at,
                                    len,
                                }
                            }
                        }
                    }
                    Edit::SourceInserted(src) => match row.slot() {
                        Slot::Opened(layer) if self.layer(layer).dirty_kids > 0 => Arm::NewSpine {
                            head: head_word(row.field, row.kind),
                            first: self.layer(layer).first,
                        },
                        Slot::Opened(_) | Slot::Unopened | Slot::Fault(_) => {
                            let (payload_at, len) = self.designated_payload(src);
                            Arm::NewBodyAlias {
                                head: head_word(row.field, row.kind),
                                at: payload_at,
                                len,
                            }
                        }
                    },
                    Edit::Imported(value) => Arm::Import { value },
                    Edit::Intact => {
                        // SAFETY: the Intact arm is outside the Inserted
                        // family.
                        let at = unsafe { scanned_at(row) };
                        if !row.dirty() {
                            return Arm::Clean { at, end: row.end };
                        }
                        match row.kind {
                            RecordKind::Len if matches!(row.slot(), Slot::Opened(_)) => {
                                let tag_at = at.as_inner();
                                let tag_end = tag_at + row.tag_w();
                                let prefix_end = tag_end + row.delim_w();
                                Arm::Spine {
                                    tag_at,
                                    tag_end,
                                    prefix_end,
                                    src_len: row.end - prefix_end,
                                    first: self.slot_first(row.slot()),
                                }
                            }
                            // A dirty Intact row is an opened container
                            // with interior edits; the scalar arm here is
                            // untouched-only in practice — it stays for
                            // totality (settle is shared with both walks).
                            _ => Arm::Clean { at, end: row.end },
                        }
                    }
                    Edit::Replaced(value) => {
                        // SAFETY: Replaced is outside the Inserted family.
                        let at = unsafe { scanned_at(row) };
                        let tag_at = at.as_inner();
                        let tag_end = tag_at + row.tag_w();
                        match row.kind {
                            RecordKind::Varint => Arm::ReValue {
                                tag_at,
                                tag_end,
                                value: Word::Varint(self.store.varint(value)),
                            },
                            RecordKind::I32 => Arm::ReValue {
                                tag_at,
                                tag_end,
                                value: Word::Bits32(self.store.bits32(value)),
                            },
                            RecordKind::I64 => Arm::ReValue {
                                tag_at,
                                tag_end,
                                value: Word::Bits64(self.store.bits64(value)),
                            },
                            RecordKind::Len => {
                                let prefix_end = tag_end + row.delim_w();
                                Arm::ReBody {
                                    tag_at,
                                    tag_end,
                                    prefix_end,
                                    src_len: row.end - prefix_end,
                                    value,
                                }
                            }
                        }
                    }
                    Edit::Inserted(value) => {
                        let head = head_word(row.field, row.kind);
                        match row.kind {
                            RecordKind::Varint => {
                                Arm::NewValue { head, value: Word::Varint(self.store.varint(value)) }
                            }
                            RecordKind::I32 => {
                                Arm::NewValue { head, value: Word::Bits32(self.store.bits32(value)) }
                            }
                            RecordKind::I64 => {
                                Arm::NewValue { head, value: Word::Bits64(self.store.bits64(value)) }
                            }
                            RecordKind::Len => Arm::NewBody { head, value },
                        }
                    }
                }
            }

    };
    (@settle transfer canonical, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// The save passes' verdict for one row, values resolved once.
            /// A dirty scanned row's offset is bound here and rides the
            /// source down to the byte readers.
            fn settle(&self, row: &Row) -> Arm {
                let source = match row.edit {
                    Edit::Deleted(_)
                    | Edit::InsertedDeleted(_)
                    | Edit::Moved { .. }
                    | Edit::SourceRecordDeleted
                    | Edit::SourcePayloadDeleted(_)
                    | Edit::SourceInsertedDeleted(_)
                    | Edit::ImportedDeleted(_) => return Arm::Skip,
                    // A live copy is dirt by state, so interior dirt is
                    // the layer count's question: clean interiors ride
                    // the whole cloned span verbatim (canonical
                    // admission proved the closure minimal).
                    Edit::SourceRecord => {
                        // SAFETY: clone-minted rows carry their source
                        // geometry.
                        let at = unsafe { scanned_at(row) };
                        return match row.slot() {
                            Slot::Opened(layer) if self.layer(layer).dirty_kids > 0 => Arm::Spine {
                                head: head_word(row.field, row.kind),
                                first: self.slot_first(row.slot()),
                                at,
                            },
                            Slot::Opened(_) | Slot::Unopened | Slot::Fault(_) => {
                                Arm::Clean { at, end: row.end }
                            }
                        };
                    }
                    // A designated payload prices and emits its subspan
                    // wholesale until an edit lands inside the descended
                    // interior; then it recurses like any edited subtree.
                    Edit::SourcePayload(src) | Edit::SourceInserted(src) => {
                        let (payload_at, len) = self.designated_payload(src);
                        return match row.slot() {
                            Slot::Opened(layer) if self.layer(layer).dirty_kids > 0 => Arm::Spine {
                                head: head_word(row.field, row.kind),
                                first: self.layer(layer).first,
                                // SAFETY: the designated subspan lies in
                                // the document zone, whose admitted end
                                // is inside the offset domain.
                                at: unsafe { At32::new_unchecked(payload_at) },
                            },
                            Slot::Opened(_) | Slot::Unopened | Slot::Fault(_) => Arm::BodyAlias {
                                head: head_word(row.field, row.kind),
                                at: payload_at,
                                len,
                            },
                        };
                    }
                    // A clean import emits its slot's exact bytes whole
                    // (canonical by admission); interior edits walk the
                    // first-class rows behind re-derived minimal framing.
                    Edit::Imported(value) => {
                        return match row.slot() {
                            Slot::Opened(layer) if self.layer(layer).dirty_kids > 0 => Arm::Spine {
                                head: head_word(row.field, row.kind),
                                first: self.layer(layer).first,
                                // SAFETY: the slot's framing bytes follow
                                // its zone base inside the store's byte
                                // column, so the base lies below the
                                // zone's admitted end.
                                at: unsafe { At32::new_unchecked(self.import_zone(value).1) },
                            },
                            Slot::Opened(_) | Slot::Unopened | Slot::Fault(_) => {
                                Arm::Import { value }
                            }
                        };
                    }
                    Edit::Replaced(value) | Edit::Inserted(value) => Src::Store(value),
                    Edit::Intact => {
                        // SAFETY: the Intact arm is outside the Inserted
                        // family.
                        let at = unsafe { scanned_at(row) };
                        if !row.dirty() {
                            return Arm::Clean { at, end: row.end };
                        }
                        Src::Doc(at)
                    }
                };
                let head = head_word(row.field, row.kind);
                match row.kind {
                    RecordKind::Varint => Arm::Varint {
                        head,
                        word: match source {
                            Src::Store(v) => self.store.varint(v),
                            Src::Doc(at) => self.scan_varint(row, at),
                        },
                    },
                    RecordKind::I32 => Arm::Bits32 {
                        head,
                        bits: match source {
                            Src::Store(v) => self.store.bits32(v),
                            Src::Doc(at) => self.scan_bits32(row, at),
                        },
                    },
                    RecordKind::I64 => Arm::Bits64 {
                        head,
                        bits: match source {
                            Src::Store(v) => self.store.bits64(v),
                            Src::Doc(at) => self.scan_bits64(row, at),
                        },
                    },
                    RecordKind::Len => match source {
                        Src::Store(value) => Arm::Body { head, value },
                        Src::Doc(at) => {
                            Arm::Spine { head, first: self.slot_first(row.slot()), at }
                        }
                    },
                }
            }

    };
    (@settle $cap:ident canonical, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// The save passes' verdict for one row, values resolved once.
            /// A dirty scanned row's offset is bound here and rides the
            /// source down to the byte readers.
            fn settle(&self, row: &Row) -> Arm {
                let source = match row.edit {
                    Edit::Deleted(_)
                    | Edit::InsertedDeleted(_)
                    | Edit::Moved { .. }
                    | Edit::SourceRecordDeleted
                    | Edit::SourcePayloadDeleted(_)
                    | Edit::SourceInsertedDeleted(_)
                    | Edit::ImportedDeleted(_) => return Arm::Skip,
                    // A live copy is dirt by state, so interior dirt is
                    // the layer count's question: clean interiors ride
                    // the whole cloned span verbatim (canonical
                    // admission proved the closure minimal).
                    Edit::SourceRecord => {
                        // SAFETY: clone-minted rows carry their source
                        // geometry.
                        let at = unsafe { scanned_at(row) };
                        return match row.slot() {
                            Slot::Opened(layer) if self.layer(layer).dirty_kids > 0 => Arm::Spine {
                                head: head_word(row.field, row.kind),
                                first: self.slot_first(row.slot()),
                                at,
                            },
                            Slot::Opened(_) | Slot::Unopened | Slot::Fault(_) => {
                                Arm::Clean { at, end: row.end }
                            }
                        };
                    }
                    // A designated payload prices and emits its subspan
                    // wholesale until an edit lands inside the descended
                    // interior; then it recurses like any edited subtree.
                    Edit::SourcePayload(src) | Edit::SourceInserted(src) => {
                        let (payload_at, len) = self.designated_payload(src);
                        return match row.slot() {
                            Slot::Opened(layer) if self.layer(layer).dirty_kids > 0 => Arm::Spine {
                                head: head_word(row.field, row.kind),
                                first: self.layer(layer).first,
                                // SAFETY: the designated subspan lies in
                                // the document zone, whose admitted end
                                // is inside the offset domain.
                                at: unsafe { At32::new_unchecked(payload_at) },
                            },
                            Slot::Opened(_) | Slot::Unopened | Slot::Fault(_) => Arm::BodyAlias {
                                head: head_word(row.field, row.kind),
                                at: payload_at,
                                len,
                            },
                        };
                    }
                    Edit::Imported(value) => return Arm::Import { value },
                    Edit::Replaced(value) | Edit::Inserted(value) => Src::Store(value),
                    Edit::Intact => {
                        // SAFETY: the Intact arm is outside the Inserted
                        // family.
                        let at = unsafe { scanned_at(row) };
                        if !row.dirty() {
                            return Arm::Clean { at, end: row.end };
                        }
                        Src::Doc(at)
                    }
                };
                let head = head_word(row.field, row.kind);
                match row.kind {
                    RecordKind::Varint => Arm::Varint {
                        head,
                        word: match source {
                            Src::Store(v) => self.store.varint(v),
                            Src::Doc(at) => self.scan_varint(row, at),
                        },
                    },
                    RecordKind::I32 => Arm::Bits32 {
                        head,
                        bits: match source {
                            Src::Store(v) => self.store.bits32(v),
                            Src::Doc(at) => self.scan_bits32(row, at),
                        },
                    },
                    RecordKind::I64 => Arm::Bits64 {
                        head,
                        bits: match source {
                            Src::Store(v) => self.store.bits64(v),
                            Src::Doc(at) => self.scan_bits64(row, at),
                        },
                    },
                    RecordKind::Len => match source {
                        Src::Store(value) => Arm::Body { head, value },
                        Src::Doc(at) => {
                            Arm::Spine { head, first: self.slot_first(row.slot()), at }
                        }
                    },
                }
            }

    };
    (@size_pass plain tolerant, prod: $prod:ident, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// The size pass: walks the visible tree once, accumulating
            /// every dirty LEN's rewritten body bottom-up and recording it
            /// in walk order for the emit pass.
            fn size_pass(&self) -> Result<(u32, Vec<u32>), SaveFault> {
                let mut bodies: Vec<u32> = Vec::new();
                let mut spine: Vec<SizeFrame> = Vec::new();
                let mut acc: u64 = 0;
                // Clean siblings tile their layer's source: a run costs one
                // discriminant-and-flag test per record and prices as a
                // single subtraction at its boundary.
                let mut run: Option<(u32, RowId)> = None;
                let mut cur = self.root.first;
                loop {
                    let Some(id) = cur else {
                        if let Some((from, last)) = run.take() {
                            acc += u64::from(self.row(last).end - from);
                        }
                        let Some(frame) = spine.pop() else { break };
                        let body = u32::try_from(acc)
                            .ok()
                            .and_then(PayloadLen::new)
                            .ok_or(SaveFault::BodyOverCap { at: frame.at })?;
                        let body = body.as_inner();
                        bodies[frame.slot] = body;
                        // The fidelity criterion: an unchanged body length
                        // keeps the source prefix, padding included.
                        // Authored spines carry no prefix and their
                        // sentinel `src_len` sits above the length class,
                        // so they always recompute.
                        let prefix = match (body == frame.src_len, frame.prefix_w) {
                            (true, Some(w)) => w.w(),
                            (true, None) | (false, _) => encoded_len32(body),
                        };
                        acc += frame.outer + u64::from(frame.tag_w.w()) + u64::from(prefix);
                        cur = frame.next;
                        continue;
                    };
                    let row = self.row(id);
                    if matches!(row.edit, Edit::Intact) && !row.dirty() {
                        // SAFETY: the Intact arm is outside the Inserted
                        // family.
                        let at = unsafe { scanned_at(row) };
                        match &mut run {
                            Some((_, last)) => *last = id,
                            None => run = Some((at.as_inner(), id)),
                        }
                        cur = row.next;
                        continue;
                    }
                    if let Some((from, last)) = run.take() {
                        acc += u64::from(self.row(last).end - from);
                    }
                    match self.settle(row) {
                        Arm::Skip => {}
                        // Clean rows join runs above; the arm stays for
                        // totality (settle is shared with the emit walk).
                        Arm::Clean { at, end } => acc += u64::from(end - at.as_inner()),
                        Arm::ReValue { tag_at, tag_end, value } => {
                            acc += u64::from(tag_end - tag_at) + u64::from(value.width());
                        }
                        Arm::NewValue { head, value } => {
                            acc += u64::from(encoded_len32(head)) + u64::from(value.width());
                        }
                        Arm::ReBody { tag_at, tag_end, prefix_end, src_len, value } => {
                            let (_, len) = self.store.span(value);
                            let prefix =
                                if len == src_len { prefix_end - tag_end } else { encoded_len32(len) };
                            acc += u64::from(tag_end - tag_at) + u64::from(prefix) + u64::from(len);
                        }
                        Arm::NewBody { head, value } => {
                            let (_, len) = self.store.span(value);
                            acc += u64::from(encoded_len32(head))
                                + u64::from(encoded_len32(len))
                                + u64::from(len);
                        }
                        Arm::Spine { tag_at, tag_end, prefix_end, src_len, first } => {
                            bodies.try_reserve(1).map_err(save_alloc)?;
                            spine.try_reserve(1).map_err(save_alloc)?;
                            let slot = bodies.len();
                            bodies.push(0);
                            let (tag_w, prefix_w) = match (row.tag_width, row.delim_width) {
                                (Some(tag_w), prefix_w @ Some(_)) => (tag_w, prefix_w),
                                // SAFETY: the settle frames only
                                // geometry-owning rows (scanned, or
                                // clones of them), whose birth stored
                                // both met width columns.
                                _ => unsafe { core::hint::unreachable_unchecked() },
                            };
                            debug_assert!(
                                tag_end - tag_at == tag_w.w()
                                    && prefix_w.is_some_and(|w| prefix_end - tag_end == w.w()),
                                "the settle's spine windows are the stored met widths"
                            );
                            spine.push(SizeFrame {
                                next: row.next,
                                outer: acc,
                                slot,
                                prefix_w,
                                src_len,
                                at: tag_at,
                                tag_w,
                            });
                            acc = 0;
                            cur = first;
                            continue;
                        }
                    }
                    cur = row.next;
                }
                let total = u32::try_from(acc)
                    .ok()
                    .filter(|total| $crate::revise::groupless::revising_machine!(@in_cap $prod, total))
                    .ok_or(SaveFault::DocOverCap { total: acc })?;
                Ok((total, bodies))
            }

    };
    (@size_pass transfer tolerant, prod: $prod:ident, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// The size pass: walks the visible tree once, accumulating
            /// every dirty LEN's rewritten body bottom-up and recording it
            /// in walk order for the emit pass.
            fn size_pass(&self) -> Result<(u32, Vec<u32>), SaveFault> {
                let mut bodies: Vec<u32> = Vec::new();
                let mut spine: Vec<SizeFrame> = Vec::new();
                let mut acc: u64 = 0;
                // Clean siblings tile their layer's source: a run costs one
                // discriminant-and-flag test per record and prices as a
                // single subtraction at its boundary.
                let mut run: Option<(u32, RowId)> = None;
                let mut cur = self.root.first;
                loop {
                    let Some(id) = cur else {
                        if let Some((from, last)) = run.take() {
                            acc += u64::from(self.row(last).end - from);
                        }
                        let Some(frame) = spine.pop() else { break };
                        let body = u32::try_from(acc)
                            .ok()
                            .and_then(PayloadLen::new)
                            .ok_or(SaveFault::BodyOverCap { at: frame.at })?;
                        let body = body.as_inner();
                        bodies[frame.slot] = body;
                        // The fidelity criterion: an unchanged body length
                        // keeps the source prefix, padding included.
                        // Authored spines carry no prefix and their
                        // sentinel `src_len` sits above the length class,
                        // so they always recompute.
                        let prefix = match (body == frame.src_len, frame.prefix_w) {
                            (true, Some(w)) => w.w(),
                            (true, None) | (false, _) => encoded_len32(body),
                        };
                        acc += frame.outer + u64::from(frame.tag_w.w()) + u64::from(prefix);
                        cur = frame.next;
                        continue;
                    };
                    let row = self.row(id);
                    if matches!(row.edit, Edit::Intact) && !row.dirty() {
                        // SAFETY: the Intact arm is outside the Inserted
                        // family.
                        let at = unsafe { scanned_at(row) };
                        match &mut run {
                            Some((_, last)) => *last = id,
                            None => run = Some((at.as_inner(), id)),
                        }
                        cur = row.next;
                        continue;
                    }
                    if let Some((from, last)) = run.take() {
                        acc += u64::from(self.row(last).end - from);
                    }
                    match self.settle(row) {
                        Arm::Skip => {}
                        // Clean rows join runs above; the arm stays for
                        // totality (settle is shared with the emit walk).
                        Arm::Clean { at, end } => acc += u64::from(end - at.as_inner()),
                        Arm::ReValue { tag_at, tag_end, value } => {
                            acc += u64::from(tag_end - tag_at) + u64::from(value.width());
                        }
                        Arm::NewValue { head, value } => {
                            acc += u64::from(encoded_len32(head)) + u64::from(value.width());
                        }
                        Arm::ReBody { tag_at, tag_end, prefix_end, src_len, value } => {
                            let (_, len) = self.store.span(value);
                            let prefix =
                                if len == src_len { prefix_end - tag_end } else { encoded_len32(len) };
                            acc += u64::from(tag_end - tag_at) + u64::from(prefix) + u64::from(len);
                        }
                        Arm::NewBody { head, value } => {
                            let (_, len) = self.store.span(value);
                            acc += u64::from(encoded_len32(head))
                                + u64::from(encoded_len32(len))
                                + u64::from(len);
                        }
                        Arm::ReBodyAlias { tag_at, tag_end, prefix_end, src_len, len, .. } => {
                            let prefix =
                                if len == src_len { prefix_end - tag_end } else { encoded_len32(len) };
                            acc += u64::from(tag_end - tag_at) + u64::from(prefix) + u64::from(len);
                        }
                        Arm::NewBodyAlias { head, len, .. } => {
                            acc += u64::from(encoded_len32(head))
                                + u64::from(encoded_len32(len))
                                + u64::from(len);
                        }
                        Arm::Import { value } => {
                            acc += u64::from(self.store.span(value).1);
                        }
                        Arm::Spine { tag_at, tag_end, prefix_end, src_len, first } => {
                            bodies.try_reserve(1).map_err(save_alloc)?;
                            spine.try_reserve(1).map_err(save_alloc)?;
                            let slot = bodies.len();
                            bodies.push(0);
                            let (tag_w, prefix_w) = match (row.tag_width, row.delim_width) {
                                (Some(tag_w), prefix_w @ Some(_)) => (tag_w, prefix_w),
                                // SAFETY: the settle frames only
                                // geometry-owning rows (scanned, or
                                // clones of them), whose birth stored
                                // both met width columns.
                                _ => unsafe { core::hint::unreachable_unchecked() },
                            };
                            debug_assert!(
                                tag_end - tag_at == tag_w.w()
                                    && prefix_w.is_some_and(|w| prefix_end - tag_end == w.w()),
                                "the settle's spine windows are the stored met widths"
                            );
                            spine.push(SizeFrame {
                                next: row.next,
                                outer: acc,
                                slot,
                                prefix_w,
                                src_len,
                                at: tag_at,
                                tag_w,
                            });
                            acc = 0;
                            cur = first;
                            continue;
                        }
                        // An import spine prices like a source spine: the
                        // zone tag and (when the body length holds) the
                        // met prefix ride verbatim, and the frame prices
                        // the walked interior bottom-up.
                        Arm::ImportSpine { tag_at, tag_end, prefix_end, src_len, first, .. } => {
                            bodies.try_reserve(1).map_err(save_alloc)?;
                            spine.try_reserve(1).map_err(save_alloc)?;
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
                                    Some(WordWidth::met_unchecked((prefix_end - tag_end) as u8)),
                                )
                            };
                            spine.push(SizeFrame {
                                next: row.next,
                                outer: acc,
                                slot,
                                prefix_w,
                                src_len,
                                at: tag_at,
                                tag_w,
                            });
                            acc = 0;
                            cur = first;
                            continue;
                        }
                        Arm::NewSpine { head, first } => {
                            bodies.try_reserve(1).map_err(save_alloc)?;
                            spine.try_reserve(1).map_err(save_alloc)?;
                            let slot = bodies.len();
                            bodies.push(0);
                            spine.push(SizeFrame {
                                next: row.next,
                                outer: acc,
                                slot,
                                // An authored head never rides a source
                                // prefix; MAX sits above the length cap,
                                // so the verbatim criterion cannot fire.
                                prefix_w: None,
                                src_len: u32::MAX,
                                at: 0,
                                tag_w: WordWidth::minimal_of(head),
                            });
                            acc = 0;
                            cur = first;
                            continue;
                        }
                    }
                    cur = row.next;
                }
                let total = u32::try_from(acc)
                    .ok()
                    .filter(|total| $crate::revise::groupless::revising_machine!(@in_cap $prod, total))
                    .ok_or(SaveFault::DocOverCap { total: acc })?;
                Ok((total, bodies))
            }

    };
    (@size_pass $cap:ident tolerant, prod: $prod:ident, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// The size pass: walks the visible tree once, accumulating
            /// every dirty LEN's rewritten body bottom-up and recording it
            /// in walk order for the emit pass.
            fn size_pass(&self) -> Result<(u32, Vec<u32>), SaveFault> {
                let mut bodies: Vec<u32> = Vec::new();
                let mut spine: Vec<SizeFrame> = Vec::new();
                let mut acc: u64 = 0;
                // Clean siblings tile their layer's source: a run costs one
                // discriminant-and-flag test per record and prices as a
                // single subtraction at its boundary.
                let mut run: Option<(u32, RowId)> = None;
                let mut cur = self.root.first;
                loop {
                    let Some(id) = cur else {
                        if let Some((from, last)) = run.take() {
                            acc += u64::from(self.row(last).end - from);
                        }
                        let Some(frame) = spine.pop() else { break };
                        let body = u32::try_from(acc)
                            .ok()
                            .and_then(PayloadLen::new)
                            .ok_or(SaveFault::BodyOverCap { at: frame.at })?;
                        let body = body.as_inner();
                        bodies[frame.slot] = body;
                        // The fidelity criterion: an unchanged body length
                        // keeps the source prefix, padding included.
                        // Authored spines carry no prefix and their
                        // sentinel `src_len` sits above the length class,
                        // so they always recompute.
                        let prefix = match (body == frame.src_len, frame.prefix_w) {
                            (true, Some(w)) => w.w(),
                            (true, None) | (false, _) => encoded_len32(body),
                        };
                        acc += frame.outer + u64::from(frame.tag_w.w()) + u64::from(prefix);
                        cur = frame.next;
                        continue;
                    };
                    let row = self.row(id);
                    if matches!(row.edit, Edit::Intact) && !row.dirty() {
                        // SAFETY: the Intact arm is outside the Inserted
                        // family.
                        let at = unsafe { scanned_at(row) };
                        match &mut run {
                            Some((_, last)) => *last = id,
                            None => run = Some((at.as_inner(), id)),
                        }
                        cur = row.next;
                        continue;
                    }
                    if let Some((from, last)) = run.take() {
                        acc += u64::from(self.row(last).end - from);
                    }
                    match self.settle(row) {
                        Arm::Skip => {}
                        // Clean rows join runs above; the arm stays for
                        // totality (settle is shared with the emit walk).
                        Arm::Clean { at, end } => acc += u64::from(end - at.as_inner()),
                        Arm::ReValue { tag_at, tag_end, value } => {
                            acc += u64::from(tag_end - tag_at) + u64::from(value.width());
                        }
                        Arm::NewValue { head, value } => {
                            acc += u64::from(encoded_len32(head)) + u64::from(value.width());
                        }
                        Arm::ReBody { tag_at, tag_end, prefix_end, src_len, value } => {
                            let (_, len) = self.store.span(value);
                            let prefix =
                                if len == src_len { prefix_end - tag_end } else { encoded_len32(len) };
                            acc += u64::from(tag_end - tag_at) + u64::from(prefix) + u64::from(len);
                        }
                        Arm::NewBody { head, value } => {
                            let (_, len) = self.store.span(value);
                            acc += u64::from(encoded_len32(head))
                                + u64::from(encoded_len32(len))
                                + u64::from(len);
                        }
                        Arm::ReBodyAlias { tag_at, tag_end, prefix_end, src_len, len, .. } => {
                            let prefix =
                                if len == src_len { prefix_end - tag_end } else { encoded_len32(len) };
                            acc += u64::from(tag_end - tag_at) + u64::from(prefix) + u64::from(len);
                        }
                        Arm::NewBodyAlias { head, len, .. } => {
                            acc += u64::from(encoded_len32(head))
                                + u64::from(encoded_len32(len))
                                + u64::from(len);
                        }
                        Arm::Import { value } => {
                            acc += u64::from(self.store.span(value).1);
                        }
                        Arm::Spine { tag_at, tag_end, prefix_end, src_len, first } => {
                            bodies.try_reserve(1).map_err(save_alloc)?;
                            spine.try_reserve(1).map_err(save_alloc)?;
                            let slot = bodies.len();
                            bodies.push(0);
                            let (tag_w, prefix_w) = match (row.tag_width, row.delim_width) {
                                (Some(tag_w), prefix_w @ Some(_)) => (tag_w, prefix_w),
                                // SAFETY: the settle frames only
                                // geometry-owning rows (scanned, or
                                // clones of them), whose birth stored
                                // both met width columns.
                                _ => unsafe { core::hint::unreachable_unchecked() },
                            };
                            debug_assert!(
                                tag_end - tag_at == tag_w.w()
                                    && prefix_w.is_some_and(|w| prefix_end - tag_end == w.w()),
                                "the settle's spine windows are the stored met widths"
                            );
                            spine.push(SizeFrame {
                                next: row.next,
                                outer: acc,
                                slot,
                                prefix_w,
                                src_len,
                                at: tag_at,
                                tag_w,
                            });
                            acc = 0;
                            cur = first;
                            continue;
                        }
                        Arm::NewSpine { head, first } => {
                            bodies.try_reserve(1).map_err(save_alloc)?;
                            spine.try_reserve(1).map_err(save_alloc)?;
                            let slot = bodies.len();
                            bodies.push(0);
                            spine.push(SizeFrame {
                                next: row.next,
                                outer: acc,
                                slot,
                                // An authored head never rides a source
                                // prefix; MAX sits above the length cap,
                                // so the verbatim criterion cannot fire.
                                prefix_w: None,
                                src_len: u32::MAX,
                                at: 0,
                                tag_w: WordWidth::minimal_of(head),
                            });
                            acc = 0;
                            cur = first;
                            continue;
                        }
                    }
                    cur = row.next;
                }
                let total = u32::try_from(acc)
                    .ok()
                    .filter(|total| $crate::revise::groupless::revising_machine!(@in_cap $prod, total))
                    .ok_or(SaveFault::DocOverCap { total: acc })?;
                Ok((total, bodies))
            }

    };
    (@size_pass plain canonical, prod: $prod:ident, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// The size pass: walks the visible tree once, accumulating
            /// every dirty LEN's rewritten body bottom-up and recording it
            /// in walk order for the emit pass.
            fn size_pass(&self) -> Result<(u32, Vec<u32>), SaveFault> {
                let mut bodies: Vec<u32> = Vec::new();
                let mut spine: Vec<SizeFrame> = Vec::new();
                let mut acc: u64 = 0;
                // Clean siblings tile their layer's source: a run costs one
                // discriminant-and-flag test per record and prices as a
                // single subtraction at its boundary.
                let mut run: Option<(u32, RowId)> = None;
                let mut cur = self.root.first;
                loop {
                    let Some(id) = cur else {
                        if let Some((from, last)) = run.take() {
                            acc += u64::from(self.row(last).end - from);
                        }
                        let Some(frame) = spine.pop() else { break };
                        let body = u32::try_from(acc)
                            .ok()
                            .and_then(PayloadLen::new)
                            .ok_or(SaveFault::BodyOverCap { at: frame.at.as_inner() })?;
                        bodies[frame.slot] = body.as_inner();
                        acc += frame.outer
                            + u64::from(encoded_len32(frame.head))
                            + u64::from(encoded_len32(body.as_inner()));
                        cur = frame.next;
                        continue;
                    };
                    let row = self.row(id);
                    if matches!(row.edit, Edit::Intact) && !row.dirty() {
                        // SAFETY: the Intact arm is outside the Inserted
                        // family.
                        let at = unsafe { scanned_at(row) };
                        match &mut run {
                            Some((_, last)) => *last = id,
                            None => run = Some((at.as_inner(), id)),
                        }
                        cur = row.next;
                        continue;
                    }
                    if let Some((from, last)) = run.take() {
                        acc += u64::from(self.row(last).end - from);
                    }
                    match self.settle(row) {
                        Arm::Skip => {}
                        // Clean rows join runs above; the arm stays for
                        // totality (settle is shared with the emit walk).
                        Arm::Clean { at, end } => acc += u64::from(end - at.as_inner()),
                        Arm::Varint { head, word } => {
                            acc += u64::from(encoded_len32(head)) + u64::from(encoded_len64(word));
                        }
                        Arm::Bits32 { head, .. } => acc += u64::from(encoded_len32(head)) + 4,
                        Arm::Bits64 { head, .. } => acc += u64::from(encoded_len32(head)) + 8,
                        Arm::Body { head, value } => {
                            let (_, len) = self.store.span(value);
                            acc += u64::from(encoded_len32(head))
                                + u64::from(encoded_len32(len))
                                + u64::from(len);
                        }
                        Arm::Spine { head, first, at } => {
                            bodies.try_reserve(1).map_err(save_alloc)?;
                            spine.try_reserve(1).map_err(save_alloc)?;
                            let slot = bodies.len();
                            bodies.push(0);
                            spine.push(SizeFrame { next: row.next, outer: acc, head, slot, at });
                            acc = 0;
                            cur = first;
                            continue;
                        }
                    }
                    cur = row.next;
                }
                let total = u32::try_from(acc)
                    .ok()
                    .filter(|total| $crate::revise::groupless::revising_machine!(@in_cap $prod, total))
                    .ok_or(SaveFault::DocOverCap { total: acc })?;
                Ok((total, bodies))
            }

    };
    (@size_pass transfer canonical, prod: $prod:ident, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// The size pass: walks the visible tree once, accumulating
            /// every dirty LEN's rewritten body bottom-up and recording it
            /// in walk order for the emit pass.
            fn size_pass(&self) -> Result<(u32, Vec<u32>), SaveFault> {
                let mut bodies: Vec<u32> = Vec::new();
                let mut spine: Vec<SizeFrame> = Vec::new();
                let mut acc: u64 = 0;
                // Clean siblings tile their layer's source: a run costs one
                // discriminant-and-flag test per record and prices as a
                // single subtraction at its boundary.
                let mut run: Option<(u32, RowId)> = None;
                let mut cur = self.root.first;
                loop {
                    let Some(id) = cur else {
                        if let Some((from, last)) = run.take() {
                            acc += u64::from(self.row(last).end - from);
                        }
                        let Some(frame) = spine.pop() else { break };
                        let body = u32::try_from(acc)
                            .ok()
                            .and_then(PayloadLen::new)
                            .ok_or(SaveFault::BodyOverCap { at: frame.at.as_inner() })?;
                        bodies[frame.slot] = body.as_inner();
                        acc += frame.outer
                            + u64::from(encoded_len32(frame.head))
                            + u64::from(encoded_len32(body.as_inner()));
                        cur = frame.next;
                        continue;
                    };
                    let row = self.row(id);
                    if matches!(row.edit, Edit::Intact) && !row.dirty() {
                        // SAFETY: the Intact arm is outside the Inserted
                        // family.
                        let at = unsafe { scanned_at(row) };
                        match &mut run {
                            Some((_, last)) => *last = id,
                            None => run = Some((at.as_inner(), id)),
                        }
                        cur = row.next;
                        continue;
                    }
                    if let Some((from, last)) = run.take() {
                        acc += u64::from(self.row(last).end - from);
                    }
                    match self.settle(row) {
                        Arm::Skip => {}
                        // Clean rows join runs above; the arm stays for
                        // totality (settle is shared with the emit walk).
                        Arm::Clean { at, end } => acc += u64::from(end - at.as_inner()),
                        Arm::Varint { head, word } => {
                            acc += u64::from(encoded_len32(head)) + u64::from(encoded_len64(word));
                        }
                        Arm::Bits32 { head, .. } => acc += u64::from(encoded_len32(head)) + 4,
                        Arm::Bits64 { head, .. } => acc += u64::from(encoded_len32(head)) + 8,
                        Arm::Body { head, value } => {
                            let (_, len) = self.store.span(value);
                            acc += u64::from(encoded_len32(head))
                                + u64::from(encoded_len32(len))
                                + u64::from(len);
                        }
                        Arm::BodyAlias { head, len, .. } => {
                            acc += u64::from(encoded_len32(head))
                                + u64::from(encoded_len32(len))
                                + u64::from(len);
                        }
                        Arm::Import { value } => {
                            acc += u64::from(self.store.span(value).1);
                        }
                        Arm::Spine { head, first, at } => {
                            bodies.try_reserve(1).map_err(save_alloc)?;
                            spine.try_reserve(1).map_err(save_alloc)?;
                            let slot = bodies.len();
                            bodies.push(0);
                            spine.push(SizeFrame { next: row.next, outer: acc, head, slot, at });
                            acc = 0;
                            cur = first;
                            continue;
                        }
                    }
                    cur = row.next;
                }
                let total = u32::try_from(acc)
                    .ok()
                    .filter(|total| $crate::revise::groupless::revising_machine!(@in_cap $prod, total))
                    .ok_or(SaveFault::DocOverCap { total: acc })?;
                Ok((total, bodies))
            }

    };
    (@size_pass $cap:ident canonical, prod: $prod:ident, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// The size pass: walks the visible tree once, accumulating
            /// every dirty LEN's rewritten body bottom-up and recording it
            /// in walk order for the emit pass.
            fn size_pass(&self) -> Result<(u32, Vec<u32>), SaveFault> {
                let mut bodies: Vec<u32> = Vec::new();
                let mut spine: Vec<SizeFrame> = Vec::new();
                let mut acc: u64 = 0;
                // Clean siblings tile their layer's source: a run costs one
                // discriminant-and-flag test per record and prices as a
                // single subtraction at its boundary.
                let mut run: Option<(u32, RowId)> = None;
                let mut cur = self.root.first;
                loop {
                    let Some(id) = cur else {
                        if let Some((from, last)) = run.take() {
                            acc += u64::from(self.row(last).end - from);
                        }
                        let Some(frame) = spine.pop() else { break };
                        let body = u32::try_from(acc)
                            .ok()
                            .and_then(PayloadLen::new)
                            .ok_or(SaveFault::BodyOverCap { at: frame.at.as_inner() })?;
                        bodies[frame.slot] = body.as_inner();
                        acc += frame.outer
                            + u64::from(encoded_len32(frame.head))
                            + u64::from(encoded_len32(body.as_inner()));
                        cur = frame.next;
                        continue;
                    };
                    let row = self.row(id);
                    if matches!(row.edit, Edit::Intact) && !row.dirty() {
                        // SAFETY: the Intact arm is outside the Inserted
                        // family.
                        let at = unsafe { scanned_at(row) };
                        match &mut run {
                            Some((_, last)) => *last = id,
                            None => run = Some((at.as_inner(), id)),
                        }
                        cur = row.next;
                        continue;
                    }
                    if let Some((from, last)) = run.take() {
                        acc += u64::from(self.row(last).end - from);
                    }
                    match self.settle(row) {
                        Arm::Skip => {}
                        // Clean rows join runs above; the arm stays for
                        // totality (settle is shared with the emit walk).
                        Arm::Clean { at, end } => acc += u64::from(end - at.as_inner()),
                        Arm::Varint { head, word } => {
                            acc += u64::from(encoded_len32(head)) + u64::from(encoded_len64(word));
                        }
                        Arm::Bits32 { head, .. } => acc += u64::from(encoded_len32(head)) + 4,
                        Arm::Bits64 { head, .. } => acc += u64::from(encoded_len32(head)) + 8,
                        Arm::Body { head, value } => {
                            let (_, len) = self.store.span(value);
                            acc += u64::from(encoded_len32(head))
                                + u64::from(encoded_len32(len))
                                + u64::from(len);
                        }
                        Arm::BodyAlias { head, len, .. } => {
                            acc += u64::from(encoded_len32(head))
                                + u64::from(encoded_len32(len))
                                + u64::from(len);
                        }
                        Arm::Import { value } => {
                            acc += u64::from(self.store.span(value).1);
                        }
                        Arm::Spine { head, first, at } => {
                            bodies.try_reserve(1).map_err(save_alloc)?;
                            spine.try_reserve(1).map_err(save_alloc)?;
                            let slot = bodies.len();
                            bodies.push(0);
                            spine.push(SizeFrame { next: row.next, outer: acc, head, slot, at });
                            acc = 0;
                            cur = first;
                            continue;
                        }
                    }
                    cur = row.next;
                }
                let total = u32::try_from(acc)
                    .ok()
                    .filter(|total| $crate::revise::groupless::revising_machine!(@in_cap $prod, total))
                    .ok_or(SaveFault::DocOverCap { total: acc })?;
                Ok((total, bodies))
            }

    };
    (@in_cap vec, $total:ident) => {
        admit(usize_of(*$total)).is_some()
    };
    (@in_cap carrier, $total:ident) => {
        *$total <= DocBytes::CAP
    };
    (@emit_pass plain tolerant, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// The emit pass: the same walk forward, writing into the
            /// prepaid output. Climbing out of containers follows parent
            /// links — the spine is the arena itself.
            fn emit_pass<O: Out>(&self, emit: &mut O, bodies: &[u32]) {
                let mut body_cursor = 0;
                let mut open: Option<RowId> = None;
                // Clean siblings tile their layer's source: a run costs one
                // discriminant-and-flag test per record and prices as a
                // single subtraction at its boundary.
                let mut run: Option<(u32, RowId)> = None;
                let mut cur = self.root.first;
                loop {
                    let Some(id) = cur else {
                        if let Some((from, last)) = run.take() {
                            emit.verbatim(from, self.row(last).end);
                        }
                        let Some(container) = open else { break };
                        let row = self.row(container);
                        cur = row.next;
                        open = row.parent;
                        continue;
                    };
                    let row = self.row(id);
                    if matches!(row.edit, Edit::Intact) && !row.dirty() {
                        // SAFETY: the Intact arm is outside the Inserted
                        // family.
                        let at = unsafe { scanned_at(row) };
                        match &mut run {
                            Some((_, last)) => *last = id,
                            None => run = Some((at.as_inner(), id)),
                        }
                        cur = row.next;
                        continue;
                    }
                    if let Some((from, last)) = run.take() {
                        emit.verbatim(from, self.row(last).end);
                    }
                    match self.settle(row) {
                        Arm::Skip => {}
                        // Clean rows join runs above; the arm stays for
                        // totality (settle is shared with the size walk).
                        Arm::Clean { at, end } => emit.verbatim(at.as_inner(), end),
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
                            let (_, len) = self.store.span(value);
                            if len == src_len {
                                emit.verbatim(tag_end, prefix_end);
                            } else {
                                emit.varint(u64::from(len));
                            }
                            emit.bytes(self.store.span_bytes(value));
                        }
                        Arm::NewBody { head, value } => {
                            let (_, len) = self.store.span(value);
                            emit.word(head);
                            emit.varint(u64::from(len));
                            emit.bytes(self.store.span_bytes(value));
                        }
                        Arm::Spine { tag_at, tag_end, prefix_end, src_len, first } => {
                            emit.verbatim(tag_at, tag_end);
                            let body = bodies[body_cursor];
                            body_cursor += 1;
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
                    cur = row.next;
                }
                emit.flush();
            }

    };
    (@emit_pass transfer tolerant, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// The emit pass: the same walk forward, writing into the
            /// prepaid output. Climbing out of containers follows parent
            /// links — the spine is the arena itself.
            fn emit_pass<'s, O: Out<'s>>(&'s self, emit: &mut O, bodies: &[u32]) {
                let mut body_cursor = 0;
                let mut open: Option<RowId> = None;
                // Clean siblings tile their layer's source: a run costs one
                // discriminant-and-flag test per record and prices as a
                // single subtraction at its boundary.
                let mut run: Option<(u32, RowId)> = None;
                let mut cur = self.root.first;
                loop {
                    let Some(id) = cur else {
                        if let Some((from, last)) = run.take() {
                            let last = self.row(last);
                            emit.verbatim_in(self.backing(last), from, last.end);
                        }
                        let Some(container) = open else { break };
                        let row = self.row(container);
                        cur = row.next;
                        open = row.parent;
                        continue;
                    };
                    let row = self.row(id);
                    if matches!(row.edit, Edit::Intact) && !row.dirty() {
                        // SAFETY: the Intact arm is outside the Inserted
                        // family.
                        let at = unsafe { scanned_at(row) };
                        match &mut run {
                            Some((_, last)) => *last = id,
                            None => run = Some((at.as_inner(), id)),
                        }
                        cur = row.next;
                        continue;
                    }
                    if let Some((from, last)) = run.take() {
                        let last = self.row(last);
                        emit.verbatim_in(self.backing(last), from, last.end);
                    }
                    match self.settle(row) {
                        Arm::Skip => {}
                        // Clean rows join runs above; the arm stays for
                        // totality (settle is shared with the size walk).
                        Arm::Clean { at, end } => {
                            emit.verbatim_in(self.backing(row), at.as_inner(), end);
                        }
                        Arm::ReValue { tag_at, tag_end, value } => {
                            emit.verbatim_in(self.backing(row), tag_at, tag_end);
                            emit.value(value);
                        }
                        Arm::NewValue { head, value } => {
                            emit.word(head);
                            emit.value(value);
                        }
                        Arm::ReBody { tag_at, tag_end, prefix_end, src_len, value } => {
                            let zone = self.backing(row);
                            emit.verbatim_in(zone, tag_at, tag_end);
                            let (_, len) = self.store.span(value);
                            if len == src_len {
                                emit.verbatim_in(zone, tag_end, prefix_end);
                            } else {
                                emit.varint(u64::from(len));
                            }
                            emit.bytes(self.store.span_bytes(value));
                        }
                        Arm::NewBody { head, value } => {
                            let (_, len) = self.store.span(value);
                            emit.word(head);
                            emit.varint(u64::from(len));
                            emit.bytes(self.store.span_bytes(value));
                        }
                        Arm::ReBodyAlias { tag_at, tag_end, prefix_end, src_len, at, len } => {
                            let zone = self.backing(row);
                            emit.verbatim_in(zone, tag_at, tag_end);
                            if len == src_len {
                                emit.verbatim_in(zone, tag_end, prefix_end);
                            } else {
                                emit.varint(u64::from(len));
                            }
                            emit.verbatim(at, at + len);
                        }
                        Arm::NewBodyAlias { head, at, len } => {
                            emit.word(head);
                            emit.varint(u64::from(len));
                            emit.verbatim(at, at + len);
                        }
                        Arm::Import { value } => {
                            emit.bytes(self.store.span_bytes(value));
                        }
                        Arm::Spine { tag_at, tag_end, prefix_end, src_len, first } => {
                            let zone = self.backing(row);
                            emit.verbatim_in(zone, tag_at, tag_end);
                            let body = bodies[body_cursor];
                            body_cursor += 1;
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
                            let (zone, _) = self.import_zone(value);
                            emit.verbatim_in(zone, tag_at, tag_end);
                            let body = bodies[body_cursor];
                            body_cursor += 1;
                            if body == src_len {
                                emit.verbatim_in(zone, tag_end, prefix_end);
                            } else {
                                emit.varint(u64::from(body));
                            }
                            open = Some(id);
                            cur = first;
                            continue;
                        }
                        Arm::NewSpine { head, first } => {
                            emit.word(head);
                            let body = bodies[body_cursor];
                            body_cursor += 1;
                            emit.varint(u64::from(body));
                            open = Some(id);
                            cur = first;
                            continue;
                        }
                    }
                    cur = row.next;
                }
                emit.flush();
            }

    };
    (@emit_pass $cap:ident tolerant, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// The emit pass: the same walk forward, writing into the
            /// prepaid output. Climbing out of containers follows parent
            /// links — the spine is the arena itself.
            fn emit_pass<O: Out>(&self, emit: &mut O, bodies: &[u32]) {
                let mut body_cursor = 0;
                let mut open: Option<RowId> = None;
                // Clean siblings tile their layer's source: a run costs one
                // discriminant-and-flag test per record and prices as a
                // single subtraction at its boundary.
                let mut run: Option<(u32, RowId)> = None;
                let mut cur = self.root.first;
                loop {
                    let Some(id) = cur else {
                        if let Some((from, last)) = run.take() {
                            emit.verbatim(from, self.row(last).end);
                        }
                        let Some(container) = open else { break };
                        let row = self.row(container);
                        cur = row.next;
                        open = row.parent;
                        continue;
                    };
                    let row = self.row(id);
                    if matches!(row.edit, Edit::Intact) && !row.dirty() {
                        // SAFETY: the Intact arm is outside the Inserted
                        // family.
                        let at = unsafe { scanned_at(row) };
                        match &mut run {
                            Some((_, last)) => *last = id,
                            None => run = Some((at.as_inner(), id)),
                        }
                        cur = row.next;
                        continue;
                    }
                    if let Some((from, last)) = run.take() {
                        emit.verbatim(from, self.row(last).end);
                    }
                    match self.settle(row) {
                        Arm::Skip => {}
                        // Clean rows join runs above; the arm stays for
                        // totality (settle is shared with the size walk).
                        Arm::Clean { at, end } => emit.verbatim(at.as_inner(), end),
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
                            let (_, len) = self.store.span(value);
                            if len == src_len {
                                emit.verbatim(tag_end, prefix_end);
                            } else {
                                emit.varint(u64::from(len));
                            }
                            emit.bytes(self.store.span_bytes(value));
                        }
                        Arm::NewBody { head, value } => {
                            let (_, len) = self.store.span(value);
                            emit.word(head);
                            emit.varint(u64::from(len));
                            emit.bytes(self.store.span_bytes(value));
                        }
                        Arm::ReBodyAlias { tag_at, tag_end, prefix_end, src_len, at, len } => {
                            emit.verbatim(tag_at, tag_end);
                            if len == src_len {
                                emit.verbatim(tag_end, prefix_end);
                            } else {
                                emit.varint(u64::from(len));
                            }
                            emit.verbatim(at, at + len);
                        }
                        Arm::NewBodyAlias { head, at, len } => {
                            emit.word(head);
                            emit.varint(u64::from(len));
                            emit.verbatim(at, at + len);
                        }
                        Arm::Import { value } => {
                            emit.bytes(self.store.span_bytes(value));
                        }
                        Arm::Spine { tag_at, tag_end, prefix_end, src_len, first } => {
                            emit.verbatim(tag_at, tag_end);
                            let body = bodies[body_cursor];
                            body_cursor += 1;
                            if body == src_len {
                                emit.verbatim(tag_end, prefix_end);
                            } else {
                                emit.varint(u64::from(body));
                            }
                            open = Some(id);
                            cur = first;
                            continue;
                        }
                        Arm::NewSpine { head, first } => {
                            emit.word(head);
                            let body = bodies[body_cursor];
                            body_cursor += 1;
                            emit.varint(u64::from(body));
                            open = Some(id);
                            cur = first;
                            continue;
                        }
                    }
                    cur = row.next;
                }
                emit.flush();
            }

    };
    (@emit_pass plain canonical, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// The emit pass: the same walk forward, writing into the
            /// prepaid output. Climbing out of containers follows parent
            /// links — the spine is the arena itself.
            fn emit_pass<O: Out>(&self, emit: &mut O, bodies: &[u32]) {
                let mut body_cursor = 0;
                let mut open: Option<RowId> = None;
                // Clean siblings tile their layer's source: a run costs one
                // discriminant-and-flag test per record and prices as a
                // single subtraction at its boundary.
                let mut run: Option<(u32, RowId)> = None;
                let mut cur = self.root.first;
                loop {
                    let Some(id) = cur else {
                        if let Some((from, last)) = run.take() {
                            emit.verbatim(from, self.row(last).end);
                        }
                        let Some(container) = open else { break };
                        let row = self.row(container);
                        cur = row.next;
                        open = row.parent;
                        continue;
                    };
                    let row = self.row(id);
                    if matches!(row.edit, Edit::Intact) && !row.dirty() {
                        // SAFETY: the Intact arm is outside the Inserted
                        // family.
                        let at = unsafe { scanned_at(row) };
                        match &mut run {
                            Some((_, last)) => *last = id,
                            None => run = Some((at.as_inner(), id)),
                        }
                        cur = row.next;
                        continue;
                    }
                    if let Some((from, last)) = run.take() {
                        emit.verbatim(from, self.row(last).end);
                    }
                    match self.settle(row) {
                        Arm::Skip => {}
                        // Clean rows join runs above; the arm stays for
                        // totality (settle is shared with the size walk).
                        Arm::Clean { at, end } => emit.verbatim(at.as_inner(), end),
                        Arm::Varint { head, word } => {
                            emit.word(head);
                            emit.varint(word);
                        }
                        Arm::Bits32 { head, bits } => {
                            emit.word(head);
                            emit.bits32(bits);
                        }
                        Arm::Bits64 { head, bits } => {
                            emit.word(head);
                            emit.bits64(bits);
                        }
                        Arm::Body { head, value } => {
                            let (_, len) = self.store.span(value);
                            emit.word(head);
                            emit.varint(u64::from(len));
                            emit.bytes(self.store.span_bytes(value));
                        }
                        Arm::Spine { head, first, .. } => {
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
            }

    };
    (@emit_pass transfer canonical, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// The emit pass: the same walk forward, writing into the
            /// prepaid output. Climbing out of containers follows parent
            /// links — the spine is the arena itself.
            fn emit_pass<'s, O: Out<'s>>(&'s self, emit: &mut O, bodies: &[u32]) {
                let mut body_cursor = 0;
                let mut open: Option<RowId> = None;
                // Clean siblings tile their layer's source: a run costs one
                // discriminant-and-flag test per record and prices as a
                // single subtraction at its boundary.
                let mut run: Option<(u32, RowId)> = None;
                let mut cur = self.root.first;
                loop {
                    let Some(id) = cur else {
                        if let Some((from, last)) = run.take() {
                            let last = self.row(last);
                            emit.verbatim_in(self.backing(last), from, last.end);
                        }
                        let Some(container) = open else { break };
                        let row = self.row(container);
                        cur = row.next;
                        open = row.parent;
                        continue;
                    };
                    let row = self.row(id);
                    if matches!(row.edit, Edit::Intact) && !row.dirty() {
                        // SAFETY: the Intact arm is outside the Inserted
                        // family.
                        let at = unsafe { scanned_at(row) };
                        match &mut run {
                            Some((_, last)) => *last = id,
                            None => run = Some((at.as_inner(), id)),
                        }
                        cur = row.next;
                        continue;
                    }
                    if let Some((from, last)) = run.take() {
                        let last = self.row(last);
                        emit.verbatim_in(self.backing(last), from, last.end);
                    }
                    match self.settle(row) {
                        Arm::Skip => {}
                        // Clean rows join runs above; the arm stays for
                        // totality (settle is shared with the size walk).
                        Arm::Clean { at, end } => {
                            emit.verbatim_in(self.backing(row), at.as_inner(), end);
                        }
                        Arm::Varint { head, word } => {
                            emit.word(head);
                            emit.varint(word);
                        }
                        Arm::Bits32 { head, bits } => {
                            emit.word(head);
                            emit.bits32(bits);
                        }
                        Arm::Bits64 { head, bits } => {
                            emit.word(head);
                            emit.bits64(bits);
                        }
                        Arm::Body { head, value } => {
                            let (_, len) = self.store.span(value);
                            emit.word(head);
                            emit.varint(u64::from(len));
                            emit.bytes(self.store.span_bytes(value));
                        }
                        Arm::BodyAlias { head, at, len } => {
                            emit.word(head);
                            emit.varint(u64::from(len));
                            emit.verbatim(at, at + len);
                        }
                        Arm::Import { value } => {
                            emit.bytes(self.store.span_bytes(value));
                        }
                        Arm::Spine { head, first, .. } => {
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
            }

    };
    (@emit_pass $cap:ident canonical, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// The emit pass: the same walk forward, writing into the
            /// prepaid output. Climbing out of containers follows parent
            /// links — the spine is the arena itself.
            fn emit_pass<O: Out>(&self, emit: &mut O, bodies: &[u32]) {
                let mut body_cursor = 0;
                let mut open: Option<RowId> = None;
                // Clean siblings tile their layer's source: a run costs one
                // discriminant-and-flag test per record and prices as a
                // single subtraction at its boundary.
                let mut run: Option<(u32, RowId)> = None;
                let mut cur = self.root.first;
                loop {
                    let Some(id) = cur else {
                        if let Some((from, last)) = run.take() {
                            emit.verbatim(from, self.row(last).end);
                        }
                        let Some(container) = open else { break };
                        let row = self.row(container);
                        cur = row.next;
                        open = row.parent;
                        continue;
                    };
                    let row = self.row(id);
                    if matches!(row.edit, Edit::Intact) && !row.dirty() {
                        // SAFETY: the Intact arm is outside the Inserted
                        // family.
                        let at = unsafe { scanned_at(row) };
                        match &mut run {
                            Some((_, last)) => *last = id,
                            None => run = Some((at.as_inner(), id)),
                        }
                        cur = row.next;
                        continue;
                    }
                    if let Some((from, last)) = run.take() {
                        emit.verbatim(from, self.row(last).end);
                    }
                    match self.settle(row) {
                        Arm::Skip => {}
                        // Clean rows join runs above; the arm stays for
                        // totality (settle is shared with the size walk).
                        Arm::Clean { at, end } => emit.verbatim(at.as_inner(), end),
                        Arm::Varint { head, word } => {
                            emit.word(head);
                            emit.varint(word);
                        }
                        Arm::Bits32 { head, bits } => {
                            emit.word(head);
                            emit.bits32(bits);
                        }
                        Arm::Bits64 { head, bits } => {
                            emit.word(head);
                            emit.bits64(bits);
                        }
                        Arm::Body { head, value } => {
                            let (_, len) = self.store.span(value);
                            emit.word(head);
                            emit.varint(u64::from(len));
                            emit.bytes(self.store.span_bytes(value));
                        }
                        Arm::BodyAlias { head, at, len } => {
                            emit.word(head);
                            emit.varint(u64::from(len));
                            emit.verbatim(at, at + len);
                        }
                        Arm::Import { value } => {
                            emit.bytes(self.store.span_bytes(value));
                        }
                        Arm::Spine { head, first, .. } => {
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
            }

    };
    (@save stream vec, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            #[doc = concat!(" Serializes the ", $noun, "'s current state into a fresh `Vec<u8>`")]
            /// — output any buffered opener (or another ingest) takes
            /// whole.
            ///
            #[doc = concat!(" A clean ", $noun, " (no dirt anywhere — ghosts included) copies")]
            /// the source verbatim, padding included. Otherwise two passes
            /// run: sizes bottom-up, then one forward emit into an
            /// exactly-reserved output — untouched subtrees copy bit-true,
            /// shrouded records prune, replaced records keep their source
            /// tags verbatim, LEN prefixes ride verbatim while their body
            /// length is unchanged, and command-authored records emit
            /// minimally.
            ///
            /// # Errors
            ///
            /// [`SaveFault::Resource`] on any allocator refusal,
            /// [`SaveFault::BodyOverCap`] when a rewritten LEN body
            /// outgrows the length class, [`SaveFault::DocOverCap`] when
            /// the document outgrows the coordinate class. On `Err` the
            #[doc = concat!(" ", $noun, " is unchanged and the save may be retried.")]
            ///
            /// # Panics
            ///
            /// If the crate's own sizing and emission passes disagree — a
            /// library bug caught at the seam.
            #[inline]
            pub fn save(&self) -> Result<Vec<u8>, SaveFault> {
                let mut out = Vec::new();
                self.save_into(&mut out)?;
                Ok(out)
            }

    };
    (@save $save_src:ident vec, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            #[doc = concat!(" Serializes the ", $noun, "'s current state into a fresh `Vec<u8>`")]
            #[doc = concat!(" — output that re-opens through [`", stringify!($Machine), "::open`]'s move door,")]
            #[doc = concat!(" so ", $noun, "s chain.")]
            ///
            #[doc = concat!(" A clean ", $noun, " (no dirt anywhere — ghosts included) copies")]
            /// the source verbatim, padding included. Otherwise two passes
            /// run: sizes bottom-up, then one forward emit into an
            /// exactly-reserved output — untouched subtrees copy bit-true,
            /// shrouded records prune, replaced records keep their source
            /// tags verbatim, LEN prefixes ride verbatim while their body
            /// length is unchanged, and command-authored records emit
            /// minimally.
            ///
            /// # Errors
            ///
            /// [`SaveFault::Resource`] on any allocator refusal,
            /// [`SaveFault::BodyOverCap`] when a rewritten LEN body
            /// outgrows the length class, [`SaveFault::DocOverCap`] when
            /// the document outgrows the coordinate class. On `Err` the
            #[doc = concat!(" ", $noun, " is unchanged and the save may be retried.")]
            ///
            /// # Panics
            ///
            /// If the crate's own sizing and emission passes disagree — a
            /// library bug caught at the seam.
            #[inline]
            pub fn save(&self) -> Result<Vec<u8>, SaveFault> {
                let mut out = Vec::new();
                self.save_into(&mut out)?;
                Ok(out)
            }

    };
    (@save $save_src:ident carrier, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            #[doc = concat!(" Serializes the ", $noun, "'s current state.")]
            ///
            #[doc = concat!(" A clean ", $noun, " (no dirt anywhere — ghosts included) hands")]
            /// back the same allocation it opened. Otherwise two passes
            /// run: sizes bottom-up, then one forward emit into an
            /// exactly-sized output — untouched subtrees copy bit-true,
            /// shrouded records prune, LEN prefixes recompute, and
            /// replaced or inserted records emit canonically.
            ///
            /// # Errors
            ///
            /// [`SaveFault::Resource`] on any allocator refusal,
            /// [`SaveFault::BodyOverCap`] when a rewritten LEN body
            /// outgrows the length class, [`SaveFault::DocOverCap`] when
            #[doc = concat!(" the document outgrows the carrier. On `Err` the ", $noun, " is")]
            /// unchanged and the save may be retried.
            ///
            /// # Panics
            ///
            /// If the crate's own sizing and emission passes disagree — a
            /// library bug caught at the seam — or, on the clean-save path
            /// that clones the carrier, if the share count would overflow
            /// (see [`DocBytes::clone`]).
            #[inline]
            pub fn save(&self) -> Result<DocBytes, SaveFault> {
                if self.root.dirty_kids == 0 {
                    return Ok(self.source.clone());
                }
                let (total, bodies) = self.size_pass()?;
                let out = RawDoc::alloc(total).ok_or(SaveFault::Resource)?;
                let mut emit = Emit { out, doc: self.source.as_slice(), run: None };
                self.emit_pass(&mut emit, &bodies);
                Ok(emit.out.finish())
            }

    };
    (@save_len vec, src: $src:ident, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            #[doc = concat!(" The exact byte length [`", stringify!($Machine), "::save`] would emit, without")]
            /// building the document: the sizing pass alone. A clean
            #[doc = concat!(" ", $noun, " answers in O(1) — the save is the source.")]
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::save`] up to publication:")]
            /// [`SaveFault::Resource`] on an allocator refusal inside the
            /// sizing pass, [`SaveFault::BodyOverCap`] when a rewritten
            /// LEN body outgrows the length class,
            /// [`SaveFault::DocOverCap`] when the document outgrows the
            /// coordinate class.
            ///
            /// # Examples
            ///
            /// ```
            /// use protobuf_edit::FieldNumber;
            #[doc = concat!(" use ", $doc_mod, "::{", stringify!($Machine), ", InsertAt};")]
            ///
            /// let msg = [0x08, 0x96, 0x01];
            #[doc = concat!(" let mut ", $noun, " = ", $door, ".unwrap();")]
            /// let field = FieldNumber::new(2).unwrap();
            #[doc = concat!(" ", $noun, ".insert_varint(InsertAt::TailOf(None), field, 42).unwrap();")]
            #[doc = concat!(" assert_eq!(", $noun, ".save_len().unwrap(), 5);")]
            #[doc = concat!(" assert_eq!(", $noun, ".save().unwrap().len(), 5);")]
            /// ```
            pub fn save_len(&self) -> Result<u32, SaveFault> {
                if self.root.dirty_kids == 0 {
                    return Ok($crate::revise::groupless::revising_machine!(@clean_len $src, self));
                }
                Ok(self.size_pass()?.0)
            }

    };
    (@save_len carrier, src: $src:ident, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            #[doc = concat!(" The exact byte length [`", stringify!($Machine), "::save`] would seal, without")]
            /// building the document: the sizing pass alone. A clean
            #[doc = concat!(" ", $noun, " answers in O(1) — the save is the shared carrier")]
            /// itself.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::save`] up to publication:")]
            /// [`SaveFault::Resource`] on an allocator refusal inside the
            /// sizing pass, [`SaveFault::BodyOverCap`] when a rewritten
            /// LEN body outgrows the length class,
            /// [`SaveFault::DocOverCap`] when the document outgrows the
            /// carrier.
            ///
            /// # Examples
            ///
            /// ```
            /// use protobuf_edit::FieldNumber;
            #[doc = concat!(" use ", $doc_mod, "::{InsertAt, ", stringify!($Machine), "};")]
            ///
            /// let msg = [0x08, 0x96, 0x01];
            #[doc = concat!(" let mut ", $noun, " = ", $door, ".unwrap();")]
            /// let field = FieldNumber::new(2).unwrap();
            #[doc = concat!(" ", $noun, ".insert_varint(InsertAt::TailOf(None), field, 42).unwrap();")]
            #[doc = concat!(" assert_eq!(", $noun, ".save_len().unwrap(), 5);")]
            #[doc = concat!(" assert_eq!(", $noun, ".save().unwrap().len(), 5);")]
            /// ```
            pub fn save_len(&self) -> Result<u32, SaveFault> {
                if self.root.dirty_kids == 0 {
                    return Ok($crate::revise::groupless::revising_machine!(@clean_len $src, self));
                }
                Ok(self.size_pass()?.0)
            }

    };
    (@clean_len vec, $this:tt) => {
        crate::admission::admitted_u32($this.source.len())
    };
    (@clean_len stream, $this:tt) => {
        crate::admission::admitted_u32($this.source.len())
    };
    (@clean_len borrow, $this:tt) => {
        crate::admission::admitted_u32($this.source.len())
    };
    (@clean_len carrier, $this:tt) => {
        $this.source.len()
    };
    (@save_into vec, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            #[doc = concat!(" Serializes the ", $noun, "'s current state by appending to `out`")]
            #[doc = concat!(" — [`", stringify!($Machine), "::save`]'s emission into a buffer the caller")]
            /// keeps, amortizable across repeated saves. Existing content
            /// is untouched, and the buffer grows by one exact fallible
            /// reservation.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::save`]: [`SaveFault::Resource`] on an")]
            /// allocator refusal (the reservation included),
            /// [`SaveFault::BodyOverCap`] when a rewritten LEN body
            /// outgrows the length class, [`SaveFault::DocOverCap`] when
            /// the document outgrows the coordinate class. Every fault
            /// precedes the first write: on `Err`, `out` keeps its length
            /// and content.
            ///
            /// # Panics
            ///
            /// If the crate's own sizing and emission passes disagree — a
            /// library bug caught at the seam.
            ///
            /// # Examples
            ///
            /// ```
            #[doc = concat!(" use ", $doc_mod, "::", stringify!($Machine), ";")]
            ///
            /// let msg = [0x08, 0x96, 0x01];
            #[doc = concat!(" let mut ", $noun, " = ", $door, ".unwrap();")]
            #[doc = concat!(" let record = ", $noun, ".top().next().unwrap();")]
            #[doc = concat!(" ", $noun, ".set_varint(record, 7).unwrap();")]
            ///
            /// let mut out = vec![0xFF];
            #[doc = concat!(" ", $noun, ".save_into(&mut out).unwrap();")]
            /// assert_eq!(out, [0xFF, 0x08, 0x07]);
            /// ```
            pub fn save_into(&self, out: &mut Vec<u8>) -> Result<(), SaveFault> {
                if self.root.dirty_kids == 0 {
                    out.try_reserve_exact(self.source.len()).map_err(save_alloc)?;
                    out.extend_from_slice(&self.source);
                    return Ok(());
                }
                let (total, bodies) = self.size_pass()?;
                out.try_reserve_exact(usize_of(total)).map_err(save_alloc)?;
                let start = out.len();
                let mut emit = VecEmit { out, doc: &self.source, run: None };
                self.emit_pass(&mut emit, &bodies);
                assert!(out.len() - start == usize_of(total), concat!($noun, " save: sizing and emission disagree"));
                Ok(())
            }

    };
    (@save_into carrier, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            #[doc = concat!(" Serializes the ", $noun, "'s current state by appending to")]
            #[doc = concat!(" `out` — [`", stringify!($Machine), "::save`]'s emission into a plain `Vec<u8>`")]
            /// instead of a sealed carrier. The carrier is `!Send` by
            /// design; the `Vec` is the owned, portable product for
            /// callers shipping the bytes to another thread or writer.
            /// Existing content is untouched, and the buffer grows by one
            /// exact fallible reservation.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::save`]: [`SaveFault::Resource`] on an")]
            /// allocator refusal (the reservation included),
            /// [`SaveFault::BodyOverCap`] when a rewritten LEN body
            /// outgrows the length class, [`SaveFault::DocOverCap`] when
            /// the document outgrows the carrier class. Every fault
            /// precedes the first write: on `Err`, `out` keeps its length
            /// and content.
            ///
            /// # Panics
            ///
            /// If the crate's own sizing and emission passes disagree — a
            /// library bug caught at the seam.
            ///
            /// # Examples
            ///
            /// ```
            #[doc = concat!(" use ", $doc_mod, "::", stringify!($Machine), ";")]
            ///
            /// let msg = [0x08, 0x96, 0x01];
            #[doc = concat!(" let mut ", $noun, " = ", $door, ".unwrap();")]
            #[doc = concat!(" let record = ", $noun, ".top().next().unwrap();")]
            #[doc = concat!(" ", $noun, ".set_varint(record, 7).unwrap();")]
            ///
            /// let mut out = vec![0xFF];
            #[doc = concat!(" ", $noun, ".save_into(&mut out).unwrap();")]
            /// assert_eq!(out, [0xFF, 0x08, 0x07]);
            /// ```
            pub fn save_into(&self, out: &mut Vec<u8>) -> Result<(), SaveFault> {
                if self.root.dirty_kids == 0 {
                    let doc = self.source.as_slice();
                    out.try_reserve_exact(doc.len()).map_err(save_alloc)?;
                    out.extend_from_slice(doc);
                    return Ok(());
                }
                let (total, bodies) = self.size_pass()?;
                out.try_reserve_exact(usize_of(total)).map_err(save_alloc)?;
                let start = out.len();
                let mut emit = VecEmit { out, doc: self.source.as_slice(), run: None };
                self.emit_pass(&mut emit, &bodies);
                assert!(out.len() - start == usize_of(total), concat!($noun, " save: sizing and emission disagree"));
                Ok(())
            }

    };
    (@save_sink stream vec, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            #[doc = concat!(" Serializes the ", $noun, "'s current state by handing the")]
            /// save's bytes to `sink` as borrowed slices, in output order
            /// — no output buffer: clean runs pass through as windows of
            /// the ingested source, authored words ride a ten-byte stack
            #[doc = concat!(" window, and the concatenation is exactly [`", stringify!($Machine), "::save`]'s")]
            #[doc = concat!(" bytes. A clean ", $noun, " hands the whole source as one window.")]
            ///
            /// The sizing pass runs first and fronts every fault — the
            /// resource refusals included — so nothing can refuse once the
            /// first slice is handed over.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::save`]; on `Err` the sink has been handed")]
            /// nothing.
            ///
            /// # Panics
            ///
            /// If the crate's own sizing and emission passes disagree — a
            /// library bug caught at the seam.
            ///
            /// # Examples
            ///
            /// ```
            #[doc = concat!(" use ", $doc_mod, "::", stringify!($Machine), ";")]
            ///
            /// let msg = [0x08, 0x96, 0x01];
            #[doc = concat!(" let mut ", $noun, " = ", $door, ".unwrap();")]
            #[doc = concat!(" let record = ", $noun, ".top().next().unwrap();")]
            #[doc = concat!(" ", $noun, ".set_varint(record, 7).unwrap();")]
            ///
            /// let mut streamed = Vec::new();
            #[doc = concat!(" ", $noun, ".save_sink(|slice| streamed.extend_from_slice(slice)).unwrap();")]
            #[doc = concat!(" assert_eq!(streamed, ", $noun, ".save().unwrap());")]
            /// ```
            pub fn save_sink(&self, mut sink: impl FnMut(&[u8])) -> Result<(), SaveFault> {
                if self.root.dirty_kids == 0 {
                    if !self.source.is_empty() {
                        sink(&self.source);
                    }
                    return Ok(());
                }
                let (total, bodies) = self.size_pass()?;
                let mut emit = SinkEmit { doc: &self.source, sink: &mut sink, run: None, written: 0 };
                self.emit_pass(&mut emit, &bodies);
                assert!(emit.written == u64::from(total), concat!($noun, " save: the sink walk covers the price"));
                Ok(())
            }

    };
    (@save_sink vec vec, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            #[doc = concat!(" Serializes the ", $noun, "'s current state by handing the")]
            /// save's bytes to `sink` as borrowed slices, in output order
            /// — no output buffer: clean runs pass through as windows of
            /// the moved-in source, authored words ride a ten-byte stack
            #[doc = concat!(" window, and the concatenation is exactly [`", stringify!($Machine), "::save`]'s")]
            #[doc = concat!(" bytes. A clean ", $noun, " hands the whole source as one window.")]
            ///
            /// The sizing pass runs first and fronts every fault — the
            /// resource refusals included — so nothing can refuse once the
            /// first slice is handed over.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::save`]; on `Err` the sink has been handed")]
            /// nothing.
            ///
            /// # Panics
            ///
            /// If the crate's own sizing and emission passes disagree — a
            /// library bug caught at the seam.
            ///
            /// # Examples
            ///
            /// ```
            #[doc = concat!(" use ", $doc_mod, "::", stringify!($Machine), ";")]
            ///
            #[doc = concat!(" let mut ", $noun, " = ", stringify!($Machine), "::open_copy(&[0x08, 0x96, 0x01]).unwrap();")]
            #[doc = concat!(" let record = ", $noun, ".top().next().unwrap();")]
            #[doc = concat!(" ", $noun, ".set_varint(record, 7).unwrap();")]
            ///
            /// let mut streamed = Vec::new();
            #[doc = concat!(" ", $noun, ".save_sink(|slice| streamed.extend_from_slice(slice)).unwrap();")]
            #[doc = concat!(" assert_eq!(streamed, ", $noun, ".save().unwrap());")]
            /// ```
            pub fn save_sink(&self, mut sink: impl FnMut(&[u8])) -> Result<(), SaveFault> {
                if self.root.dirty_kids == 0 {
                    if !self.source.is_empty() {
                        sink(&self.source);
                    }
                    return Ok(());
                }
                let (total, bodies) = self.size_pass()?;
                let mut emit = SinkEmit { doc: &self.source, sink: &mut sink, run: None, written: 0 };
                self.emit_pass(&mut emit, &bodies);
                assert!(emit.written == u64::from(total), concat!($noun, " save: the sink walk covers the price"));
                Ok(())
            }

    };
    (@save_sink borrow vec, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            #[doc = concat!(" Serializes the ", $noun, "'s current state by handing the")]
            /// save's bytes to `sink` as borrowed slices, in output order
            /// — no output buffer: clean runs pass through as windows of
            /// the borrowed source, authored words ride a ten-byte stack
            #[doc = concat!(" window, and the concatenation is exactly [`", stringify!($Machine), "::save`]'s")]
            #[doc = concat!(" bytes. A clean ", $noun, " hands the whole source as one window.")]
            ///
            /// The sizing pass runs first and fronts every fault — the
            /// resource refusals included — so nothing can refuse once the
            /// first slice is handed over.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::save`]; on `Err` the sink has been handed")]
            /// nothing.
            ///
            /// # Panics
            ///
            /// If the crate's own sizing and emission passes disagree — a
            /// library bug caught at the seam.
            ///
            /// # Examples
            ///
            /// ```
            #[doc = concat!(" use ", $doc_mod, "::", stringify!($Machine), ";")]
            ///
            /// let msg = [0x08, 0x96, 0x01];
            #[doc = concat!(" let mut ", $noun, " = ", stringify!($Machine), "::open(&msg).unwrap();")]
            #[doc = concat!(" let record = ", $noun, ".top().next().unwrap();")]
            #[doc = concat!(" ", $noun, ".set_varint(record, 7).unwrap();")]
            ///
            /// let mut streamed = Vec::new();
            #[doc = concat!(" ", $noun, ".save_sink(|slice| streamed.extend_from_slice(slice)).unwrap();")]
            #[doc = concat!(" assert_eq!(streamed, ", $noun, ".save().unwrap());")]
            /// ```
            pub fn save_sink(&self, mut sink: impl FnMut(&[u8])) -> Result<(), SaveFault> {
                if self.root.dirty_kids == 0 {
                    if !self.source.is_empty() {
                        sink(self.source);
                    }
                    return Ok(());
                }
                let (total, bodies) = self.size_pass()?;
                let mut emit = SinkEmit { doc: self.source, sink: &mut sink, run: None, written: 0 };
                self.emit_pass(&mut emit, &bodies);
                assert!(emit.written == u64::from(total), concat!($noun, " save: the sink walk covers the price"));
                Ok(())
            }

    };
    (@save_sink carrier carrier, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            #[doc = concat!(" Serializes the ", $noun, "'s current state by handing the")]
            /// save's bytes to `sink` as borrowed slices, in output order
            /// — no output buffer: clean runs pass through as windows of
            /// the sealed document, authored words ride a ten-byte stack
            #[doc = concat!(" window, and the concatenation is exactly [`", stringify!($Machine), "::save`]'s")]
            #[doc = concat!(" bytes. A clean ", $noun, " hands the whole document as one")]
            /// window.
            ///
            /// The sizing pass runs first and fronts every fault — the
            /// resource refusals included — so nothing can refuse once the
            /// first slice is handed over.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::save`]; on `Err` the sink has been handed")]
            /// nothing.
            ///
            /// # Panics
            ///
            /// If the crate's own sizing and emission passes disagree — a
            /// library bug caught at the seam.
            ///
            /// # Examples
            ///
            /// ```
            #[doc = concat!(" use ", $doc_mod, "::", stringify!($Machine), ";")]
            ///
            #[doc = concat!(" let mut ", $noun, " = ", stringify!($Machine), "::open_copy(&[0x08, 0x96, 0x01]).unwrap();")]
            #[doc = concat!(" let record = ", $noun, ".top().next().unwrap();")]
            #[doc = concat!(" ", $noun, ".set_varint(record, 7).unwrap();")]
            ///
            /// let mut streamed = Vec::new();
            #[doc = concat!(" ", $noun, ".save_sink(|slice| streamed.extend_from_slice(slice)).unwrap();")]
            #[doc = concat!(" assert_eq!(streamed, ", $noun, ".save().unwrap().as_slice());")]
            /// ```
            pub fn save_sink(&self, mut sink: impl FnMut(&[u8])) -> Result<(), SaveFault> {
                if self.root.dirty_kids == 0 {
                    let doc = self.source.as_slice();
                    if !doc.is_empty() {
                        sink(doc);
                    }
                    return Ok(());
                }
                let (total, bodies) = self.size_pass()?;
                let mut emit =
                    SinkEmit { doc: self.source.as_slice(), sink: &mut sink, run: None, written: 0 };
                self.emit_pass(&mut emit, &bodies);
                assert!(emit.written == u64::from(total), concat!($noun, " save: the sink walk covers the price"));
                Ok(())
            }

    };
    (@spans_face src: $src:ident, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            #[doc = concat!(" The output-order span table of the save this ", $noun, " would")]
            /// emit: every record the save walk emits — source-endorsed or
            /// authored, not shrouded, ghosts excluded — paired with its
            /// whole-record span in the output, containers enclosing their
            /// interiors. (An authored payload emits wholesale, so its
            /// record is one entry; rows scanned out of it stay interior
            /// to that entry.) The sizing pass runs first, so the table
            #[doc = concat!(" prices exactly what [`", stringify!($Machine), "::save`] would produce,")]
            /// without emitting a byte.
            ///
            /// Handles do not survive a save-and-reopen; spans do — the
            #[doc = $crate::revise::groupless::revising_machine!(@recipe_doc $src, $noun)]
            /// this face with `narrowest` on the reopened document.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::save`] — the same sizing pass surfaces the")]
            /// same faults, and the table's memory reserves fallibly.
            ///
            /// # Panics
            ///
            /// If the sizing and span walks disagree — a library bug
            /// caught at the seam.
            ///
            /// # Examples
            ///
            /// ```
            #[doc = concat!(" use ", $doc_mod, "::", stringify!($Machine), ";")]
            ///
            /// // varint f1=150 · varint f2=42; delete f2.
            /// let msg = [0x08, 0x96, 0x01, 0x10, 0x2A];
            #[doc = concat!(" let mut ", $noun, " = ", $door, ".unwrap();")]
            #[doc = concat!(" let tops: Vec<_> = ", $noun, ".top().collect();")]
            #[doc = concat!(" ", $noun, ".delete(tops[1]).unwrap();")]
            ///
            #[doc = concat!(" let spans = ", $noun, ".save_spans().unwrap();")]
            /// let table: Vec<_> = spans.iter().collect();
            /// assert_eq!(table.len(), 1, "shrouded records leave the table");
            /// assert_eq!(table[0].0, tops[0]);
            /// assert_eq!((table[0].1.start(), table[0].1.end()), (0, 3));
            /// ```
            pub fn save_spans(&self) -> Result<SaveSpans, SaveFault> {
                let (total, bodies) = if self.root.dirty_kids == 0 {
                    ($crate::revise::groupless::revising_machine!(@clean_len $src, self), Vec::new())
                } else {
                    self.size_pass()?
                };
                let mut entries: Vec<(Handle, Span)> = Vec::new();
                // One reservation covers the table: at most one entry per
                // arena row.
                entries.try_reserve(self.rows.len()).map_err(save_alloc)?;
                let covered = self.span_walk(&bodies, &mut entries)?;
                assert!(covered == total, concat!($noun, " spans: the span walk covers the priced save"));
                Ok(SaveSpans { entries })
            }

    };
    (@verbatim_spans Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// Span entries for one clean scanned subtree: every live row
            /// shifts by one delta — the subtree's output position against
            /// its document position. Ghosts contribute no entry and hide
            /// their (authored, never-emitted) interiors.
            fn verbatim_spans(&self, root: RowId, out: u32, entries: &mut Vec<(Handle, Span)>) {
                // SAFETY: the callers' clean arm admits only scanned rows.
                let base = unsafe { scanned_at(self.row(root)) }.as_inner();
                let mut cur = Some(root);
                while let Some(id) = cur {
                    let row = self.row(id);
                    let live = matches!(row.edit, Edit::Intact);
                    if live {
                        // SAFETY: `Intact` is outside the Inserted family.
                        let at = unsafe { scanned_at(row) }.as_inner();
                        entries.push((Handle(id), Span::new(at - base + out, row.end - base + out)));
                    }
                    let kid = if live { self.slot_first(row.slot()) } else { None };
                    cur = kid.map_or_else(
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

    };
    (@span_walk plain tolerant, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// The span walk: the emit pass's twin, advancing an output
            /// cursor instead of bytes. Container entries open with their
            /// start and take their end at climb-out, when the interior
            /// has priced itself.
            fn span_walk(
                &self,
                bodies: &[u32],
                entries: &mut Vec<(Handle, Span)>,
            ) -> Result<u32, SaveFault> {
                let mut out: u32 = 0;
                let mut body_cursor = 0;
                // Entry indexes of open containers, patched at climb-out.
                let mut frames: Vec<usize> = Vec::new();
                let mut open: Option<RowId> = None;
                let mut cur = self.root.first;
                loop {
                    let Some(id) = cur else {
                        let Some(container) = open else { break };
                        let row = self.row(container);
                        let Some(at) = frames.pop() else {
                            unreachable!(concat!($noun, " spans: climb without an open frame"))
                        };
                        entries[at].1 = Span::new(entries[at].1.start(), out);
                        cur = row.next;
                        open = row.parent;
                        continue;
                    };
                    let row = self.row(id);
                    if matches!(row.edit, Edit::Intact) && !row.dirty() {
                        // SAFETY: the Intact arm is outside the Inserted
                        // family.
                        let at = unsafe { scanned_at(row) };
                        self.verbatim_spans(id, out, entries);
                        out += row.end - at.as_inner();
                        cur = row.next;
                        continue;
                    }
                    match self.settle(row) {
                        Arm::Skip => {}
                        // Clean rows take the verbatim arm above; this one
                        // stays for totality (settle is shared with the
                        // byte walks).
                        Arm::Clean { at, end } => {
                            self.verbatim_spans(id, out, entries);
                            out += end - at.as_inner();
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
                            let (_, plen) = self.store.span(value);
                            let prefix =
                                if plen == src_len { prefix_end - tag_end } else { encoded_len32(plen) };
                            let len = (tag_end - tag_at) + prefix + plen;
                            entries.push((Handle(id), Span::new(out, out + len)));
                            out += len;
                        }
                        Arm::NewBody { head, value } => {
                            let (_, plen) = self.store.span(value);
                            let len = encoded_len32(head) + encoded_len32(plen) + plen;
                            entries.push((Handle(id), Span::new(out, out + len)));
                            out += len;
                        }
                        Arm::Spine { tag_at, tag_end, prefix_end, src_len, first } => {
                            let body = bodies[body_cursor];
                            body_cursor += 1;
                            let prefix =
                                if body == src_len { prefix_end - tag_end } else { encoded_len32(body) };
                            frames.try_reserve(1).map_err(save_alloc)?;
                            frames.push(entries.len());
                            entries.push((Handle(id), Span::new(out, out)));
                            out += (tag_end - tag_at) + prefix;
                            open = Some(id);
                            cur = first;
                            continue;
                        }
                    }
                    cur = row.next;
                }
                Ok(out)
            }
    };
    (@span_walk transfer tolerant, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// The span walk: the emit pass's twin, advancing an output
            /// cursor instead of bytes. Container entries open with their
            /// start and take their end at climb-out, when the interior
            /// has priced itself.
            fn span_walk(
                &self,
                bodies: &[u32],
                entries: &mut Vec<(Handle, Span)>,
            ) -> Result<u32, SaveFault> {
                let mut out: u32 = 0;
                let mut body_cursor = 0;
                // Entry indexes of open containers, patched at climb-out.
                let mut frames: Vec<usize> = Vec::new();
                let mut open: Option<RowId> = None;
                let mut cur = self.root.first;
                loop {
                    let Some(id) = cur else {
                        let Some(container) = open else { break };
                        let row = self.row(container);
                        let Some(at) = frames.pop() else {
                            unreachable!(concat!($noun, " spans: climb without an open frame"))
                        };
                        entries[at].1 = Span::new(entries[at].1.start(), out);
                        cur = row.next;
                        open = row.parent;
                        continue;
                    };
                    let row = self.row(id);
                    if matches!(row.edit, Edit::Intact) && !row.dirty() {
                        // SAFETY: the Intact arm is outside the Inserted
                        // family.
                        let at = unsafe { scanned_at(row) };
                        self.verbatim_spans(id, out, entries);
                        out += row.end - at.as_inner();
                        cur = row.next;
                        continue;
                    }
                    match self.settle(row) {
                        Arm::Skip => {}
                        // Clean rows take the verbatim arm above; this one
                        // stays for totality (settle is shared with the
                        // byte walks).
                        Arm::Clean { at, end } => {
                            self.verbatim_spans(id, out, entries);
                            out += end - at.as_inner();
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
                            let (_, plen) = self.store.span(value);
                            let prefix =
                                if plen == src_len { prefix_end - tag_end } else { encoded_len32(plen) };
                            let len = (tag_end - tag_at) + prefix + plen;
                            entries.push((Handle(id), Span::new(out, out + len)));
                            out += len;
                        }
                        Arm::NewBody { head, value } => {
                            let (_, plen) = self.store.span(value);
                            let len = encoded_len32(head) + encoded_len32(plen) + plen;
                            entries.push((Handle(id), Span::new(out, out + len)));
                            out += len;
                        }
                        Arm::ReBodyAlias { tag_at, tag_end, prefix_end, src_len, len, .. } => {
                            let prefix =
                                if len == src_len { prefix_end - tag_end } else { encoded_len32(len) };
                            let whole = (tag_end - tag_at) + prefix + len;
                            entries.push((Handle(id), Span::new(out, out + whole)));
                            out += whole;
                        }
                        Arm::NewBodyAlias { head, len, .. } => {
                            let whole = encoded_len32(head) + encoded_len32(len) + len;
                            entries.push((Handle(id), Span::new(out, out + whole)));
                            out += whole;
                        }
                        Arm::Import { value } => {
                            let len = self.store.span(value).1;
                            entries.push((Handle(id), Span::new(out, out + len)));
                            out += len;
                        }
                        Arm::Spine { tag_at, tag_end, prefix_end, src_len, first } => {
                            let body = bodies[body_cursor];
                            body_cursor += 1;
                            let prefix =
                                if body == src_len { prefix_end - tag_end } else { encoded_len32(body) };
                            frames.try_reserve(1).map_err(save_alloc)?;
                            frames.push(entries.len());
                            entries.push((Handle(id), Span::new(out, out)));
                            out += (tag_end - tag_at) + prefix;
                            open = Some(id);
                            cur = first;
                            continue;
                        }
                        Arm::ImportSpine { tag_at, tag_end, prefix_end, src_len, first, .. } => {
                            let body = bodies[body_cursor];
                            body_cursor += 1;
                            let prefix =
                                if body == src_len { prefix_end - tag_end } else { encoded_len32(body) };
                            frames.try_reserve(1).map_err(save_alloc)?;
                            frames.push(entries.len());
                            entries.push((Handle(id), Span::new(out, out)));
                            out += (tag_end - tag_at) + prefix;
                            open = Some(id);
                            cur = first;
                            continue;
                        }
                        Arm::NewSpine { head, first } => {
                            let body = bodies[body_cursor];
                            body_cursor += 1;
                            frames.try_reserve(1).map_err(save_alloc)?;
                            frames.push(entries.len());
                            entries.push((Handle(id), Span::new(out, out)));
                            out += encoded_len32(head) + encoded_len32(body);
                            open = Some(id);
                            cur = first;
                            continue;
                        }
                    }
                    cur = row.next;
                }
                Ok(out)
            }
    };
    (@span_walk $cap:ident tolerant, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// The span walk: the emit pass's twin, advancing an output
            /// cursor instead of bytes. Container entries open with their
            /// start and take their end at climb-out, when the interior
            /// has priced itself.
            fn span_walk(
                &self,
                bodies: &[u32],
                entries: &mut Vec<(Handle, Span)>,
            ) -> Result<u32, SaveFault> {
                let mut out: u32 = 0;
                let mut body_cursor = 0;
                // Entry indexes of open containers, patched at climb-out.
                let mut frames: Vec<usize> = Vec::new();
                let mut open: Option<RowId> = None;
                let mut cur = self.root.first;
                loop {
                    let Some(id) = cur else {
                        let Some(container) = open else { break };
                        let row = self.row(container);
                        let Some(at) = frames.pop() else {
                            unreachable!(concat!($noun, " spans: climb without an open frame"))
                        };
                        entries[at].1 = Span::new(entries[at].1.start(), out);
                        cur = row.next;
                        open = row.parent;
                        continue;
                    };
                    let row = self.row(id);
                    if matches!(row.edit, Edit::Intact) && !row.dirty() {
                        // SAFETY: the Intact arm is outside the Inserted
                        // family.
                        let at = unsafe { scanned_at(row) };
                        self.verbatim_spans(id, out, entries);
                        out += row.end - at.as_inner();
                        cur = row.next;
                        continue;
                    }
                    match self.settle(row) {
                        Arm::Skip => {}
                        // Clean rows take the verbatim arm above; this one
                        // stays for totality (settle is shared with the
                        // byte walks).
                        Arm::Clean { at, end } => {
                            self.verbatim_spans(id, out, entries);
                            out += end - at.as_inner();
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
                            let (_, plen) = self.store.span(value);
                            let prefix =
                                if plen == src_len { prefix_end - tag_end } else { encoded_len32(plen) };
                            let len = (tag_end - tag_at) + prefix + plen;
                            entries.push((Handle(id), Span::new(out, out + len)));
                            out += len;
                        }
                        Arm::NewBody { head, value } => {
                            let (_, plen) = self.store.span(value);
                            let len = encoded_len32(head) + encoded_len32(plen) + plen;
                            entries.push((Handle(id), Span::new(out, out + len)));
                            out += len;
                        }
                        Arm::ReBodyAlias { tag_at, tag_end, prefix_end, src_len, len, .. } => {
                            let prefix =
                                if len == src_len { prefix_end - tag_end } else { encoded_len32(len) };
                            let whole = (tag_end - tag_at) + prefix + len;
                            entries.push((Handle(id), Span::new(out, out + whole)));
                            out += whole;
                        }
                        Arm::NewBodyAlias { head, len, .. } => {
                            let whole = encoded_len32(head) + encoded_len32(len) + len;
                            entries.push((Handle(id), Span::new(out, out + whole)));
                            out += whole;
                        }
                        Arm::Import { value } => {
                            let len = self.store.span(value).1;
                            entries.push((Handle(id), Span::new(out, out + len)));
                            out += len;
                        }
                        Arm::Spine { tag_at, tag_end, prefix_end, src_len, first } => {
                            let body = bodies[body_cursor];
                            body_cursor += 1;
                            let prefix =
                                if body == src_len { prefix_end - tag_end } else { encoded_len32(body) };
                            frames.try_reserve(1).map_err(save_alloc)?;
                            frames.push(entries.len());
                            entries.push((Handle(id), Span::new(out, out)));
                            out += (tag_end - tag_at) + prefix;
                            open = Some(id);
                            cur = first;
                            continue;
                        }
                        Arm::NewSpine { head, first } => {
                            let body = bodies[body_cursor];
                            body_cursor += 1;
                            frames.try_reserve(1).map_err(save_alloc)?;
                            frames.push(entries.len());
                            entries.push((Handle(id), Span::new(out, out)));
                            out += encoded_len32(head) + encoded_len32(body);
                            open = Some(id);
                            cur = first;
                            continue;
                        }
                    }
                    cur = row.next;
                }
                Ok(out)
            }
    };
    (@span_walk plain canonical, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// The span walk: the emit pass's twin, advancing an output
            /// cursor instead of bytes. Container entries open with their
            /// start and take their end at climb-out, when the interior
            /// has priced itself.
            fn span_walk(
                &self,
                bodies: &[u32],
                entries: &mut Vec<(Handle, Span)>,
            ) -> Result<u32, SaveFault> {
                let mut out: u32 = 0;
                let mut body_cursor = 0;
                // Entry indexes of open containers, patched at climb-out.
                let mut frames: Vec<usize> = Vec::new();
                let mut open: Option<RowId> = None;
                let mut cur = self.root.first;
                loop {
                    let Some(id) = cur else {
                        let Some(container) = open else { break };
                        let row = self.row(container);
                        let Some(at) = frames.pop() else {
                            unreachable!(concat!($noun, " spans: climb without an open frame"))
                        };
                        entries[at].1 = Span::new(entries[at].1.start(), out);
                        cur = row.next;
                        open = row.parent;
                        continue;
                    };
                    let row = self.row(id);
                    if matches!(row.edit, Edit::Intact) && !row.dirty() {
                        // SAFETY: the Intact arm is outside the Inserted
                        // family.
                        let at = unsafe { scanned_at(row) };
                        self.verbatim_spans(id, out, entries);
                        out += row.end - at.as_inner();
                        cur = row.next;
                        continue;
                    }
                    match self.settle(row) {
                        Arm::Skip => {}
                        // Clean rows take the verbatim arm above; this one
                        // stays for totality (settle is shared with the
                        // byte walks).
                        Arm::Clean { at, end } => {
                            self.verbatim_spans(id, out, entries);
                            out += end - at.as_inner();
                        }
                        Arm::Varint { head, word } => {
                            let len = encoded_len32(head) + encoded_len64(word);
                            entries.push((Handle(id), Span::new(out, out + len)));
                            out += len;
                        }
                        Arm::Bits32 { head, .. } => {
                            let len = encoded_len32(head) + 4;
                            entries.push((Handle(id), Span::new(out, out + len)));
                            out += len;
                        }
                        Arm::Bits64 { head, .. } => {
                            let len = encoded_len32(head) + 8;
                            entries.push((Handle(id), Span::new(out, out + len)));
                            out += len;
                        }
                        Arm::Body { head, value } => {
                            let (_, plen) = self.store.span(value);
                            let len = encoded_len32(head) + encoded_len32(plen) + plen;
                            entries.push((Handle(id), Span::new(out, out + len)));
                            out += len;
                        }
                        Arm::Spine { head, first, .. } => {
                            let body = bodies[body_cursor];
                            body_cursor += 1;
                            frames.try_reserve(1).map_err(save_alloc)?;
                            frames.push(entries.len());
                            entries.push((Handle(id), Span::new(out, out)));
                            out += encoded_len32(head) + encoded_len32(body);
                            open = Some(id);
                            cur = first;
                            continue;
                        }
                    }
                    cur = row.next;
                }
                Ok(out)
            }
    };
    (@span_walk transfer canonical, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// The span walk: the emit pass's twin, advancing an output
            /// cursor instead of bytes. Container entries open with their
            /// start and take their end at climb-out, when the interior
            /// has priced itself.
            fn span_walk(
                &self,
                bodies: &[u32],
                entries: &mut Vec<(Handle, Span)>,
            ) -> Result<u32, SaveFault> {
                let mut out: u32 = 0;
                let mut body_cursor = 0;
                // Entry indexes of open containers, patched at climb-out.
                let mut frames: Vec<usize> = Vec::new();
                let mut open: Option<RowId> = None;
                let mut cur = self.root.first;
                loop {
                    let Some(id) = cur else {
                        let Some(container) = open else { break };
                        let row = self.row(container);
                        let Some(at) = frames.pop() else {
                            unreachable!(concat!($noun, " spans: climb without an open frame"))
                        };
                        entries[at].1 = Span::new(entries[at].1.start(), out);
                        cur = row.next;
                        open = row.parent;
                        continue;
                    };
                    let row = self.row(id);
                    if matches!(row.edit, Edit::Intact) && !row.dirty() {
                        // SAFETY: the Intact arm is outside the Inserted
                        // family.
                        let at = unsafe { scanned_at(row) };
                        self.verbatim_spans(id, out, entries);
                        out += row.end - at.as_inner();
                        cur = row.next;
                        continue;
                    }
                    match self.settle(row) {
                        Arm::Skip => {}
                        // Clean rows take the verbatim arm above; this one
                        // stays for totality (settle is shared with the
                        // byte walks).
                        Arm::Clean { at, end } => {
                            self.verbatim_spans(id, out, entries);
                            out += end - at.as_inner();
                        }
                        Arm::Varint { head, word } => {
                            let len = encoded_len32(head) + encoded_len64(word);
                            entries.push((Handle(id), Span::new(out, out + len)));
                            out += len;
                        }
                        Arm::Bits32 { head, .. } => {
                            let len = encoded_len32(head) + 4;
                            entries.push((Handle(id), Span::new(out, out + len)));
                            out += len;
                        }
                        Arm::Bits64 { head, .. } => {
                            let len = encoded_len32(head) + 8;
                            entries.push((Handle(id), Span::new(out, out + len)));
                            out += len;
                        }
                        Arm::Body { head, value } => {
                            let (_, plen) = self.store.span(value);
                            let len = encoded_len32(head) + encoded_len32(plen) + plen;
                            entries.push((Handle(id), Span::new(out, out + len)));
                            out += len;
                        }
                        Arm::BodyAlias { head, len, .. } => {
                            let whole = encoded_len32(head) + encoded_len32(len) + len;
                            entries.push((Handle(id), Span::new(out, out + whole)));
                            out += whole;
                        }
                        Arm::Import { value } => {
                            let len = self.store.span(value).1;
                            entries.push((Handle(id), Span::new(out, out + len)));
                            out += len;
                        }
                        Arm::Spine { head, first, .. } => {
                            let body = bodies[body_cursor];
                            body_cursor += 1;
                            frames.try_reserve(1).map_err(save_alloc)?;
                            frames.push(entries.len());
                            entries.push((Handle(id), Span::new(out, out)));
                            out += encoded_len32(head) + encoded_len32(body);
                            open = Some(id);
                            cur = first;
                            continue;
                        }
                    }
                    cur = row.next;
                }
                Ok(out)
            }
    };
    (@span_walk $cap:ident canonical, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// The span walk: the emit pass's twin, advancing an output
            /// cursor instead of bytes. Container entries open with their
            /// start and take their end at climb-out, when the interior
            /// has priced itself.
            fn span_walk(
                &self,
                bodies: &[u32],
                entries: &mut Vec<(Handle, Span)>,
            ) -> Result<u32, SaveFault> {
                let mut out: u32 = 0;
                let mut body_cursor = 0;
                // Entry indexes of open containers, patched at climb-out.
                let mut frames: Vec<usize> = Vec::new();
                let mut open: Option<RowId> = None;
                let mut cur = self.root.first;
                loop {
                    let Some(id) = cur else {
                        let Some(container) = open else { break };
                        let row = self.row(container);
                        let Some(at) = frames.pop() else {
                            unreachable!(concat!($noun, " spans: climb without an open frame"))
                        };
                        entries[at].1 = Span::new(entries[at].1.start(), out);
                        cur = row.next;
                        open = row.parent;
                        continue;
                    };
                    let row = self.row(id);
                    if matches!(row.edit, Edit::Intact) && !row.dirty() {
                        // SAFETY: the Intact arm is outside the Inserted
                        // family.
                        let at = unsafe { scanned_at(row) };
                        self.verbatim_spans(id, out, entries);
                        out += row.end - at.as_inner();
                        cur = row.next;
                        continue;
                    }
                    match self.settle(row) {
                        Arm::Skip => {}
                        // Clean rows take the verbatim arm above; this one
                        // stays for totality (settle is shared with the
                        // byte walks).
                        Arm::Clean { at, end } => {
                            self.verbatim_spans(id, out, entries);
                            out += end - at.as_inner();
                        }
                        Arm::Varint { head, word } => {
                            let len = encoded_len32(head) + encoded_len64(word);
                            entries.push((Handle(id), Span::new(out, out + len)));
                            out += len;
                        }
                        Arm::Bits32 { head, .. } => {
                            let len = encoded_len32(head) + 4;
                            entries.push((Handle(id), Span::new(out, out + len)));
                            out += len;
                        }
                        Arm::Bits64 { head, .. } => {
                            let len = encoded_len32(head) + 8;
                            entries.push((Handle(id), Span::new(out, out + len)));
                            out += len;
                        }
                        Arm::Body { head, value } => {
                            let (_, plen) = self.store.span(value);
                            let len = encoded_len32(head) + encoded_len32(plen) + plen;
                            entries.push((Handle(id), Span::new(out, out + len)));
                            out += len;
                        }
                        Arm::BodyAlias { head, len, .. } => {
                            let whole = encoded_len32(head) + encoded_len32(len) + len;
                            entries.push((Handle(id), Span::new(out, out + whole)));
                            out += whole;
                        }
                        Arm::Import { value } => {
                            let len = self.store.span(value).1;
                            entries.push((Handle(id), Span::new(out, out + len)));
                            out += len;
                        }
                        Arm::Spine { head, first, .. } => {
                            let body = bodies[body_cursor];
                            body_cursor += 1;
                            frames.try_reserve(1).map_err(save_alloc)?;
                            frames.push(entries.len());
                            entries.push((Handle(id), Span::new(out, out)));
                            out += encoded_len32(head) + encoded_len32(body);
                            open = Some(id);
                            cur = first;
                            continue;
                        }
                    }
                    cur = row.next;
                }
                Ok(out)
            }
    };
    (@canonical plain canonical, prod: $prod:ident, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {};
    (@canonical plain tolerant, prod: $prod:ident, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            // ── canonical output ──

            /// The canonical walk's verdict for one row, every value
            /// resolved at judgment time. Stored widths are not output
            /// widths here — they remain the source-geometry proof that
            /// locates each value, prefix, and payload.
            fn settle_canonical(&self, row: &Row) -> CanonicalArm {
                let head = head_word(row.field, row.kind);
                let source = match row.edit {
                    Edit::Deleted(_) | Edit::InsertedDeleted(_) => return CanonicalArm::Skip,
                    Edit::Replaced(value) | Edit::Inserted(value) => CanonicalSrc::Store(value),
                    Edit::Intact => {
                        // The walk never crosses an effective authored
                        // payload, so no authored-zone row is reachable.
                        debug_assert!(!row.authored_zone(), "the canonical walk stays in the closure");
                        // SAFETY: the Intact arm is outside the Inserted
                        // family.
                        CanonicalSrc::Doc(unsafe { scanned_at(row) })
                    }
                };
                match row.kind {
                    RecordKind::Varint => CanonicalArm::Varint {
                        head,
                        word: match source {
                            CanonicalSrc::Store(v) => self.store.varint(v),
                            CanonicalSrc::Doc(at) => self.scan_varint(row, at),
                        },
                    },
                    RecordKind::I32 => CanonicalArm::I32 {
                        head,
                        value: match source {
                            CanonicalSrc::Store(v) => {
                                CanonicalValue::Store(Word::Bits32(self.store.bits32(v)))
                            }
                            CanonicalSrc::Doc(at) => {
                                CanonicalValue::Doc { at: scanned_value_at(at, row.tag_w()) }
                            }
                        },
                    },
                    RecordKind::I64 => CanonicalArm::I64 {
                        head,
                        value: match source {
                            CanonicalSrc::Store(v) => {
                                CanonicalValue::Store(Word::Bits64(self.store.bits64(v)))
                            }
                            CanonicalSrc::Doc(at) => {
                                CanonicalValue::Doc { at: scanned_value_at(at, row.tag_w()) }
                            }
                        },
                    },
                    RecordKind::Len => match source {
                        // An effective authored payload terminates the
                        // closure whatever rows a browse materialized.
                        CanonicalSrc::Store(value) => {
                            CanonicalArm::OpaqueLen { head, payload: CanonicalPayload::Store(value) }
                        }
                        CanonicalSrc::Doc(at) => match row.slot() {
                            Slot::Opened(layer) => CanonicalArm::OpenLen {
                                head,
                                first: self.layer(layer).first,
                                at,
                            },
                            // Unopened, faulted, or refused: the payload
                            // bytes are a declaration, not records — the
                            // closure ends here even when they happen to
                            // parse.
                            Slot::Unopened | Slot::Fault(_) => {
                                let (payload_at, len) = self.len_geometry(row, at);
                                CanonicalArm::OpaqueLen {
                                    head,
                                    payload: CanonicalPayload::Doc { at: payload_at, len },
                                }
                            }
                        },
                    },
                }
            }

            /// The canonical sizing walk: one complete pass over the
            /// materialized commitment closure, accumulating every
            /// opened LEN's canonical body bottom-up and recording it in
            /// walk order for the emit walk's prefixes. Every live row
            /// is visited — the walk follows visibility, not dirt, so a
            #[doc = concat!(" clean ", $noun, " still pays it in full. Body totals and the")]
            /// spine are call-local; nothing is cached in the machine.
            ///
            /// # Errors
            ///
            /// [`SaveFault::Resource`] on an allocator refusal for the
            /// walk's scratch, [`SaveFault::BodyOverCap`] when an opened
            /// LEN's canonical body outgrows the length class,
            /// [`SaveFault::DocOverCap`] when the canonical document
            /// outgrows the coordinate class.
            fn canonical_size_pass(&self) -> Result<(u32, Vec<u32>), SaveFault> {
                let mut bodies: Vec<u32> = Vec::new();
                let mut spine: Vec<CanonicalFrame> = Vec::new();
                let mut acc: u64 = 0;
                let mut cur = self.root.first;
                loop {
                    let Some(id) = cur else {
                        let Some(frame) = spine.pop() else { break };
                        let body = u32::try_from(acc)
                            .ok()
                            .and_then(PayloadLen::new)
                            .ok_or(SaveFault::BodyOverCap { at: frame.at.as_inner() })?;
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
                                CanonicalPayload::Store(value) => self.store.span(value).1,
                            };
                            acc += u64::from(encoded_len32(head))
                                + u64::from(encoded_len32(len))
                                + u64::from(len);
                        }
                        CanonicalArm::OpenLen { head, first, at } => {
                            bodies.try_reserve(1).map_err(save_alloc)?;
                            spine.try_reserve(1).map_err(save_alloc)?;
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
                    .filter(|total| $crate::revise::groupless::revising_machine!(@in_cap $prod, total))
                    .ok_or(SaveFault::DocOverCap { total: acc })?;
                Ok((total, bodies))
            }

            /// The canonical emit walk: the sizing walk's twin, forward,
            /// writing into the prepaid output. Climbing out of opened
            /// LENs follows parent links — the spine is the arena itself.
            /// Returns the count of body slots consumed, for the faces'
            /// seam assertion.
            fn canonical_emit_pass<O: Out>(&self, emit: &mut O, bodies: &[u32]) -> usize {
                let mut body_cursor = 0;
                let mut open: Option<RowId> = None;
                let mut cur = self.root.first;
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
                            emit.value(Word::Varint(word));
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
                                    emit.varint(u64::from(self.store.span(value).1));
                                    emit.bytes(self.store.span_bytes(value));
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
            /// into a fresh, exactly reserved `Vec<u8>`: minimally emits
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
            /// LEN payload and every effective authored payload
            /// terminate the closure and ride byte-for-byte behind
            /// re-derived framing, even when those bytes happen to
            /// parse. Values, field order, duplicates, liveness, and
            /// the fixed-width bits are untouched.
            ///
            /// The face reads `&self` and caches nothing: body totals
            /// and the sizing spine are call-local, so
            #[doc = concat!(" [`pending`](", stringify!($Machine), "::pending), every status, source spans, the undo")]
            /// log, and the ordinary fidelity save read identically
            /// before and after the call. The ordinary
            /// [`save`](Self::save) family answers byte-fidelity
            /// instead; both re-ingest under `Tolerant`, and this
            /// family's output additionally closes under the dialect
            /// validator's `CanonicalMinimal` standard.
            ///
            /// # Errors
            ///
            /// [`SaveFault::Resource`] when the allocator refuses the
            /// sizing scratch or the output reservation,
            /// [`SaveFault::BodyOverCap`] when an opened LEN's canonical
            /// body outgrows the length class, [`SaveFault::DocOverCap`]
            /// when the canonical document outgrows the coordinate
            /// class. Canonical totals never exceed fidelity totals, so
            /// a state whose fidelity save is in class cannot meet the
            #[doc = concat!(" cap faults here. On `Err` the ", $noun, " is unchanged and")]
            /// the save may be retried.
            ///
            /// # Panics
            ///
            /// If the canonical sizing and emit walks disagree — a
            /// library bug caught at the seam.
            ///
            /// # Examples
            ///
            /// ```
            #[doc = concat!(" use ", $doc_mod, "::", stringify!($Machine), ";")]
            ///
            /// // varint f1=1 (tag padded to two bytes) · LEN f2 [88 00]
            /// let msg = [0x88, 0x00, 0x01, 0x12, 0x02, 0x88, 0x00];
            #[doc = concat!(" let ", $noun, " = ", $door, ".unwrap();")]
            ///
            /// // Fidelity keeps the padded kept tag; the canonical face
            /// // re-emits it minimally. The undescended payload's bytes
            /// // are a declaration and ride opaque.
            #[doc = concat!(" assert_eq!(", $noun, ".save().unwrap(), msg);")]
            #[doc = concat!(" assert_eq!(", $noun, ".save_canonical().unwrap(), [0x08, 0x01, 0x12, 0x02, 0x88, 0x00]);")]
            /// ```
            pub fn save_canonical(&self) -> Result<Vec<u8>, SaveFault> {
                let (total, bodies) = self.canonical_size_pass()?;
                let mut out = Vec::new();
                out.try_reserve_exact(usize_of(total)).map_err(save_alloc)?;
                let mut emit = VecEmit { out: &mut out, doc: &self.source, run: None };
                let consumed = self.canonical_emit_pass(&mut emit, &bodies);
                assert!(
                    consumed == bodies.len() && out.len() == usize_of(total),
                    concat!($noun, " canonical save: sizing and emission disagree")
                );
                Ok(out)
            }

            #[doc = concat!(" [`", stringify!($Machine), "::save_canonical`]'s emission appended to `out`")]
            /// — existing content is untouched. The sizing walk runs
            /// first and the buffer grows by one exact fallible
            /// reservation, so the appends never regrow it.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::save_canonical`]. Every fault precedes the")]
            /// first write: on `Err`, `out` keeps its length and
            #[doc = concat!(" content, and the ", $noun, " is unchanged.")]
            ///
            /// # Panics
            ///
            /// If the canonical sizing and emit walks disagree — a
            /// library bug caught at the seam.
            ///
            /// # Examples
            ///
            /// ```
            #[doc = concat!(" use ", $doc_mod, "::", stringify!($Machine), ";")]
            ///
            /// // varint f1=1, value padded to two bytes.
            /// let msg = [0x08, 0x81, 0x00];
            #[doc = concat!(" let ", $noun, " = ", $door, ".unwrap();")]
            ///
            /// let mut out = vec![0xFF];
            #[doc = concat!(" ", $noun, ".save_canonical_into(&mut out).unwrap();")]
            /// assert_eq!(out, [0xFF, 0x08, 0x01]);
            /// ```
            pub fn save_canonical_into(&self, out: &mut Vec<u8>) -> Result<(), SaveFault> {
                let (total, bodies) = self.canonical_size_pass()?;
                out.try_reserve_exact(usize_of(total)).map_err(save_alloc)?;
                let start = out.len();
                let mut emit = VecEmit { out, doc: &self.source, run: None };
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
            /// through as windows of their backing, framing words ride a
            /// ten-byte stack window, and the concatenation is exactly
            #[doc = concat!(" [`", stringify!($Machine), "::save_canonical`]'s output.")]
            ///
            /// The sizing walk runs first and fronts every fault — the
            /// resource refusals included — so nothing can refuse once
            /// the first slice is handed over. A panic unwinding out of
            /// `sink` may leave already-handed slices with the caller,
            #[doc = concat!(" as any callback panic can; the ", $noun, " itself stays")]
            /// unchanged and reusable.
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
                let mut emit =
                    SinkEmit { doc: &self.source, sink: &mut sink, run: None, written: 0 };
                let consumed = self.canonical_emit_pass(&mut emit, &bodies);
                assert!(
                    consumed == bodies.len() && emit.written == u64::from(total),
                    concat!($noun, " canonical save: the sink walk covers the price")
                );
                Ok(())
            }
    };
    (@canonical $cap:ident canonical, prod: $prod:ident, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {};
    (@canonical transfer tolerant, prod: $prod:ident, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            // ── canonical output ──

            /// The canonical walk's verdict for one row, every value
            /// resolved at judgment time. Stored widths are not output
            /// widths here — they remain the source-geometry proof that
            /// locates each value, prefix, and payload.
            fn settle_canonical(&self, row: &Row) -> CanonicalArm {
                let head = head_word(row.field, row.kind);
                let source = match row.edit {
                    Edit::Deleted(_)
                    | Edit::InsertedDeleted(_)
                    | Edit::Moved { .. }
                    | Edit::SourceRecordDeleted
                    | Edit::SourcePayloadDeleted(_)
                    | Edit::SourceInsertedDeleted(_)
                    | Edit::ImportedDeleted(_) => return CanonicalArm::Skip,
                    Edit::Replaced(value) | Edit::Inserted(value) => CanonicalSrc::Store(value),
                    // A designated payload is an opaque doc-zone subspan
                    // behind re-derived framing; a descended interior
                    // joins the commitment closure and recurses.
                    Edit::SourcePayload(src) | Edit::SourceInserted(src) => {
                        let (payload_at, len) = self.designated_payload(src);
                        return match row.slot() {
                            Slot::Opened(layer) => CanonicalArm::OpenLen {
                                head,
                                first: self.layer(layer).first,
                                // SAFETY: the designated subspan lies in
                                // the document zone, whose admitted end
                                // is inside the offset domain.
                                at: unsafe { At32::new_unchecked(payload_at) },
                            },
                            Slot::Unopened | Slot::Fault(_) => CanonicalArm::OpaqueLen {
                                head,
                                payload: CanonicalPayload::Doc { at: payload_at, len },
                            },
                        };
                    }
                    // An imported record re-emits minimally under the
                    // canonical standard: its met framing is decoded from
                    // the slot, never preserved.
                    Edit::Imported(value) => {
                        let bytes = self.import_slot(value);
                        let at = import_value_at(bytes);
                        return match row.kind {
                            RecordKind::Varint => CanonicalArm::Varint {
                                head,
                                word: match slice::value64(bytes, at, bytes.len()) {
                                    Ok((word, _)) => word,
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
                            RecordKind::Len => match row.slot() {
                                Slot::Opened(layer) if row.dirty() => CanonicalArm::OpenLen {
                                    head,
                                    first: self.layer(layer).first,
                                    // SAFETY: the slot's framing bytes
                                    // follow its zone base inside the
                                    // store's byte column, so the base
                                    // lies below the zone's admitted
                                    // end.
                                    at: unsafe { At32::new_unchecked(self.import_zone(value).1) },
                                },
                                Slot::Opened(_) | Slot::Unopened | Slot::Fault(_) => {
                                    CanonicalArm::OpaqueLen {
                                        head,
                                        payload: CanonicalPayload::Import(value),
                                    }
                                }
                            },
                        };
                    }
                    // A local copy's rows canonicalize from their cloned
                    // geometry exactly like scanned rows: the closure
                    // re-emits minimally, opened interiors recurse.
                    Edit::Intact | Edit::SourceRecord => {
                        // The walk never crosses an effective authored
                        // payload; the only authored-zone rows reachable
                        // are first-class import interiors.
                        debug_assert!(
                            !row.authored_zone() || self.import_zone_row(row),
                            "the canonical walk stays in the closure"
                        );
                        // SAFETY: these arms sit outside the Inserted and
                        // Imported families.
                        CanonicalSrc::Doc(unsafe { scanned_at(row) })
                    }
                };
                match row.kind {
                    RecordKind::Varint => CanonicalArm::Varint {
                        head,
                        word: match source {
                            CanonicalSrc::Store(v) => self.store.varint(v),
                            CanonicalSrc::Doc(at) => self.scan_varint(row, at),
                        },
                    },
                    RecordKind::I32 => CanonicalArm::I32 {
                        head,
                        value: match source {
                            CanonicalSrc::Store(v) => {
                                CanonicalValue::Store(Word::Bits32(self.store.bits32(v)))
                            }
                            CanonicalSrc::Doc(at) => {
                                CanonicalValue::Doc { at: scanned_value_at(at, row.tag_w()) }
                            }
                        },
                    },
                    RecordKind::I64 => CanonicalArm::I64 {
                        head,
                        value: match source {
                            CanonicalSrc::Store(v) => {
                                CanonicalValue::Store(Word::Bits64(self.store.bits64(v)))
                            }
                            CanonicalSrc::Doc(at) => {
                                CanonicalValue::Doc { at: scanned_value_at(at, row.tag_w()) }
                            }
                        },
                    },
                    RecordKind::Len => match source {
                        // An effective authored payload terminates the
                        // closure whatever rows a browse materialized.
                        CanonicalSrc::Store(value) => {
                            CanonicalArm::OpaqueLen { head, payload: CanonicalPayload::Store(value) }
                        }
                        CanonicalSrc::Doc(at) => match row.slot() {
                            Slot::Opened(layer) => CanonicalArm::OpenLen {
                                head,
                                first: self.layer(layer).first,
                                at,
                            },
                            // Unopened, faulted, or refused: the payload
                            // bytes are a declaration, not records — the
                            // closure ends here even when they happen to
                            // parse.
                            Slot::Unopened | Slot::Fault(_) => {
                                let (payload_at, len) = self.len_geometry(row, at);
                                CanonicalArm::OpaqueLen {
                                    head,
                                    payload: CanonicalPayload::Doc { at: payload_at, len },
                                }
                            }
                        },
                    },
                }
            }

            /// The canonical sizing walk: one complete pass over the
            /// materialized commitment closure, accumulating every
            /// opened LEN's canonical body bottom-up and recording it in
            /// walk order for the emit walk's prefixes. Every live row
            /// is visited — the walk follows visibility, not dirt, so a
            #[doc = concat!(" clean ", $noun, " still pays it in full. Body totals and the")]
            /// spine are call-local; nothing is cached in the machine.
            ///
            /// # Errors
            ///
            /// [`SaveFault::Resource`] on an allocator refusal for the
            /// walk's scratch, [`SaveFault::BodyOverCap`] when an opened
            /// LEN's canonical body outgrows the length class,
            /// [`SaveFault::DocOverCap`] when the canonical document
            /// outgrows the coordinate class.
            fn canonical_size_pass(&self) -> Result<(u32, Vec<u32>), SaveFault> {
                let mut bodies: Vec<u32> = Vec::new();
                let mut spine: Vec<CanonicalFrame> = Vec::new();
                let mut acc: u64 = 0;
                let mut cur = self.root.first;
                loop {
                    let Some(id) = cur else {
                        let Some(frame) = spine.pop() else { break };
                        let body = u32::try_from(acc)
                            .ok()
                            .and_then(PayloadLen::new)
                            .ok_or(SaveFault::BodyOverCap { at: frame.at.as_inner() })?;
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
                                CanonicalPayload::Store(value) => self.store.span(value).1,
                                CanonicalPayload::Import(value) => {
                                    crate::admission::admitted_u32(self.import_payload(value).len())
                                }
                            };
                            acc += u64::from(encoded_len32(head))
                                + u64::from(encoded_len32(len))
                                + u64::from(len);
                        }
                        CanonicalArm::OpenLen { head, first, at } => {
                            bodies.try_reserve(1).map_err(save_alloc)?;
                            spine.try_reserve(1).map_err(save_alloc)?;
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
                    .filter(|total| $crate::revise::groupless::revising_machine!(@in_cap $prod, total))
                    .ok_or(SaveFault::DocOverCap { total: acc })?;
                Ok((total, bodies))
            }

            /// The canonical emit walk: the sizing walk's twin, forward,
            /// writing into the prepaid output. Climbing out of opened
            /// LENs follows parent links — the spine is the arena itself.
            /// Returns the count of body slots consumed, for the faces'
            /// seam assertion.
            fn canonical_emit_pass<'s, O: Out<'s>>(&'s self, emit: &mut O, bodies: &[u32]) -> usize {
                let mut body_cursor = 0;
                let mut open: Option<RowId> = None;
                let mut cur = self.root.first;
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
                            emit.value(Word::Varint(word));
                        }
                        CanonicalArm::I32 { head, value } => {
                            emit.word(head);
                            match value {
                                CanonicalValue::Doc { at } => {
                                    let at = at.as_inner();
                                    emit.verbatim_in(self.backing(row), at, at + 4);
                                }
                                CanonicalValue::Store(word) => emit.value(word),
                            }
                        }
                        CanonicalArm::I64 { head, value } => {
                            emit.word(head);
                            match value {
                                CanonicalValue::Doc { at } => {
                                    let at = at.as_inner();
                                    emit.verbatim_in(self.backing(row), at, at + 8);
                                }
                                CanonicalValue::Store(word) => emit.value(word),
                            }
                        }
                        CanonicalArm::OpaqueLen { head, payload } => {
                            emit.word(head);
                            match payload {
                                CanonicalPayload::Doc { at, len } => {
                                    emit.varint(u64::from(len));
                                    emit.verbatim_in(self.backing(row), at, at + len);
                                }
                                CanonicalPayload::Store(value) => {
                                    emit.varint(u64::from(self.store.span(value).1));
                                    emit.bytes(self.store.span_bytes(value));
                                }
                                CanonicalPayload::Import(value) => {
                                    let payload = self.import_payload(value);
                                    emit.varint(u64::from(crate::admission::admitted_u32(
                                        payload.len(),
                                    )));
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
            /// into a fresh, exactly reserved `Vec<u8>`: minimally emits
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
            /// LEN payload and every effective authored payload
            /// terminate the closure and ride byte-for-byte behind
            /// re-derived framing, even when those bytes happen to
            /// parse. Values, field order, duplicates, liveness, and
            /// the fixed-width bits are untouched.
            ///
            /// The face reads `&self` and caches nothing: body totals
            /// and the sizing spine are call-local, so
            #[doc = concat!(" [`pending`](", stringify!($Machine), "::pending), every status, source spans, the undo")]
            /// log, and the ordinary fidelity save read identically
            /// before and after the call. The ordinary
            /// [`save`](Self::save) family answers byte-fidelity
            /// instead; both re-ingest under `Tolerant`, and this
            /// family's output additionally closes under the dialect
            /// validator's `CanonicalMinimal` standard.
            ///
            /// # Errors
            ///
            /// [`SaveFault::Resource`] when the allocator refuses the
            /// sizing scratch or the output reservation,
            /// [`SaveFault::BodyOverCap`] when an opened LEN's canonical
            /// body outgrows the length class, [`SaveFault::DocOverCap`]
            /// when the canonical document outgrows the coordinate
            /// class. Canonical totals never exceed fidelity totals, so
            /// a state whose fidelity save is in class cannot meet the
            #[doc = concat!(" cap faults here. On `Err` the ", $noun, " is unchanged and")]
            /// the save may be retried.
            ///
            /// # Panics
            ///
            /// If the canonical sizing and emit walks disagree — a
            /// library bug caught at the seam.
            ///
            /// # Examples
            ///
            /// ```
            #[doc = concat!(" use ", $doc_mod, "::", stringify!($Machine), ";")]
            ///
            /// // varint f1=1 (tag padded to two bytes) · LEN f2 [88 00]
            /// let msg = [0x88, 0x00, 0x01, 0x12, 0x02, 0x88, 0x00];
            #[doc = concat!(" let ", $noun, " = ", $door, ".unwrap();")]
            ///
            /// // Fidelity keeps the padded kept tag; the canonical face
            /// // re-emits it minimally. The undescended payload's bytes
            /// // are a declaration and ride opaque.
            #[doc = concat!(" assert_eq!(", $noun, ".save().unwrap(), msg);")]
            #[doc = concat!(" assert_eq!(", $noun, ".save_canonical().unwrap(), [0x08, 0x01, 0x12, 0x02, 0x88, 0x00]);")]
            /// ```
            pub fn save_canonical(&self) -> Result<Vec<u8>, SaveFault> {
                let (total, bodies) = self.canonical_size_pass()?;
                let mut out = Vec::new();
                out.try_reserve_exact(usize_of(total)).map_err(save_alloc)?;
                let mut emit = VecEmit { out: &mut out, doc: &self.source, run: None };
                let consumed = self.canonical_emit_pass(&mut emit, &bodies);
                assert!(
                    consumed == bodies.len() && out.len() == usize_of(total),
                    concat!($noun, " canonical save: sizing and emission disagree")
                );
                Ok(out)
            }

            #[doc = concat!(" [`", stringify!($Machine), "::save_canonical`]'s emission appended to `out`")]
            /// — existing content is untouched. The sizing walk runs
            /// first and the buffer grows by one exact fallible
            /// reservation, so the appends never regrow it.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::save_canonical`]. Every fault precedes the")]
            /// first write: on `Err`, `out` keeps its length and
            #[doc = concat!(" content, and the ", $noun, " is unchanged.")]
            ///
            /// # Panics
            ///
            /// If the canonical sizing and emit walks disagree — a
            /// library bug caught at the seam.
            ///
            /// # Examples
            ///
            /// ```
            #[doc = concat!(" use ", $doc_mod, "::", stringify!($Machine), ";")]
            ///
            /// // varint f1=1, value padded to two bytes.
            /// let msg = [0x08, 0x81, 0x00];
            #[doc = concat!(" let ", $noun, " = ", $door, ".unwrap();")]
            ///
            /// let mut out = vec![0xFF];
            #[doc = concat!(" ", $noun, ".save_canonical_into(&mut out).unwrap();")]
            /// assert_eq!(out, [0xFF, 0x08, 0x01]);
            /// ```
            pub fn save_canonical_into(&self, out: &mut Vec<u8>) -> Result<(), SaveFault> {
                let (total, bodies) = self.canonical_size_pass()?;
                out.try_reserve_exact(usize_of(total)).map_err(save_alloc)?;
                let start = out.len();
                let mut emit = VecEmit { out, doc: &self.source, run: None };
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
            /// through as windows of their backing, framing words ride a
            /// ten-byte stack window, and the concatenation is exactly
            #[doc = concat!(" [`", stringify!($Machine), "::save_canonical`]'s output.")]
            ///
            /// The sizing walk runs first and fronts every fault — the
            /// resource refusals included — so nothing can refuse once
            /// the first slice is handed over. A panic unwinding out of
            /// `sink` may leave already-handed slices with the caller,
            #[doc = concat!(" as any callback panic can; the ", $noun, " itself stays")]
            /// unchanged and reusable.
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
                let mut emit =
                    SinkEmit { doc: &self.source, sink: &mut sink, run: None, written: 0 };
                let consumed = self.canonical_emit_pass(&mut emit, &bodies);
                assert!(
                    consumed == bodies.len() && emit.written == u64::from(total),
                    concat!($noun, " canonical save: the sink walk covers the price")
                );
                Ok(())
            }
    };
    (@canonical $cap:ident tolerant, prod: $prod:ident, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            // ── canonical output ──

            /// The canonical walk's verdict for one row, every value
            /// resolved at judgment time. Stored widths are not output
            /// widths here — they remain the source-geometry proof that
            /// locates each value, prefix, and payload.
            fn settle_canonical(&self, row: &Row) -> CanonicalArm {
                let head = head_word(row.field, row.kind);
                let source = match row.edit {
                    Edit::Deleted(_)
                    | Edit::InsertedDeleted(_)
                    | Edit::Moved { .. }
                    | Edit::SourceRecordDeleted
                    | Edit::SourcePayloadDeleted(_)
                    | Edit::SourceInsertedDeleted(_)
                    | Edit::ImportedDeleted(_) => return CanonicalArm::Skip,
                    Edit::Replaced(value) | Edit::Inserted(value) => CanonicalSrc::Store(value),
                    // A designated payload is an opaque doc-zone subspan
                    // behind re-derived framing; a descended interior
                    // joins the commitment closure and recurses.
                    Edit::SourcePayload(src) | Edit::SourceInserted(src) => {
                        let (payload_at, len) = self.designated_payload(src);
                        return match row.slot() {
                            Slot::Opened(layer) => CanonicalArm::OpenLen {
                                head,
                                first: self.layer(layer).first,
                                // SAFETY: the designated subspan lies in
                                // the document zone, whose admitted end
                                // is inside the offset domain.
                                at: unsafe { At32::new_unchecked(payload_at) },
                            },
                            Slot::Unopened | Slot::Fault(_) => CanonicalArm::OpaqueLen {
                                head,
                                payload: CanonicalPayload::Doc { at: payload_at, len },
                            },
                        };
                    }
                    // An imported record re-emits minimally under the
                    // canonical standard: its met framing is decoded from
                    // the slot, never preserved.
                    Edit::Imported(value) => {
                        let bytes = self.import_slot(value);
                        let at = import_value_at(bytes);
                        return match row.kind {
                            RecordKind::Varint => CanonicalArm::Varint {
                                head,
                                word: match slice::value64(bytes, at, bytes.len()) {
                                    Ok((word, _)) => word,
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
                                payload: CanonicalPayload::Import(value),
                            },
                        };
                    }
                    // A local copy's rows canonicalize from their cloned
                    // geometry exactly like scanned rows: the closure
                    // re-emits minimally, opened interiors recurse.
                    Edit::Intact | Edit::SourceRecord => {
                        // The walk never crosses an effective authored
                        // payload, so no authored-zone row is reachable.
                        debug_assert!(!row.authored_zone(), "the canonical walk stays in the closure");
                        // SAFETY: these arms sit outside the Inserted and
                        // Imported families.
                        CanonicalSrc::Doc(unsafe { scanned_at(row) })
                    }
                };
                match row.kind {
                    RecordKind::Varint => CanonicalArm::Varint {
                        head,
                        word: match source {
                            CanonicalSrc::Store(v) => self.store.varint(v),
                            CanonicalSrc::Doc(at) => self.scan_varint(row, at),
                        },
                    },
                    RecordKind::I32 => CanonicalArm::I32 {
                        head,
                        value: match source {
                            CanonicalSrc::Store(v) => {
                                CanonicalValue::Store(Word::Bits32(self.store.bits32(v)))
                            }
                            CanonicalSrc::Doc(at) => {
                                CanonicalValue::Doc { at: scanned_value_at(at, row.tag_w()) }
                            }
                        },
                    },
                    RecordKind::I64 => CanonicalArm::I64 {
                        head,
                        value: match source {
                            CanonicalSrc::Store(v) => {
                                CanonicalValue::Store(Word::Bits64(self.store.bits64(v)))
                            }
                            CanonicalSrc::Doc(at) => {
                                CanonicalValue::Doc { at: scanned_value_at(at, row.tag_w()) }
                            }
                        },
                    },
                    RecordKind::Len => match source {
                        // An effective authored payload terminates the
                        // closure whatever rows a browse materialized.
                        CanonicalSrc::Store(value) => {
                            CanonicalArm::OpaqueLen { head, payload: CanonicalPayload::Store(value) }
                        }
                        CanonicalSrc::Doc(at) => match row.slot() {
                            Slot::Opened(layer) => CanonicalArm::OpenLen {
                                head,
                                first: self.layer(layer).first,
                                at,
                            },
                            // Unopened, faulted, or refused: the payload
                            // bytes are a declaration, not records — the
                            // closure ends here even when they happen to
                            // parse.
                            Slot::Unopened | Slot::Fault(_) => {
                                let (payload_at, len) = self.len_geometry(row, at);
                                CanonicalArm::OpaqueLen {
                                    head,
                                    payload: CanonicalPayload::Doc { at: payload_at, len },
                                }
                            }
                        },
                    },
                }
            }

            /// The canonical sizing walk: one complete pass over the
            /// materialized commitment closure, accumulating every
            /// opened LEN's canonical body bottom-up and recording it in
            /// walk order for the emit walk's prefixes. Every live row
            /// is visited — the walk follows visibility, not dirt, so a
            #[doc = concat!(" clean ", $noun, " still pays it in full. Body totals and the")]
            /// spine are call-local; nothing is cached in the machine.
            ///
            /// # Errors
            ///
            /// [`SaveFault::Resource`] on an allocator refusal for the
            /// walk's scratch, [`SaveFault::BodyOverCap`] when an opened
            /// LEN's canonical body outgrows the length class,
            /// [`SaveFault::DocOverCap`] when the canonical document
            /// outgrows the coordinate class.
            fn canonical_size_pass(&self) -> Result<(u32, Vec<u32>), SaveFault> {
                let mut bodies: Vec<u32> = Vec::new();
                let mut spine: Vec<CanonicalFrame> = Vec::new();
                let mut acc: u64 = 0;
                let mut cur = self.root.first;
                loop {
                    let Some(id) = cur else {
                        let Some(frame) = spine.pop() else { break };
                        let body = u32::try_from(acc)
                            .ok()
                            .and_then(PayloadLen::new)
                            .ok_or(SaveFault::BodyOverCap { at: frame.at.as_inner() })?;
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
                                CanonicalPayload::Store(value) => self.store.span(value).1,
                                CanonicalPayload::Import(value) => {
                                    crate::admission::admitted_u32(self.import_payload(value).len())
                                }
                            };
                            acc += u64::from(encoded_len32(head))
                                + u64::from(encoded_len32(len))
                                + u64::from(len);
                        }
                        CanonicalArm::OpenLen { head, first, at } => {
                            bodies.try_reserve(1).map_err(save_alloc)?;
                            spine.try_reserve(1).map_err(save_alloc)?;
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
                    .filter(|total| $crate::revise::groupless::revising_machine!(@in_cap $prod, total))
                    .ok_or(SaveFault::DocOverCap { total: acc })?;
                Ok((total, bodies))
            }

            /// The canonical emit walk: the sizing walk's twin, forward,
            /// writing into the prepaid output. Climbing out of opened
            /// LENs follows parent links — the spine is the arena itself.
            /// Returns the count of body slots consumed, for the faces'
            /// seam assertion.
            fn canonical_emit_pass<O: Out>(&self, emit: &mut O, bodies: &[u32]) -> usize {
                let mut body_cursor = 0;
                let mut open: Option<RowId> = None;
                let mut cur = self.root.first;
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
                            emit.value(Word::Varint(word));
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
                                    emit.varint(u64::from(self.store.span(value).1));
                                    emit.bytes(self.store.span_bytes(value));
                                }
                                CanonicalPayload::Import(value) => {
                                    let payload = self.import_payload(value);
                                    emit.varint(u64::from(crate::admission::admitted_u32(
                                        payload.len(),
                                    )));
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
            /// into a fresh, exactly reserved `Vec<u8>`: minimally emits
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
            /// LEN payload and every effective authored payload
            /// terminate the closure and ride byte-for-byte behind
            /// re-derived framing, even when those bytes happen to
            /// parse. Values, field order, duplicates, liveness, and
            /// the fixed-width bits are untouched.
            ///
            /// The face reads `&self` and caches nothing: body totals
            /// and the sizing spine are call-local, so
            #[doc = concat!(" [`pending`](", stringify!($Machine), "::pending), every status, source spans, the undo")]
            /// log, and the ordinary fidelity save read identically
            /// before and after the call. The ordinary
            /// [`save`](Self::save) family answers byte-fidelity
            /// instead; both re-ingest under `Tolerant`, and this
            /// family's output additionally closes under the dialect
            /// validator's `CanonicalMinimal` standard.
            ///
            /// # Errors
            ///
            /// [`SaveFault::Resource`] when the allocator refuses the
            /// sizing scratch or the output reservation,
            /// [`SaveFault::BodyOverCap`] when an opened LEN's canonical
            /// body outgrows the length class, [`SaveFault::DocOverCap`]
            /// when the canonical document outgrows the coordinate
            /// class. Canonical totals never exceed fidelity totals, so
            /// a state whose fidelity save is in class cannot meet the
            #[doc = concat!(" cap faults here. On `Err` the ", $noun, " is unchanged and")]
            /// the save may be retried.
            ///
            /// # Panics
            ///
            /// If the canonical sizing and emit walks disagree — a
            /// library bug caught at the seam.
            ///
            /// # Examples
            ///
            /// ```
            #[doc = concat!(" use ", $doc_mod, "::", stringify!($Machine), ";")]
            ///
            /// // varint f1=1 (tag padded to two bytes) · LEN f2 [88 00]
            /// let msg = [0x88, 0x00, 0x01, 0x12, 0x02, 0x88, 0x00];
            #[doc = concat!(" let ", $noun, " = ", $door, ".unwrap();")]
            ///
            /// // Fidelity keeps the padded kept tag; the canonical face
            /// // re-emits it minimally. The undescended payload's bytes
            /// // are a declaration and ride opaque.
            #[doc = concat!(" assert_eq!(", $noun, ".save().unwrap(), msg);")]
            #[doc = concat!(" assert_eq!(", $noun, ".save_canonical().unwrap(), [0x08, 0x01, 0x12, 0x02, 0x88, 0x00]);")]
            /// ```
            pub fn save_canonical(&self) -> Result<Vec<u8>, SaveFault> {
                let (total, bodies) = self.canonical_size_pass()?;
                let mut out = Vec::new();
                out.try_reserve_exact(usize_of(total)).map_err(save_alloc)?;
                let mut emit = VecEmit { out: &mut out, doc: &self.source, run: None };
                let consumed = self.canonical_emit_pass(&mut emit, &bodies);
                assert!(
                    consumed == bodies.len() && out.len() == usize_of(total),
                    concat!($noun, " canonical save: sizing and emission disagree")
                );
                Ok(out)
            }

            #[doc = concat!(" [`", stringify!($Machine), "::save_canonical`]'s emission appended to `out`")]
            /// — existing content is untouched. The sizing walk runs
            /// first and the buffer grows by one exact fallible
            /// reservation, so the appends never regrow it.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::save_canonical`]. Every fault precedes the")]
            /// first write: on `Err`, `out` keeps its length and
            #[doc = concat!(" content, and the ", $noun, " is unchanged.")]
            ///
            /// # Panics
            ///
            /// If the canonical sizing and emit walks disagree — a
            /// library bug caught at the seam.
            ///
            /// # Examples
            ///
            /// ```
            #[doc = concat!(" use ", $doc_mod, "::", stringify!($Machine), ";")]
            ///
            /// // varint f1=1, value padded to two bytes.
            /// let msg = [0x08, 0x81, 0x00];
            #[doc = concat!(" let ", $noun, " = ", $door, ".unwrap();")]
            ///
            /// let mut out = vec![0xFF];
            #[doc = concat!(" ", $noun, ".save_canonical_into(&mut out).unwrap();")]
            /// assert_eq!(out, [0xFF, 0x08, 0x01]);
            /// ```
            pub fn save_canonical_into(&self, out: &mut Vec<u8>) -> Result<(), SaveFault> {
                let (total, bodies) = self.canonical_size_pass()?;
                out.try_reserve_exact(usize_of(total)).map_err(save_alloc)?;
                let start = out.len();
                let mut emit = VecEmit { out, doc: &self.source, run: None };
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
            /// through as windows of their backing, framing words ride a
            /// ten-byte stack window, and the concatenation is exactly
            #[doc = concat!(" [`", stringify!($Machine), "::save_canonical`]'s output.")]
            ///
            /// The sizing walk runs first and fronts every fault — the
            /// resource refusals included — so nothing can refuse once
            /// the first slice is handed over. A panic unwinding out of
            /// `sink` may leave already-handed slices with the caller,
            #[doc = concat!(" as any callback panic can; the ", $noun, " itself stays")]
            /// unchanged and reusable.
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
                let mut emit =
                    SinkEmit { doc: &self.source, sink: &mut sink, run: None, written: 0 };
                let consumed = self.canonical_emit_pass(&mut emit, &bodies);
                assert!(
                    consumed == bodies.len() && emit.written == u64::from(total),
                    concat!($noun, " canonical save: the sink walk covers the price")
                );
                Ok(())
            }
    };
    (@core_transfer_readers plain, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {};
    (@core_transfer_readers $cap:ident, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// The designated row's source payload subspan: offset and
            /// length in the document zone. Designation gates admit
            /// scanned LENs alone, and geometry columns never change
            /// after the scan, so the answer holds for the machine's
            /// whole life whatever edits later land on the row.
            fn designated_payload(&self, src: RowId) -> (u32, u32) {
                let row = self.row(src);
                // SAFETY: designation gates admit rows outside the
                // Inserted family alone, and the scan records offsets.
                let at = unsafe { scanned_at(row) };
                self.len_geometry(row, at)
            }

            /// The designated row's source payload bytes.
            fn designated_bytes(&self, src: RowId) -> &[u8] {
                let (at, len) = self.designated_payload(src);
                let start = usize_of(at);
                // SAFETY: the scan judged the payload extent inside the
                // sealed document zone.
                unsafe { self.backing(self.row(src)).get_unchecked(start..start + usize_of(len)) }
            }

            /// An imported record's exact bytes — the store span the
            /// import registered.
            fn import_slot(&self, value: ValueAt) -> &[u8] {
                self.store.span_bytes(value)
            }

            /// The payload subspan inside an imported LEN's bytes.
            /// Imported designations are structurally complete, so the
            /// bounded reads cannot refuse.
            fn import_payload(&self, value: ValueAt) -> &[u8] {
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
    (@core_transfer_faces plain, pay: $pay:ident, acc: $acc:ident, pay_lt: [$($plt:lifetime)?], Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {};
    (@zone_gate plain, $self:ident, $row:ident) => { $row.authored_zone() };
    (@zone_gate $cap:ident, $self:ident, $row:ident) => {
        $row.authored_zone() && !$self.import_zone_row($row)
    };
    (@import_first_class transfer) => { true };
    (@import_zone transfer copy, Machine: $Machine:ident) => {
            /// The import zone and the slot's window base inside it: the
            /// copy column is one sealed zone, so import windows use
            /// zone-global offsets.
            fn import_zone(&self, value: ValueAt) -> (&[u8], u32) {
                (self.store.zone(), self.store.span(value).0)
            }
    };
    (@import_zone transfer borrow, Machine: $Machine:ident) => {
            /// The import zone and the slot's window base inside it: each
            /// import slot is its own sealed zone, so import windows are
            /// slot-relative.
            fn import_zone(&self, value: ValueAt) -> (&[u8], u32) {
                (self.store.span_bytes(value), 0)
            }
    };
    (@import_zone $cap:ident $pay:ident, Machine: $Machine:ident) => {};
    (@import_zone_row plain, Machine: $Machine:ident) => {};
    (@import_zone_row $cap:ident, Machine: $Machine:ident) => {
            /// True when the row's backing zone is an import slot: the
            /// nearest slot-bearing ancestor is an import root. Interiors
            /// installed under a replaced or authored payload climb to
            /// that payload's own slot first, so they stay browse-only;
            /// only rows the transfer profile marked first-class (the
            /// alias flag over an authored zone) can answer true.
            fn import_zone_row(&self, row: &Row) -> bool {
                if !row.alias() {
                    return false;
                }
                let mut cur = row;
                loop {
                    let parent = match cur.parent {
                        Some(id) => self.row(id),
                        None => return false,
                    };
                    match parent.edit {
                        Edit::Imported(_) | Edit::ImportedDeleted(_) => return true,
                        Edit::Replaced(_)
                        | Edit::Deleted(Some(_))
                        | Edit::Inserted(_)
                        | Edit::InsertedDeleted(_) => return false,
                        _ => cur = parent,
                    }
                }
            }
    };
    (@core_transfer_faces $cap:ident, pay: $pay:ident, acc: $acc:ident, pay_lt: [$($plt:lifetime)?], Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            // ── source transfer ──

            /// The gap a proven plan names: the row that will follow the
            /// splice.
            fn plan_next(&self, plan: &InsertPlan) -> Option<RowId> {
                plan.prev
                    .map_or_else(|| self.holding_layer(plan.parent).first, |prev| self.row(prev).next)
            }

            /// Splices a prebuilt transfer row without logging — the
            /// move's destination side, whose one transition lives on
            /// the source (the row is born its own ghost; entering
            /// `Moved` awakens it). Every reservation holds.
            fn splice_ghost(&mut self, plan: &InsertPlan, id: RowId, row: Row) {
                let next = row.next;
                // The reservation in the command covers this push.
                self.rows.push(row);
                match plan.prev {
                    Some(prev) => self.row_mut(prev).next = Some(id),
                    None => self.holding_layer_mut(plan.parent).first = Some(id),
                }
                if next.is_none() {
                    self.holding_layer_mut(plan.parent).last = Some(id);
                }
            }

            /// Splices, logs, and awakens a transfer row (the infallible
            /// suffix of the copy commands: every reservation holds).
            /// Born as its own ghost, one logged transition awakens it —
            /// reverting the birth ghosts it again.
            fn apply_transfer(&mut self, plan: &InsertPlan, id: RowId, row: Row, live: Edit) {
                let ghost = row.edit;
                self.splice_ghost(plan, id, row);
                self.log_push(id, ghost);
                self.write_state(id, live);
            }

            /// The transfer faces' source witness: the row is an
            /// original admitted occurrence. A pending edit does not
            /// block a copy — the designation names the source reading —
            /// while suppressed, authored, copied, and imported rows
            /// refuse.
            #[track_caller]
            fn transfer_source(&self, source: Handle) -> Result<Row, EditFault> {
                let row = *gate(&self.rows, source);
                if row.dead() {
                    return Err(EditFault::DeadHandle);
                }
                if row.authored_zone()
                    || row.alias()
                    || !matches!(
                        row.edit,
                        Edit::Intact
                            | Edit::Replaced(_)
                            | Edit::Deleted(_)
                            | Edit::SourcePayload(_)
                            | Edit::SourcePayloadDeleted(_)
                    )
                {
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
                if !matches!(row.edit, Edit::Intact) || row.dirty() {
                    return Err(EditFault::SourceModified);
                }
                Ok(row)
            }

            /// Refuses a destination gap owned by the moved record's own
            /// subtree: with the source suppressed, such a gap has no
            /// emitted owner. A gap right after the source resolves into
            /// the parent's chain and stays lawful.
            fn move_gap_gate(&self, plan: &InsertPlan, source: RowId) -> Result<(), EditFault> {
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
            /// own pending state. The copy is output-authored: its
            /// status reads `Inserted`, it answers no source span, and
            /// it does not designate; its interior starts opaque, and a
            #[doc = concat!(" later [`", stringify!($Machine), "::descend`] parses the retained")]
            /// source-backed bytes into first-class editable rows. Zero
            /// payload bytes stage; one command, one pending step.
            ///
            /// # Errors
            ///
            /// [`EditFault::DeadHandle`] for an orphaned source,
            /// [`EditFault::SourceNotBacked`] when `source` is not an
            /// original source occurrence, the anchor gates of
            #[doc = concat!(" [`", stringify!($Machine), "::insert_varint`], and")]
            /// [`EditFault::Resource`]/[`EditFault::IndexSpaceExhausted`]
            #[doc = concat!(" when the row or log cannot grow. On any `Err` the ", $noun)]
            /// is unchanged.
            ///
            /// # Panics
            ///
            /// Panics if a handle inside the arguments was not minted by
            #[doc = concat!(" this ", $noun, " (the arena index contract).")]
            ///
            /// # Examples
            ///
            /// ```
            #[doc = concat!(" use ", $doc_mod, "::{InsertAt, ", stringify!($Machine), "};")]
            ///
            /// // varint f1=5 · varint f2=6; copy f1 to the tail, then
            /// // revert the one step.
            /// let msg = [0x08, 0x05, 0x10, 0x06];
            #[doc = concat!(" let mut ", $noun, " = ", $door, ".unwrap();")]
            #[doc = concat!(" let first = ", $noun, ".top().next().unwrap();")]
            #[doc = concat!(" ", $noun, ".copy_record(first, InsertAt::TailOf(None)).unwrap();")]
            #[doc = concat!(" assert_eq!(", $noun, ".save().unwrap()[..], [0x08, 0x05, 0x10, 0x06, 0x08, 0x05]);")]
            #[doc = concat!(" assert_eq!(", $noun, ".pending(), 1);")]
            #[doc = concat!(" ", $noun, ".revert();")]
            #[doc = concat!(" assert_eq!(", $noun, ".save().unwrap()[..], msg);")]
            /// ```
            #[track_caller]
            pub fn copy_record(&mut self, source: Handle, at: InsertAt) -> Result<Handle, EditFault> {
                let src = self.transfer_source(source)?;
                let plan = self.resolve_anchor(at)?;
                let id = self.mint_insert()?;
                self.rows.try_reserve(1).map_err(edit_resource)?;
                self.log.try_reserve(1).map_err(edit_resource)?;
                let next = self.plan_next(&plan);
                self.apply_transfer(
                    &plan,
                    id,
                    src.cloned_alias(plan.parent, next),
                    Edit::SourceRecord,
                );
                Ok(Handle(id))
            }

            /// Moves the designated record to the anchor: one atomic
            #[doc = concat!(" command equal to [`", stringify!($Machine), "::copy_record`] plus suppression")]
            /// of the original occurrence — the exact source bytes emit
            /// at the destination and nowhere else. One pending step:
            #[doc = concat!(" [`", stringify!($Machine), "::pending`] grows by one, and one")]
            #[doc = concat!(" [`", stringify!($Machine), "::revert`] restores the source and ghosts the")]
            /// destination alias (later commands on the alias sit above
            /// the move in the log, so they unwind first).
            ///
            /// # Errors
            ///
            /// [`EditFault::DeadHandle`] for an orphaned source,
            /// [`EditFault::SourceNotBacked`] when `source` is not an
            /// original source occurrence,
            /// [`EditFault::SourceModified`] when its current subtree is
            /// not the source reading (a replacement, deletion, or
            /// interior edit sits on it — relocating would silently
            /// discard that edit), [`EditFault::MoveIntoSource`] when
            /// the destination gap is owned by the moved record's own
            /// subtree, the anchor gates of
            #[doc = concat!(" [`", stringify!($Machine), "::insert_varint`], and")]
            /// [`EditFault::Resource`]/[`EditFault::IndexSpaceExhausted`]
            #[doc = concat!(" when the row or log cannot grow. On any `Err` the ", $noun)]
            /// is unchanged.
            ///
            /// # Panics
            ///
            /// Panics if a handle inside the arguments was not minted by
            #[doc = concat!(" this ", $noun, " (the arena index contract).")]
            ///
            /// # Examples
            ///
            /// ```
            #[doc = concat!(" use ", $doc_mod, "::{EditStatus, InsertAt, ", stringify!($Machine), "};")]
            ///
            /// // varint f1=5 · varint f2=6; move f1 after f2 — one
            /// // pending step, one revert restores everything.
            /// let msg = [0x08, 0x05, 0x10, 0x06];
            #[doc = concat!(" let mut ", $noun, " = ", $door, ".unwrap();")]
            #[doc = concat!(" let tops: Vec<_> = ", $noun, ".top().collect();")]
            #[doc = concat!(" let dest = ", $noun, ".move_record(tops[0], InsertAt::After(tops[1])).unwrap();")]
            #[doc = concat!(" assert_eq!(", $noun, ".pending(), 1);")]
            #[doc = concat!(" assert_eq!(", $noun, ".status(tops[0]).unwrap(), EditStatus::Moved);")]
            #[doc = concat!(" assert_eq!(", $noun, ".save().unwrap()[..], [0x10, 0x06, 0x08, 0x05]);")]
            ///
            #[doc = concat!(" assert_eq!(", $noun, ".revert(), Some(tops[0]));")]
            #[doc = concat!(" assert_eq!(", $noun, ".status(dest).unwrap(), EditStatus::InsertedDeleted);")]
            #[doc = concat!(" assert_eq!(", $noun, ".save().unwrap()[..], msg);")]
            /// ```
            #[track_caller]
            pub fn move_record(&mut self, source: Handle, at: InsertAt) -> Result<Handle, EditFault> {
                let src = self.move_source(source)?;
                let plan = self.resolve_anchor(at)?;
                self.move_gap_gate(&plan, source.0)?;
                let id = self.mint_insert()?;
                self.rows.try_reserve(1).map_err(edit_resource)?;
                self.log.try_reserve(1).map_err(edit_resource)?;
                let next = self.plan_next(&plan);
                self.splice_ghost(&plan, id, src.cloned_alias(plan.parent, next));
                self.apply_move(source.0, id);
                Ok(Handle(id))
            }

            /// Copies the designated LEN's payload interior to the
            /// target: a replacement keeps the target's own tag verbatim
            /// (and its prefix too while the length is unchanged), an
            /// insertion authors the supplied field's tag and prefix
            /// minimally — only the interior bytes are the source's, and
            /// they ride byte-exact. Zero payload bytes stage: the state
            /// stores the designation, resolved against the machine's
            /// own source at every read and save. One command, one
            /// pending step.
            ///
            /// # Errors
            ///
            /// [`EditFault::DeadHandle`] for an orphaned source,
            /// [`EditFault::KindMismatch`] unless `source` is a LEN,
            /// [`EditFault::SourceNotBacked`] when it is not an original
            /// source occurrence, plus the target's own gates
            #[doc = concat!(" ([`", stringify!($Machine), "::set_payload`]'s for a replacement,")]
            #[doc = concat!(" [`", stringify!($Machine), "::insert_varint`]'s anchor gates for an")]
            #[doc = concat!(" insertion). On any `Err` the ", $noun, " is unchanged.")]
            ///
            /// # Panics
            ///
            /// Panics if a handle inside the arguments was not minted by
            #[doc = concat!(" this ", $noun, " (the arena index contract).")]
            ///
            /// # Examples
            ///
            /// ```
            #[doc = concat!(" use ", $doc_mod, "::{PayloadTarget, ", stringify!($Machine), "};")]
            ///
            /// // LEN f1 "hi" · LEN f2 "no": replace f2's payload with
            /// // f1's, then revert the one step.
            /// let msg = [0x0A, 0x02, 0x68, 0x69, 0x12, 0x02, 0x6E, 0x6F];
            #[doc = concat!(" let mut ", $noun, " = ", $door, ".unwrap();")]
            #[doc = concat!(" let tops: Vec<_> = ", $noun, ".top().collect();")]
            #[doc = concat!(" ", $noun, ".copy_payload(tops[0], PayloadTarget::Replace(tops[1])).unwrap();")]
            #[doc = concat!(" assert_eq!(", $noun, ".save().unwrap()[..], [0x0A, 0x02, 0x68, 0x69, 0x12, 0x02, 0x68, 0x69]);")]
            #[doc = concat!(" ", $noun, ".revert();")]
            #[doc = concat!(" assert_eq!(", $noun, ".save().unwrap()[..], msg);")]
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
                match target {
                    PayloadTarget::Replace(handle) => {
                        self.value_gate(handle, RecordKind::Len)?;
                        self.interior_gate(handle.0)?;
                        self.log.try_reserve(1).map_err(edit_resource)?;
                        self.apply_edit(handle.0, Edit::SourcePayload(source.0));
                        Ok(handle)
                    }
                    PayloadTarget::Insert { at, field } => {
                        let plan = self.resolve_anchor(at)?;
                        let id = self.mint_insert()?;
                        self.rows.try_reserve(1).map_err(edit_resource)?;
                        self.log.try_reserve(1).map_err(edit_resource)?;
                        let next = self.plan_next(&plan);
                        self.apply_transfer(
                            &plan,
                            id,
                            Row::transfer_authored(
                                field,
                                RecordKind::Len,
                                plan.parent,
                                next,
                                Edit::SourceInsertedDeleted(source.0),
                            ),
                            Edit::SourceInserted(source.0),
                        );
                        Ok(Handle(id))
                    }
                }
            }

            /// Moves the designated LEN's payload interior to a fresh
            /// record at the anchor: one atomic command equal to
            #[doc = concat!(" [`", stringify!($Machine), "::copy_payload`]'s insertion form plus")]
            /// suppression of the whole source record — removing only
            /// the payload would leave a tag and prefix with no lawful
            /// meaning. The fresh record authors `field`'s tag and
            /// prefix minimally; the interior rides byte-exact, zero
            /// bytes staged. One pending step; one revert restores the
            /// source and ghosts the destination.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::move_record`], plus")]
            /// [`EditFault::KindMismatch`] unless `source` is a LEN.
            #[doc = concat!(" On any `Err` the ", $noun, " is unchanged.")]
            ///
            /// # Panics
            ///
            /// Panics if a handle inside the arguments was not minted by
            #[doc = concat!(" this ", $noun, " (the arena index contract).")]
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
                self.rows.try_reserve(1).map_err(edit_resource)?;
                self.log.try_reserve(1).map_err(edit_resource)?;
                let next = self.plan_next(&plan);
                self.splice_ghost(
                    &plan,
                    id,
                    Row::transfer_authored(
                        field,
                        RecordKind::Len,
                        plan.parent,
                        next,
                        Edit::SourceInsertedDeleted(source.0),
                    ),
                );
                self.apply_move(source.0, id);
                Ok(Handle(id))
            }

            $crate::revise::groupless::revising_machine!(@transfer_import $pay $acc $(<$plt>)?, Machine: $Machine, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod);
    };
    (@core_status plain, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// The record's edit status.
            ///
            /// # Errors
            ///
            /// [`EditFault::DeadHandle`] for an orphaned row.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the")]
            /// arena index contract).
            #[inline]
            #[track_caller]
            pub fn status(&self, handle: Handle) -> Result<EditStatus, EditFault> {
                Ok(match self.live(handle)?.edit {
                    Edit::Intact => EditStatus::Intact,
                    Edit::Replaced(_) => EditStatus::Replaced,
                    Edit::Deleted(_) => EditStatus::Deleted,
                    Edit::Inserted(_) => EditStatus::Inserted,
                    Edit::InsertedDeleted(_) => EditStatus::InsertedDeleted,
                })
            }
    };
    (@core_status $cap:ident, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// The record's edit status.
            ///
            /// # Errors
            ///
            /// [`EditFault::DeadHandle`] for an orphaned row.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the")]
            /// arena index contract).
            #[inline]
            #[track_caller]
            pub fn status(&self, handle: Handle) -> Result<EditStatus, EditFault> {
                let row = self.live(handle)?;
                // Rows of a copy's retained interior are output-authored
                // whatever their internal state.
                if row.alias() && matches!(row.edit, Edit::Intact | Edit::Replaced(_)) {
                    return Ok(EditStatus::Inserted);
                }
                if row.alias() && matches!(row.edit, Edit::Deleted(_)) {
                    return Ok(EditStatus::InsertedDeleted);
                }
                Ok(match row.edit {
                    Edit::Intact => EditStatus::Intact,
                    Edit::Replaced(_) => EditStatus::Replaced,
                    Edit::Deleted(_) => EditStatus::Deleted,
                    Edit::SourcePayload(_) => EditStatus::Replaced,
                    Edit::Inserted(_)
                    | Edit::SourceRecord
                    | Edit::SourceInserted(_)
                    | Edit::Imported(_) => EditStatus::Inserted,
                    Edit::InsertedDeleted(_)
                    | Edit::SourceRecordDeleted
                    | Edit::SourceInsertedDeleted(_)
                    | Edit::ImportedDeleted(_) => EditStatus::InsertedDeleted,
                    Edit::SourcePayloadDeleted(_) => EditStatus::Deleted,
                    Edit::Moved { .. } => EditStatus::Moved,
                })
            }
    };
    (@core_value_reads plain, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// The varint record's current word (the pending replacement
            /// if one is set, otherwise the scanned value).
            ///
            /// # Errors
            ///
            /// [`EditFault::DeadHandle`] for an orphaned row,
            /// [`EditFault::KindMismatch`] off the varint kind.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the")]
            /// arena index contract).
            #[inline]
            #[track_caller]
            pub fn varint_word(&self, handle: Handle) -> Result<u64, EditFault> {
                let row = self.live(handle)?;
                if !matches!(row.kind, RecordKind::Varint) {
                    return Err(EditFault::KindMismatch { have: row.kind });
                }
                Ok(row.edit.effective().map_or_else(
                    // SAFETY: `effective()` returned None, so the edit is
                    // Intact or Deleted(None) — outside the Inserted family.
                    || self.scan_varint(row, unsafe { scanned_at(row) }),
                    |v| self.store.varint(v),
                ))
            }

            /// The fixed 32-bit record's current bits.
            ///
            /// # Errors
            ///
            /// [`EditFault::DeadHandle`] for an orphaned row,
            /// [`EditFault::KindMismatch`] off the I32 kind.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the")]
            /// arena index contract).
            #[inline]
            #[track_caller]
            pub fn i32_bits(&self, handle: Handle) -> Result<u32, EditFault> {
                let row = self.live(handle)?;
                if !matches!(row.kind, RecordKind::I32) {
                    return Err(EditFault::KindMismatch { have: row.kind });
                }
                Ok(row.edit.effective().map_or_else(
                    // SAFETY: `effective()` returned None, so the edit is
                    // Intact or Deleted(None) — outside the Inserted family.
                    || self.scan_bits32(row, unsafe { scanned_at(row) }),
                    |v| self.store.bits32(v),
                ))
            }

            /// The fixed 64-bit record's current bits.
            ///
            /// # Errors
            ///
            /// [`EditFault::DeadHandle`] for an orphaned row,
            /// [`EditFault::KindMismatch`] off the I64 kind.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the")]
            /// arena index contract).
            #[inline]
            #[track_caller]
            pub fn i64_bits(&self, handle: Handle) -> Result<u64, EditFault> {
                let row = self.live(handle)?;
                if !matches!(row.kind, RecordKind::I64) {
                    return Err(EditFault::KindMismatch { have: row.kind });
                }
                Ok(row.edit.effective().map_or_else(
                    // SAFETY: `effective()` returned None, so the edit is
                    // Intact or Deleted(None) — outside the Inserted family.
                    || self.scan_bits64(row, unsafe { scanned_at(row) }),
                    |v| self.store.bits64(v),
                ))
            }

            /// The LEN record's current payload bytes (readable whatever
            /// the descend verdict was).
            ///
            /// # Errors
            ///
            /// [`EditFault::DeadHandle`] for an orphaned row,
            /// [`EditFault::KindMismatch`] off the LEN kind.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the")]
            /// arena index contract).
            #[inline]
            #[track_caller]
            pub fn payload_bytes(&self, handle: Handle) -> Result<&[u8], EditFault> {
                let row = self.live(handle)?;
                if !matches!(row.kind, RecordKind::Len) {
                    return Err(EditFault::KindMismatch { have: row.kind });
                }
                Ok(row.edit.effective().map_or_else(
                    || {
                        // SAFETY: this arm matched an edit outside the
                        // Inserted family.
                        let (at, len) = self.len_geometry(row, unsafe { scanned_at(row) });
                        let start = usize_of(at);
                        // SAFETY: the scan judged the payload extent inside
                        // the sealed zone.
                        unsafe { self.backing(row).get_unchecked(start..start + usize_of(len)) }
                    },
                    |v| self.store.span_bytes(v),
                ))
            }
    };
    (@core_value_reads $cap:ident, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// The varint record's current word (the pending replacement
            /// if one is set, otherwise the scanned value).
            ///
            /// # Errors
            ///
            /// [`EditFault::DeadHandle`] for an orphaned row,
            /// [`EditFault::KindMismatch`] off the varint kind.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the")]
            /// arena index contract).
            #[inline]
            #[track_caller]
            pub fn varint_word(&self, handle: Handle) -> Result<u64, EditFault> {
                let row = self.live(handle)?;
                if !matches!(row.kind, RecordKind::Varint) {
                    return Err(EditFault::KindMismatch { have: row.kind });
                }
                Ok(match row.edit {
                    Edit::Replaced(v)
                    | Edit::Deleted(Some(v))
                    | Edit::Inserted(v)
                    | Edit::InsertedDeleted(v) => self.store.varint(v),
                    Edit::Imported(v) | Edit::ImportedDeleted(v) => {
                        let bytes = self.import_slot(v);
                        match slice::value64(bytes, import_value_at(bytes), bytes.len()) {
                            Ok((value, _)) => value,
                            Err(_) => unreachable!("imported records are structurally complete"),
                        }
                    }
                    Edit::SourcePayload(_)
                    | Edit::SourcePayloadDeleted(_)
                    | Edit::SourceInserted(_)
                    | Edit::SourceInsertedDeleted(_) => {
                        unreachable!("payload designations land on LEN rows alone")
                    }
                    // SAFETY: the remaining states sit outside the
                    // Inserted and Imported families, whose rows alone
                    // lack offsets.
                    Edit::Intact
                    | Edit::Deleted(None)
                    | Edit::Moved { .. }
                    | Edit::SourceRecord
                    | Edit::SourceRecordDeleted => {
                        self.scan_varint(row, unsafe { scanned_at(row) })
                    }
                })
            }

            /// The fixed 32-bit record's current bits.
            ///
            /// # Errors
            ///
            /// [`EditFault::DeadHandle`] for an orphaned row,
            /// [`EditFault::KindMismatch`] off the I32 kind.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the")]
            /// arena index contract).
            #[inline]
            #[track_caller]
            pub fn i32_bits(&self, handle: Handle) -> Result<u32, EditFault> {
                let row = self.live(handle)?;
                if !matches!(row.kind, RecordKind::I32) {
                    return Err(EditFault::KindMismatch { have: row.kind });
                }
                Ok(match row.edit {
                    Edit::Replaced(v)
                    | Edit::Deleted(Some(v))
                    | Edit::Inserted(v)
                    | Edit::InsertedDeleted(v) => self.store.bits32(v),
                    Edit::Imported(v) | Edit::ImportedDeleted(v) => {
                        let bytes = self.import_slot(v);
                        let at = import_value_at(bytes);
                        let Ok(value) = bytes[at..at + 4].try_into() else {
                            unreachable!("imported records are structurally complete")
                        };
                        u32::from_le_bytes(value)
                    }
                    Edit::SourcePayload(_)
                    | Edit::SourcePayloadDeleted(_)
                    | Edit::SourceInserted(_)
                    | Edit::SourceInsertedDeleted(_) => {
                        unreachable!("payload designations land on LEN rows alone")
                    }
                    // SAFETY: the remaining states sit outside the
                    // Inserted and Imported families, whose rows alone
                    // lack offsets.
                    Edit::Intact
                    | Edit::Deleted(None)
                    | Edit::Moved { .. }
                    | Edit::SourceRecord
                    | Edit::SourceRecordDeleted => {
                        self.scan_bits32(row, unsafe { scanned_at(row) })
                    }
                })
            }

            /// The fixed 64-bit record's current bits.
            ///
            /// # Errors
            ///
            /// [`EditFault::DeadHandle`] for an orphaned row,
            /// [`EditFault::KindMismatch`] off the I64 kind.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the")]
            /// arena index contract).
            #[inline]
            #[track_caller]
            pub fn i64_bits(&self, handle: Handle) -> Result<u64, EditFault> {
                let row = self.live(handle)?;
                if !matches!(row.kind, RecordKind::I64) {
                    return Err(EditFault::KindMismatch { have: row.kind });
                }
                Ok(match row.edit {
                    Edit::Replaced(v)
                    | Edit::Deleted(Some(v))
                    | Edit::Inserted(v)
                    | Edit::InsertedDeleted(v) => self.store.bits64(v),
                    Edit::Imported(v) | Edit::ImportedDeleted(v) => {
                        let bytes = self.import_slot(v);
                        let at = import_value_at(bytes);
                        let Ok(value) = bytes[at..at + 8].try_into() else {
                            unreachable!("imported records are structurally complete")
                        };
                        u64::from_le_bytes(value)
                    }
                    Edit::SourcePayload(_)
                    | Edit::SourcePayloadDeleted(_)
                    | Edit::SourceInserted(_)
                    | Edit::SourceInsertedDeleted(_) => {
                        unreachable!("payload designations land on LEN rows alone")
                    }
                    // SAFETY: the remaining states sit outside the
                    // Inserted and Imported families, whose rows alone
                    // lack offsets.
                    Edit::Intact
                    | Edit::Deleted(None)
                    | Edit::Moved { .. }
                    | Edit::SourceRecord
                    | Edit::SourceRecordDeleted => {
                        self.scan_bits64(row, unsafe { scanned_at(row) })
                    }
                })
            }

            /// The LEN record's current payload bytes (readable whatever
            /// the descend verdict was).
            ///
            /// # Errors
            ///
            /// [`EditFault::DeadHandle`] for an orphaned row,
            /// [`EditFault::KindMismatch`] off the LEN kind.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the")]
            /// arena index contract).
            #[inline]
            #[track_caller]
            pub fn payload_bytes(&self, handle: Handle) -> Result<&[u8], EditFault> {
                let row = self.live(handle)?;
                if !matches!(row.kind, RecordKind::Len) {
                    return Err(EditFault::KindMismatch { have: row.kind });
                }
                Ok(match row.edit {
                    Edit::Replaced(v)
                    | Edit::Deleted(Some(v))
                    | Edit::Inserted(v)
                    | Edit::InsertedDeleted(v) => self.store.span_bytes(v),
                    Edit::SourcePayload(src)
                    | Edit::SourcePayloadDeleted(src)
                    | Edit::SourceInserted(src)
                    | Edit::SourceInsertedDeleted(src) => self.designated_bytes(src),
                    Edit::Imported(v) | Edit::ImportedDeleted(v) => self.import_payload(v),
                    Edit::Intact
                    | Edit::Deleted(None)
                    | Edit::Moved { .. }
                    | Edit::SourceRecord
                    | Edit::SourceRecordDeleted => {
                        // SAFETY: these states sit outside the Inserted
                        // and Imported families, whose rows alone lack
                        // offsets.
                        let (at, len) = self.len_geometry(row, unsafe { scanned_at(row) });
                        let start = usize_of(at);
                        // SAFETY: the scan judged the payload extent inside
                        // the sealed zone.
                        unsafe { self.backing(row).get_unchecked(start..start + usize_of(len)) }
                    }
                })
            }
    };
    (@core_seal_scan plain, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// Publishes a freshly scanned interior: mints the source run
            /// (source-backed, non-empty layers only) and the layer
            /// descriptor, then seals the slot last — an `Err` from either
            /// reservation leaves the container unopened, and the caller
            /// discards the provisional tables.
            fn seal_scan(
                &mut self,
                id: RowId,
                first: Option<RowId>,
                last: Option<RowId>,
                authored: bool,
            ) -> Result<(), EditFault> {
                let source = match (authored, first) {
                    (false, Some(run_first)) => {
                        self.source_runs.try_reserve(1).map_err(edit_resource)?;
                        let run = u32::try_from(self.source_runs.len())
                            .ok()
                            .and_then(SourceRunId::new)
                            .ok_or(EditFault::IndexSpaceExhausted)?;
                        self.source_runs.push(SourceRun { first: run_first, end: arena_end(&self.rows) });
                        Some(run)
                    }
                    _ => None,
                };
                self.layers.try_reserve(1).map_err(edit_resource)?;
                let layer = u32::try_from(self.layers.len())
                    .ok()
                    .and_then(LayerId::new)
                    .ok_or(EditFault::IndexSpaceExhausted)?;
                self.layers.push(Layer { first, last, dirty_kids: 0, history_kids: 0, source });
                self.row_mut(id).set_slot(Slot::Opened(layer));
                #[cfg(debug_assertions)]
                self.assert_lattices();
                Ok(())
            }
    };
    (@core_seal_scan $cap:ident, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// Publishes a freshly scanned interior: mints the source run
            /// (source-backed, non-empty layers only) and the layer
            /// descriptor, then seals the slot last — an `Err` from either
            /// reservation leaves the container unopened, and the caller
            /// discards the provisional tables.
            fn seal_scan(
                &mut self,
                id: RowId,
                first: Option<RowId>,
                last: Option<RowId>,
                run: bool,
            ) -> Result<(), EditFault> {
                let source = match (run, first) {
                    (true, Some(run_first)) => {
                        self.source_runs.try_reserve(1).map_err(edit_resource)?;
                        let run = u32::try_from(self.source_runs.len())
                            .ok()
                            .and_then(SourceRunId::new)
                            .ok_or(EditFault::IndexSpaceExhausted)?;
                        self.source_runs.push(SourceRun { first: run_first, end: arena_end(&self.rows) });
                        Some(run)
                    }
                    _ => None,
                };
                self.layers.try_reserve(1).map_err(edit_resource)?;
                let layer = u32::try_from(self.layers.len())
                    .ok()
                    .and_then(LayerId::new)
                    .ok_or(EditFault::IndexSpaceExhausted)?;
                self.layers.push(Layer { first, last, dirty_kids: 0, history_kids: 0, source });
                self.row_mut(id).set_slot(Slot::Opened(layer));
                #[cfg(debug_assertions)]
                self.assert_lattices();
                Ok(())
            }
    };
    (@core_value_gate plain, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// A live, editable witness for value commands.
            #[track_caller]
            fn value_gate(&self, handle: Handle, want: RecordKind) -> Result<LiveEdit, EditFault> {
                let row = self.live(handle)?;
                if row.authored_zone() {
                    return Err(EditFault::InsideAuthoredBody);
                }
                if row.kind != want {
                    return Err(EditFault::KindMismatch { have: row.kind });
                }
                match row.edit {
                    Edit::Intact => Ok(LiveEdit::Virgin),
                    Edit::Replaced(_) => Ok(LiveEdit::Replaced),
                    Edit::Inserted(_) => Ok(LiveEdit::Inserted),
                    Edit::Deleted(_) | Edit::InsertedDeleted(_) => Err(EditFault::DeletedTarget),
                }
            }
    };
    (@core_value_gate $cap:ident, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// A live, editable witness for value commands.
            #[track_caller]
            fn value_gate(&self, handle: Handle, want: RecordKind) -> Result<LiveEdit, EditFault> {
                let row = self.live(handle)?;
                if row.authored_zone() && !self.import_zone_row(row) {
                    return Err(EditFault::InsideAuthoredBody);
                }
                if row.kind != want {
                    return Err(EditFault::KindMismatch { have: row.kind });
                }
                match row.edit {
                    Edit::Intact => Ok(LiveEdit::Virgin),
                    // A designated payload replaces like a stored one; a
                    // value command supersedes the designation. A copy's
                    // rows keep their cloned tag spelling under value
                    // commands, exactly like scanned rows — the authored
                    // identity rides the alias flag, not the emission.
                    Edit::Replaced(_) | Edit::SourcePayload(_) | Edit::SourceRecord => {
                        Ok(LiveEdit::Replaced)
                    }
                    Edit::Inserted(_) | Edit::SourceInserted(_) | Edit::Imported(_) => {
                        Ok(LiveEdit::Inserted)
                    }
                    Edit::Deleted(_)
                    | Edit::InsertedDeleted(_)
                    | Edit::Moved { .. }
                    | Edit::SourceRecordDeleted
                    | Edit::SourcePayloadDeleted(_)
                    | Edit::SourceInsertedDeleted(_)
                    | Edit::ImportedDeleted(_) => Err(EditFault::DeletedTarget),
                }
            }
    };
    (@core_shrouds plain, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// Shrouds a record: it stays in the topology, stops emitting,
            #[doc = concat!(" and holds its pending value for [`", stringify!($Machine), "::undelete`].")]
            ///
            /// # Errors
            ///
            /// [`EditFault::DeadHandle`],
            /// [`EditFault::InsideAuthoredBody`],
            /// [`EditFault::DeletedTarget`] when already shrouded,
            /// [`EditFault::Resource`] when the log cannot grow. On any
            #[doc = concat!(" `Err` the ", $noun, " is unchanged.")]
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the")]
            /// arena index contract).
            #[inline]
            #[track_caller]
            pub fn delete(&mut self, handle: Handle) -> Result<(), EditFault> {
                let row = self.live(handle)?;
                if row.authored_zone() {
                    return Err(EditFault::InsideAuthoredBody);
                }
                let to = match row.edit {
                    Edit::Intact => Edit::Deleted(None),
                    Edit::Replaced(value) => Edit::Deleted(Some(value)),
                    Edit::Inserted(value) => Edit::InsertedDeleted(value),
                    Edit::Deleted(_) | Edit::InsertedDeleted(_) => return Err(EditFault::DeletedTarget),
                };
                self.log.try_reserve(1).map_err(edit_resource)?;
                self.apply_edit(handle.0, to);
                Ok(())
            }

            /// Lifts a shroud, restoring the state deletion found.
            ///
            /// # Errors
            ///
            /// [`EditFault::DeadHandle`],
            /// [`EditFault::InsideAuthoredBody`],
            /// [`EditFault::NotDeleted`] when nothing is shrouded,
            /// [`EditFault::Resource`] when the log cannot grow. On any
            #[doc = concat!(" `Err` the ", $noun, " is unchanged.")]
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the")]
            /// arena index contract).
            #[inline]
            #[track_caller]
            pub fn undelete(&mut self, handle: Handle) -> Result<(), EditFault> {
                let row = self.live(handle)?;
                if row.authored_zone() {
                    return Err(EditFault::InsideAuthoredBody);
                }
                let to = match row.edit {
                    Edit::Deleted(None) => Edit::Intact,
                    Edit::Deleted(Some(value)) => Edit::Replaced(value),
                    Edit::InsertedDeleted(value) => Edit::Inserted(value),
                    Edit::Intact | Edit::Replaced(_) | Edit::Inserted(_) => {
                        return Err(EditFault::NotDeleted);
                    }
                };
                self.log.try_reserve(1).map_err(edit_resource)?;
                self.apply_edit(handle.0, to);
                Ok(())
            }

            /// Clears a replacement back to the scanned state. On a LEN
            /// this is a backing flip, but it needs no interior gate: a
            /// replaced LEN's materialized interior is authored bytes, and
            /// authored rows refuse every mutation face — the interior can
            /// hold no history to protect.
            ///
            /// # Errors
            ///
            /// [`EditFault::DeadHandle`],
            /// [`EditFault::InsideAuthoredBody`],
            /// [`EditFault::NotClearable`] off the `Replaced` state,
            /// [`EditFault::Resource`] when the log cannot grow.
            #[doc = concat!(" On any `Err` the ", $noun, " is unchanged.")]
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the")]
            /// arena index contract).
            #[inline]
            #[track_caller]
            pub fn clear_edit(&mut self, handle: Handle) -> Result<(), EditFault> {
                let row = self.live(handle)?;
                if row.authored_zone() {
                    return Err(EditFault::InsideAuthoredBody);
                }
                match row.edit {
                    Edit::Replaced(_) => {}
                    Edit::Intact | Edit::Deleted(_) | Edit::Inserted(_) | Edit::InsertedDeleted(_) => {
                        return Err(EditFault::NotClearable);
                    }
                }
                self.log.try_reserve(1).map_err(edit_resource)?;
                self.apply_edit(handle.0, Edit::Intact);
                Ok(())
            }
    };
    (@core_shrouds $cap:ident, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// Shrouds a record: it stays in the topology, stops emitting,
            #[doc = concat!(" and holds its pending value for [`", stringify!($Machine), "::undelete`].")]
            ///
            /// # Errors
            ///
            /// [`EditFault::DeadHandle`],
            /// [`EditFault::InsideAuthoredBody`],
            /// [`EditFault::DeletedTarget`] when already shrouded,
            /// [`EditFault::Resource`] when the log cannot grow. On any
            #[doc = concat!(" `Err` the ", $noun, " is unchanged.")]
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the")]
            /// arena index contract).
            #[inline]
            #[track_caller]
            pub fn delete(&mut self, handle: Handle) -> Result<(), EditFault> {
                let row = self.live(handle)?;
                if row.authored_zone() && !self.import_zone_row(row) {
                    return Err(EditFault::InsideAuthoredBody);
                }
                let to = match row.edit {
                    Edit::Intact => Edit::Deleted(None),
                    Edit::Replaced(value) => Edit::Deleted(Some(value)),
                    Edit::Inserted(value) => Edit::InsertedDeleted(value),
                    Edit::SourceRecord => Edit::SourceRecordDeleted,
                    Edit::SourcePayload(src) => Edit::SourcePayloadDeleted(src),
                    Edit::SourceInserted(src) => Edit::SourceInsertedDeleted(src),
                    Edit::Imported(value) => Edit::ImportedDeleted(value),
                    Edit::Deleted(_)
                    | Edit::InsertedDeleted(_)
                    | Edit::Moved { .. }
                    | Edit::SourceRecordDeleted
                    | Edit::SourcePayloadDeleted(_)
                    | Edit::SourceInsertedDeleted(_)
                    | Edit::ImportedDeleted(_) => return Err(EditFault::DeletedTarget),
                };
                self.log.try_reserve(1).map_err(edit_resource)?;
                self.apply_edit(handle.0, to);
                Ok(())
            }

            /// Lifts a shroud, restoring the state deletion found.
            ///
            /// # Errors
            ///
            /// [`EditFault::DeadHandle`],
            /// [`EditFault::InsideAuthoredBody`],
            /// [`EditFault::NotDeleted`] when nothing is shrouded,
            /// [`EditFault::Resource`] when the log cannot grow. On any
            #[doc = concat!(" `Err` the ", $noun, " is unchanged.")]
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the")]
            /// arena index contract).
            #[inline]
            #[track_caller]
            pub fn undelete(&mut self, handle: Handle) -> Result<(), EditFault> {
                let row = self.live(handle)?;
                if row.authored_zone() && !self.import_zone_row(row) {
                    return Err(EditFault::InsideAuthoredBody);
                }
                let to = match row.edit {
                    Edit::Deleted(None) => Edit::Intact,
                    Edit::Deleted(Some(value)) => Edit::Replaced(value),
                    Edit::InsertedDeleted(value) => Edit::Inserted(value),
                    Edit::SourceRecordDeleted => Edit::SourceRecord,
                    Edit::SourcePayloadDeleted(src) => Edit::SourcePayload(src),
                    Edit::SourceInsertedDeleted(src) => Edit::SourceInserted(src),
                    Edit::ImportedDeleted(value) => Edit::Imported(value),
                    // A moved record is suppressed, not shrouded: one
                    // revert of the move restores it.
                    Edit::Intact
                    | Edit::Replaced(_)
                    | Edit::Inserted(_)
                    | Edit::Moved { .. }
                    | Edit::SourceRecord
                    | Edit::SourcePayload(_)
                    | Edit::SourceInserted(_)
                    | Edit::Imported(_) => {
                        return Err(EditFault::NotDeleted);
                    }
                };
                self.log.try_reserve(1).map_err(edit_resource)?;
                self.apply_edit(handle.0, to);
                Ok(())
            }

            /// Clears a replacement back to the scanned state. On a LEN
            /// this is a backing flip, but it needs no interior gate: a
            /// replaced LEN's materialized interior is authored bytes, and
            /// authored rows refuse every mutation face — the interior can
            /// hold no history to protect.
            ///
            /// # Errors
            ///
            /// [`EditFault::DeadHandle`],
            /// [`EditFault::InsideAuthoredBody`],
            /// [`EditFault::NotClearable`] off the `Replaced` state,
            /// [`EditFault::Resource`] when the log cannot grow.
            #[doc = concat!(" On any `Err` the ", $noun, " is unchanged.")]
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the")]
            /// arena index contract).
            #[inline]
            #[track_caller]
            pub fn clear_edit(&mut self, handle: Handle) -> Result<(), EditFault> {
                let row = self.live(handle)?;
                if row.authored_zone() && !self.import_zone_row(row) {
                    return Err(EditFault::InsideAuthoredBody);
                }
                match row.edit {
                    // A designated payload clears exactly like a stored
                    // replacement: back to the scanned reading. A copy's
                    // rows have no scanned state to restore.
                    Edit::Replaced(_) | Edit::SourcePayload(_) if !row.alias() => {}
                    _ => return Err(EditFault::NotClearable),
                }
                self.log.try_reserve(1).map_err(edit_resource)?;
                self.apply_edit(handle.0, Edit::Intact);
                Ok(())
            }
    };
    (@core_container_gate plain, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// Gates an insertion container and yields its layer.
            #[track_caller]
            fn container_gate(&self, container: Option<Handle>) -> Result<&Layer, EditFault> {
                let Some(handle) = container else {
                    return Ok(&self.root);
                };
                let row = self.live(handle)?;
                if row.authored_zone() {
                    return Err(EditFault::InsideAuthoredBody);
                }
                match row.kind {
                    RecordKind::Len => {
                        if row.edit.effective().is_some() {
                            // A replaced or authored payload: its interior
                            // is authored bytes, browse-only.
                            return Err(EditFault::InsideAuthoredBody);
                        }
                    }
                    RecordKind::Varint | RecordKind::I32 | RecordKind::I64 => {
                        return Err(EditFault::KindMismatch { have: row.kind });
                    }
                }
                match row.slot() {
                    Slot::Opened(layer) => Ok(self.layer(layer)),
                    Slot::Unopened | Slot::Fault(_) => Err(EditFault::TargetUnopened),
                }
            }
    };
    (@core_container_gate transfer, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// Gates an insertion container and yields its layer.
            #[track_caller]
            fn container_gate(&self, container: Option<Handle>) -> Result<&Layer, EditFault> {
                let Some(handle) = container else {
                    return Ok(&self.root);
                };
                let row = self.live(handle)?;
                if row.authored_zone() && !self.import_zone_row(row) {
                    return Err(EditFault::InsideAuthoredBody);
                }
                match row.kind {
                    RecordKind::Len => match row.edit {
                        // A replaced or authored payload: its interior is
                        // authored bytes, browse-only.
                        Edit::Replaced(_)
                        | Edit::Deleted(Some(_))
                        | Edit::Inserted(_)
                        | Edit::InsertedDeleted(_) => {
                            return Err(EditFault::InsideAuthoredBody);
                        }
                        // A shrouded import accepts no insertions (the
                        // shroud restores exactly on undeletion).
                        Edit::ImportedDeleted(_) => {
                            return Err(EditFault::DeletedTarget);
                        }
                        // A live import's descended interior is
                        // first-class: it accepts insertions like any
                        // scanned layer; transfer interiors likewise.
                        Edit::Imported(_)
                        | Edit::Intact
                        | Edit::Deleted(None)
                        | Edit::Moved { .. }
                        | Edit::SourceRecord
                        | Edit::SourceRecordDeleted
                        | Edit::SourcePayload(_)
                        | Edit::SourcePayloadDeleted(_)
                        | Edit::SourceInserted(_)
                        | Edit::SourceInsertedDeleted(_) => {}
                    },
                    RecordKind::Varint | RecordKind::I32 | RecordKind::I64 => {
                        return Err(EditFault::KindMismatch { have: row.kind });
                    }
                }
                match row.slot() {
                    Slot::Opened(layer) => Ok(self.layer(layer)),
                    Slot::Unopened | Slot::Fault(_) => Err(EditFault::TargetUnopened),
                }
            }
    };
    (@core_container_gate $cap:ident, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// Gates an insertion container and yields its layer.
            #[track_caller]
            fn container_gate(&self, container: Option<Handle>) -> Result<&Layer, EditFault> {
                let Some(handle) = container else {
                    return Ok(&self.root);
                };
                let row = self.live(handle)?;
                if row.authored_zone() {
                    return Err(EditFault::InsideAuthoredBody);
                }
                match row.kind {
                    RecordKind::Len => match row.edit {
                        // A replaced, authored, or imported payload: its
                        // interior is authored bytes, browse-only.
                        Edit::Replaced(_)
                        | Edit::Deleted(Some(_))
                        | Edit::Inserted(_)
                        | Edit::InsertedDeleted(_)
                        | Edit::Imported(_)
                        | Edit::ImportedDeleted(_) => {
                            return Err(EditFault::InsideAuthoredBody);
                        }
                        // Transfer interiors are first-class: their alias
                        // rows edit and insert like scanned ones.
                        Edit::Intact
                        | Edit::Deleted(None)
                        | Edit::Moved { .. }
                        | Edit::SourceRecord
                        | Edit::SourceRecordDeleted
                        | Edit::SourcePayload(_)
                        | Edit::SourcePayloadDeleted(_)
                        | Edit::SourceInserted(_)
                        | Edit::SourceInsertedDeleted(_) => {}
                    },
                    RecordKind::Varint | RecordKind::I32 | RecordKind::I64 => {
                        return Err(EditFault::KindMismatch { have: row.kind });
                    }
                }
                match row.slot() {
                    Slot::Opened(layer) => Ok(self.layer(layer)),
                    Slot::Unopened | Slot::Fault(_) => Err(EditFault::TargetUnopened),
                }
            }
    };
    (@core_undo plain, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// Reverts the most recent command; returns the touched row.
            /// Reverting an insertion shrouds the row (topology is
            /// monotone; the ghost stays for presentation to filter).
            #[inline]
            pub fn revert(&mut self) -> Option<Handle> {
                let transition = self.log_pop()?;
                self.write_state(transition.row(), transition.from);
                Some(Handle(transition.row()))
            }

            /// Reverts every pending command, newest first.
            #[inline]
            pub fn revert_all(&mut self) {
                while self.revert().is_some() {}
            }

            // ── state maintenance ──

            /// Applies one edit transition: sets the state, re-seals the
            /// child slot when the row's backing flips, and keeps the dirt
            /// lattice exact in both directions.
            ///
            /// Orphaned interiors are always clean; three guarantees join
            /// to prove it: the interior gate refuses a forward flip over
            /// any interior history, revert executes strictly
            /// last-in-first-out (every later descendant transition is
            /// already unwound when a flip replays backwards), and rows
            /// under an authored backing accept no edits at all.
            fn write_state(&mut self, id: RowId, to: Edit) {
                let row = self.row_mut(id);
                debug_assert!(!row.dead(), "write_state: dead rows accept no transitions");
                let from = row.edit;
                row.edit = to;
                let flip = from.effective() != to.effective();
                let sealed = !matches!(row.slot(), Slot::Unopened);
                if flip && sealed {
                    self.orphan_interior(id);
                }
                if to.own_dirty() {
                    self.raise_mark(Mark::Dirt, id);
                } else {
                    self.lower_mark(Mark::Dirt, id);
                }
                #[cfg(debug_assertions)]
                self.assert_lattices();
            }
    };
    (@core_undo $cap:ident, Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// Reverts the most recent command; returns the touched row.
            /// Reverting an insertion shrouds the row (topology is
            /// monotone; the ghost stays for presentation to filter).
            /// Reverting a move unwinds both rows it touched in one step
            /// — the suppressed source comes back and the destination
            /// alias is shrouded — and the returned handle is the
            /// source's.
            #[inline]
            pub fn revert(&mut self) -> Option<Handle> {
                let transition = self.log_pop()?;
                // A move entry carries its `Moved` state as the tag:
                // that one entry unwinds both sides.
                if let Edit::Moved { destination } = transition.from {
                    self.revert_move(transition.row(), destination);
                } else {
                    self.write_state(transition.row(), transition.from);
                }
                Some(Handle(transition.row()))
            }

            /// Reverts every pending command, newest first.
            #[inline]
            pub fn revert_all(&mut self) {
                while self.revert().is_some() {}
            }

            // ── state maintenance ──

            /// Applies one edit transition: sets the state, re-seals the
            /// child slot when the row's backing flips, and keeps the dirt
            /// lattice exact in both directions.
            ///
            /// Orphaned interiors are always clean; three guarantees join
            /// to prove it: the interior gate refuses a forward flip over
            /// any interior history, revert executes strictly
            /// last-in-first-out (every later descendant transition is
            /// already unwound when a flip replays backwards), and rows
            /// under an authored backing accept no edits at all.
            fn write_state(&mut self, id: RowId, to: Edit) {
                let row = self.row_mut(id);
                debug_assert!(!row.dead(), "write_state: dead rows accept no transitions");
                debug_assert!(
                    !matches!(row.edit, Edit::Moved { .. }) && !matches!(to, Edit::Moved { .. }),
                    "write_state: move transitions run the coupled primitive"
                );
                let from = row.edit;
                row.edit = to;
                let flip = from.speaker() != to.speaker();
                let sealed = !matches!(row.slot(), Slot::Unopened);
                if flip && sealed {
                    self.orphan_interior(id);
                }
                if to.own_dirty() {
                    self.raise_mark(Mark::Dirt, id);
                } else {
                    self.lower_mark(Mark::Dirt, id);
                }
                #[cfg(debug_assertions)]
                self.assert_lattices();
            }

            /// The move faces' coupled transition: one logged step
            /// suppresses the source occurrence and enlivens its ghosted
            /// destination alias. The log entry carries the `Moved`
            /// state itself — the move gate admits only an intact,
            /// undirtied source, so the state to restore is fixed — and
            /// `revert` routes such an entry through the coupled unwind.
            /// Neither side's speaker changes (the source keeps its
            /// scanned reading suppressed; the alias keeps its own), so
            /// no interior re-seals, and the dirt lattice moves exactly
            /// one step on each side.
            fn apply_move(&mut self, source: RowId, destination: RowId) {
                debug_assert!(
                    matches!(self.row(source).edit, Edit::Intact),
                    "apply_move: the move gate admits only intact sources"
                );
                self.log_push(source, Edit::Moved { destination });
                // Intact and Moved share the scanned speaker, so no
                // interior re-seals; the dirt lattice moves one step.
                self.row_mut(source).edit = Edit::Moved { destination };
                self.raise_mark(Mark::Dirt, source);
                let live = match self.row(destination).edit {
                    Edit::SourceRecordDeleted => Edit::SourceRecord,
                    Edit::SourceInsertedDeleted(src) => Edit::SourceInserted(src),
                    _ => unreachable!("a move's destination is its own ghosted alias"),
                };
                self.write_state(destination, live);
            }

            /// The coupled unwind: restores the moved source to its
            /// intact reading and ghosts the destination alias — its own
            /// later commands are already unwound, because undoing runs
            /// last-in-first-out.
            fn revert_move(&mut self, source: RowId, destination: RowId) {
                debug_assert!(
                    matches!(self.row(source).edit, Edit::Moved { .. }),
                    "revert_move: only a moved source unwinds here"
                );
                // Moved and Intact share the scanned speaker, so no
                // interior re-seals; the dirt lattice moves one step.
                self.row_mut(source).edit = Edit::Intact;
                self.lower_mark(Mark::Dirt, source);
                let ghost = match self.row(destination).edit {
                    Edit::SourceRecord => Edit::SourceRecordDeleted,
                    Edit::SourceInserted(src) => Edit::SourceInsertedDeleted(src),
                    _ => unreachable!("a move's destination is its own live alias"),
                };
                self.write_state(destination, ghost);
            }
    };
    (@core $cap:ident, $Machine:ident $(<$($lt:lifetime),+>)?, src_lt: [$($slt:lifetime)?], pay_lt: [$($plt:lifetime)?], pay: $pay:ident, store: $Store:ident, src: $src:ident, acc: $acc:ident, prod: $prod:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
        impl$(<$($lt),+>)? $Machine$(<$($lt),+>)? {
            $crate::revise::groupless::revising_machine!(@doors $src $acc $(<$slt>)?, store: $Store, Machine: $Machine, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod);
            $crate::revise::groupless::revising_machine!(@snapshot $acc, Machine: $Machine);
            // ── internal row access ──

            /// A gated row by coordinate (every public entry gates first).
            fn row(&self, id: RowId) -> &Row {
                // SAFETY: `id` was gated or minted by this machine, and
                // the arena never shrinks below a live coordinate.
                unsafe { self.rows.get_unchecked(id.index()) }
            }

            #[doc = concat!(" Mutable twin of [`", stringify!($Machine), "::row`].")]
            fn row_mut(&mut self, id: RowId) -> &mut Row {
                // SAFETY: as [`$Machine::row`].
                unsafe { self.rows.get_unchecked_mut(id.index()) }
            }

            /// A layer descriptor by minted coordinate.
            fn layer(&self, layer: LayerId) -> &Layer {
                // SAFETY: `layer` was minted by this machine, and the
                // layer table never shrinks below a live coordinate.
                unsafe { self.layers.get_unchecked(layer.index()) }
            }

            /// The first row of a slot's layer (`None` unless opened).
            fn slot_first(&self, slot: Slot) -> Option<RowId> {
                match slot {
                    Slot::Opened(layer) => self.layer(layer).first,
                    Slot::Unopened | Slot::Fault(_) => None,
                }
            }

            /// The layer that directly holds a row with this parent: the
            /// parent's opened layer, or the root descriptor for top-level
            /// rows. Live rows always sit in a materialized layer — LEN
            /// interiors publish theirs at descend, and a re-sealed
            /// container orphans its whole subtree first.
            fn holding_layer(&self, parent: Option<RowId>) -> &Layer {
                parent.map_or(&self.root, |id| match self.row(id).slot() {
                    Slot::Opened(layer) => self.layer(layer),
                    // SAFETY: live rows sit in materialized layers — dead
                    // rows are refused upstream, and a re-sealing container
                    // orphans its whole subtree before unsealing the slot.
                    Slot::Unopened | Slot::Fault(_) => unsafe {
                        debug_assert!(false, "live rows sit in materialized layers");
                        core::hint::unreachable_unchecked()
                    },
                })
            }

            #[doc = concat!(" Mutable twin of [`", stringify!($Machine), "::holding_layer`].")]
            fn holding_layer_mut(&mut self, parent: Option<RowId>) -> &mut Layer {
                match parent {
                    Some(id) => match self.row(id).slot() {
                        Slot::Opened(layer) => {
                            // SAFETY: as [`$Machine::layer`].
                            unsafe { self.layers.get_unchecked_mut(layer.index()) }
                        }
                        // SAFETY: as [`$Machine::holding_layer`] — live rows
                        // sit in materialized layers.
                        Slot::Unopened | Slot::Fault(_) => unsafe {
                            debug_assert!(false, "live rows sit in materialized layers");
                            core::hint::unreachable_unchecked()
                        },
                    },
                    None => &mut self.root,
                }
            }

            /// Gates a handle and refuses orphaned rows.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the")]
            /// documented index contract).
            #[track_caller]
            fn live(&self, handle: Handle) -> Result<&Row, EditFault> {
                let row = gate(&self.rows, handle);
                if row.dead() { Err(EditFault::DeadHandle) } else { Ok(row) }
            }

            $crate::revise::groupless::revising_machine!(@core_transfer_readers $cap, Machine: $Machine, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod);

            $crate::revise::groupless::revising_machine!(@backing $cap $pay $src, Machine: $Machine, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod);
            $crate::revise::groupless::revising_machine!(@zone_readers $acc, Machine: $Machine, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod);
            // ── observation ──

            $crate::revise::groupless::revising_machine!(@observe_head $src, Machine: $Machine, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod);
            /// Revision-log length: the number of revertible steps.
            #[inline]
            #[must_use]
            pub const fn pending(&self) -> usize {
                self.log.len()
            }

            /// The record's wire kind.
            ///
            /// # Errors
            ///
            /// [`EditFault::DeadHandle`] for an orphaned row.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the")]
            /// arena index contract).
            #[inline]
            #[track_caller]
            pub fn kind(&self, handle: Handle) -> Result<RecordKind, EditFault> {
                Ok(self.live(handle)?.kind)
            }

            /// The record's field number.
            ///
            /// # Errors
            ///
            /// [`EditFault::DeadHandle`] for an orphaned row.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the")]
            /// arena index contract).
            #[inline]
            #[track_caller]
            pub fn field(&self, handle: Handle) -> Result<FieldNumber, EditFault> {
                Ok(self.live(handle)?.field)
            }

            $crate::revise::groupless::revising_machine!(@core_status $cap, Machine: $Machine, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod);

            /// True when the record's subtree carries any dirt — a
            #[doc = concat!(" subtree answer [`", stringify!($Machine), "::status`] cannot give.")]
            ///
            /// # Errors
            ///
            /// [`EditFault::DeadHandle`] for an orphaned row.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the")]
            /// arena index contract).
            #[inline]
            #[track_caller]
            pub fn dirty(&self, handle: Handle) -> Result<bool, EditFault> {
                Ok(self.live(handle)?.dirty())
            }

            /// The record's parent container, if any.
            ///
            /// # Errors
            ///
            /// [`EditFault::DeadHandle`] for an orphaned row.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the")]
            /// arena index contract).
            #[inline]
            #[track_caller]
            pub fn parent(&self, handle: Handle) -> Result<Option<Handle>, EditFault> {
                Ok(self.live(handle)?.parent.map(Handle))
            }

            /// The top layer, in wire order. Shrouded records and ghosts
            /// stay in the chain — presentation filters, topology does
            /// not.
            #[inline]
            pub fn top(&self) -> Children<'_> {
                Children { rows: &self.rows, cur: self.root.first }
            }

            /// The record's materialized children, in wire order (empty
            /// until a LEN is descended).
            ///
            /// # Errors
            ///
            /// [`EditFault::DeadHandle`] for an orphaned row.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the")]
            /// arena index contract).
            #[inline]
            #[track_caller]
            pub fn children(&self, handle: Handle) -> Result<Children<'_>, EditFault> {
                Ok(Children { rows: &self.rows, cur: self.slot_first(self.live(handle)?.slot()) })
            }

            /// The record's ancestor chain, innermost first.
            ///
            /// # Errors
            ///
            /// [`EditFault::DeadHandle`] for an orphaned row.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the")]
            /// arena index contract).
            #[inline]
            #[track_caller]
            pub fn ancestors(&self, handle: Handle) -> Result<Ancestors<'_>, EditFault> {
                Ok(Ancestors { rows: &self.rows, cur: self.live(handle)?.parent })
            }

            /// The record's whole source span in document coordinates
            /// (`None` for command-authored rows and rows inside authored
            /// payloads — they own no hex).
            ///
            /// # Errors
            ///
            /// [`EditFault::DeadHandle`] for an orphaned row.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the")]
            /// arena index contract).
            #[inline]
            #[track_caller]
            pub fn span(&self, handle: Handle) -> Result<Option<Span>, EditFault> {
                let row = self.live(handle)?;
                if $crate::revise::groupless::revising_machine!(@authored_identity $cap, row) {
                    return Ok(None);
                }
                Ok(row.at.map(|at| Span::new(at.as_inner(), row.end)))
            }

            $crate::revise::groupless::revising_machine!(@record_ref $cap $acc, Machine: $Machine, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod);
            $crate::revise::groupless::revising_machine!(@source_spans $cap $acc, Machine: $Machine, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod);
            /// The narrowest source-backed record whose span contains
            /// `pos` — the hex view's reverse index. Descends exactly as
            /// far as layers have materialized: each source run's rows
            /// ascend by offset, so a bisection lands on the
            /// latest-starting candidate, and an opened LEN chains into
            /// its interior's own run.
            #[inline]
            #[must_use]
            pub fn narrowest(&self, pos: u32) -> Option<Handle> {
                let mut best: Option<RowId> = None;
                let mut run = self.root.source;
                while let Some(run_id) = run {
                    // SAFETY: `run_id` was minted by this machine, and the
                    // run table never shrinks.
                    let range = unsafe { self.source_runs.get_unchecked(run_id.index()) };
                    let Some(id) = self.bisect_run(range, pos) else { break };
                    let row = self.row(id);
                    if pos >= row.end {
                        // Records pave their layer without gaps, so only
                        // the root run's tail can leave a candidate short:
                        // the position lies past the document's content and
                        // no proven container exists. Should paving ever
                        // weaken, the proven container still answers.
                        debug_assert!(best.is_none(), "a paved layer left its container uncovered");
                        return best.map(Handle);
                    }
                    best = Some(id);
                    run = match row.slot() {
                        Slot::Opened(layer) => self.layer(layer).source,
                        Slot::Unopened | Slot::Fault(_) => None,
                    };
                }
                best.map(Handle)
            }

            /// The latest-starting row of a run whose offset is at or
            /// before `pos` (`None` when every row starts past it). Run
            /// rows were minted by one source scan in strictly ascending
            /// offset order, which is the bisection's whole warrant.
            fn bisect_run(&self, range: &SourceRun, pos: u32) -> Option<RowId> {
                let mut lo = range.first.as_inner();
                let mut hi = range.end;
                while lo < hi {
                    let mid = lo + (hi - lo) / 2;
                    // SAFETY: `mid` is below the run's end, an arena index
                    // the run's scan minted.
                    let row = unsafe { self.rows.get_unchecked(usize_of(mid)) };
                    // SAFETY: `mid` is inside the run.
                    if unsafe { run_at(row) }.as_inner() <= pos {
                        lo = mid + 1;
                    } else {
                        hi = mid;
                    }
                }
                if lo == range.first.as_inner() {
                    return None;
                }
                // SAFETY: `lo - 1` is inside the run, whose every index was
                // minted through the `RowId` judgment.
                Some(unsafe { RowId::new_unchecked(lo - 1) })
            }

            $crate::revise::groupless::revising_machine!(@core_value_reads $cap, Machine: $Machine, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod);

            // ── descending ──

            $crate::revise::groupless::revising_machine!(@descend $cap $pay, src: $src, Machine: $Machine, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod);
            $crate::revise::groupless::revising_machine!(@core_seal_scan $cap, Machine: $Machine, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod);

            /// Registers a resident verdict; the slot is only written once
            /// this succeeds.
            #[cold]
            fn push_fault(&mut self, fault: SlotFault) -> Result<u32, EditFault> {
                self.faults.try_reserve(1).map_err(edit_resource)?;
                let index = u32::try_from(self.faults.len()).map_err(|_| EditFault::IndexSpaceExhausted)?;
                self.faults.push(fault);
                Ok(index)
            }

            // ── mutation ──

            $crate::revise::groupless::revising_machine!(@core_value_gate $cap, Machine: $Machine, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod);

            /// Refuses a backing flip over an interior that carries undo
            /// history: precise undo would otherwise point into rows the
            /// flip orphans. The target's own history is fine — only
            /// strict descendants block, and the layer's history count
            /// answers for them whole.
            fn interior_gate(&self, id: RowId) -> Result<(), EditFault> {
                match self.row(id).slot() {
                    Slot::Opened(layer) if self.layer(layer).history_kids > 0 => {
                        Err(EditFault::EditedInterior)
                    }
                    Slot::Opened(_) | Slot::Unopened | Slot::Fault(_) => Ok(()),
                }
            }

            /// The undo log's single append point: records the step, marks
            /// the row's own history on its first pending entry, and
            /// raises the subtree marks. Every reservation already holds.
            fn log_push(&mut self, id: RowId, from: Edit) {
                let fresh = !self.row(id).own_hist();
                self.log.push(Transition::new(id, from, fresh));
                if fresh {
                    self.row_mut(id).flags |= FLAG_OWN_HIST;
                    self.raise_mark(Mark::Hist, id);
                }
            }

            /// The undo log's single removal point: popping a row's fresh
            /// (first) entry releases its own-history mark and lowers the
            /// subtree marks — exact because reverts run strictly
            /// last-in-first-out, so no later entry for the row remains.
            fn log_pop(&mut self) -> Option<Transition> {
                let transition = self.log.pop()?;
                if transition.fresh() {
                    self.row_mut(transition.row()).flags &= !FLAG_OWN_HIST;
                    self.lower_mark(Mark::Hist, transition.row());
                }
                Some(transition)
            }

            /// Raises a subtree mark from `id` upward: each newly flagged
            /// row counts into its holding layer, and the climb stops at
            /// the first ancestor already flagged. Inlined for the
            /// already-flagged early return on the value-edit hot path.
            #[inline]
            fn raise_mark(&mut self, mark: Mark, mut id: RowId) {
                loop {
                    let row = self.row_mut(id);
                    if row.flags & mark.flag() != 0 {
                        return;
                    }
                    row.flags |= mark.flag();
                    let parent = row.parent;
                    *self.holding_layer_mut(parent).count_mut(mark) += 1;
                    match parent {
                        Some(next) => id = next,
                        None => return,
                    }
                }
            }

            /// Lowers a subtree mark from `id` upward: a row stays flagged
            /// while its own state or its opened layer's count holds the
            /// mark, and each falling flag leaves its holding layer's
            /// count. Inlined for the still-held early return on the
            /// value-edit hot path.
            #[inline]
            fn lower_mark(&mut self, mark: Mark, mut id: RowId) {
                loop {
                    let row = self.row(id);
                    if row.flags & mark.flag() == 0 {
                        return;
                    }
                    let held = mark.own(row)
                        || match row.slot() {
                            Slot::Opened(layer) => self.layer(layer).count(mark) > 0,
                            Slot::Unopened | Slot::Fault(_) => false,
                        };
                    if held {
                        return;
                    }
                    let parent = row.parent;
                    self.row_mut(id).flags &= !mark.flag();
                    *self.holding_layer_mut(parent).count_mut(mark) -= 1;
                    match parent {
                        Some(next) => id = next,
                        None => return,
                    }
                }
            }

            /// Logs and applies one edit transition (the infallible suffix
            /// of every value command: both reservations already hold).
            fn apply_edit(&mut self, id: RowId, to: Edit) {
                let from = self.row(id).edit;
                self.log_push(id, from);
                self.write_state(id, to);
            }

            /// Replaces a varint record's value.
            ///
            /// # Errors
            ///
            /// [`EditFault::DeadHandle`], [`EditFault::KindMismatch`],
            /// [`EditFault::DeletedTarget`],
            /// [`EditFault::InsideAuthoredBody`] off the gates;
            /// [`EditFault::Resource`]/[`EditFault::IndexSpaceExhausted`] when the
            #[doc = concat!(" value cannot be stored. On any `Err` the ", $noun, " is")]
            /// unchanged.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the")]
            /// arena index contract).
            #[inline]
            #[track_caller]
            pub fn set_varint(&mut self, handle: Handle, value: u64) -> Result<(), EditFault> {
                let witness = self.value_gate(handle, RecordKind::Varint)?;
                self.log.try_reserve(1).map_err(edit_resource)?;
                let at = self.store.push_varint(value).map_err(edit_store_fault)?;
                self.apply_edit(handle.0, witness.set(at));
                Ok(())
            }

            /// Replaces a fixed 32-bit record's bits.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::set_varint`].")]
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the")]
            /// arena index contract).
            #[inline]
            #[track_caller]
            pub fn set_i32(&mut self, handle: Handle, bits: u32) -> Result<(), EditFault> {
                let witness = self.value_gate(handle, RecordKind::I32)?;
                self.log.try_reserve(1).map_err(edit_resource)?;
                let at = self.store.push_bits32(bits).map_err(edit_store_fault)?;
                self.apply_edit(handle.0, witness.set(at));
                Ok(())
            }

            /// Replaces a fixed 64-bit record's bits.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::set_varint`].")]
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the")]
            /// arena index contract).
            #[inline]
            #[track_caller]
            pub fn set_i64(&mut self, handle: Handle, bits: u64) -> Result<(), EditFault> {
                let witness = self.value_gate(handle, RecordKind::I64)?;
                self.log.try_reserve(1).map_err(edit_resource)?;
                let at = self.store.push_bits64(bits).map_err(edit_store_fault)?;
                self.apply_edit(handle.0, witness.set(at));
                Ok(())
            }

            $crate::revise::groupless::revising_machine!(@set_payload $pay $(<$plt>)?, Machine: $Machine, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod);
            $crate::revise::groupless::revising_machine!(@core_shrouds $cap, Machine: $Machine, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod);

            // ── insertion ──

            $crate::revise::groupless::revising_machine!(@core_container_gate $cap, Machine: $Machine, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod);

            /// Resolves an anchor into a proven splice point.
            #[track_caller]
            fn resolve_anchor(&self, at: InsertAt) -> Result<InsertPlan, EditFault> {
                match at {
                    InsertAt::HeadOf(container) => {
                        self.container_gate(container)?;
                        Ok(InsertPlan { parent: container.map(|h| h.0), prev: None })
                    }
                    InsertAt::TailOf(container) => {
                        let layer = self.container_gate(container)?;
                        Ok(InsertPlan { parent: container.map(|h| h.0), prev: layer.last })
                    }
                    InsertAt::After(anchor) => {
                        let row = self.live(anchor)?;
                        if $crate::revise::groupless::revising_machine!(@zone_gate $cap, self, row) {
                            return Err(EditFault::InsideAuthoredBody);
                        }
                        Ok(InsertPlan { parent: row.parent, prev: Some(anchor.0) })
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

            /// Splices, logs, and awakens an authored row (the infallible
            /// suffix of every insert command: every reservation holds).
            /// Chain anchors update in place: the holding layer's head
            /// when the row splices first, its tail when nothing follows.
            fn apply_insert(
                &mut self,
                plan: &InsertPlan,
                id: RowId,
                field: FieldNumber,
                kind: RecordKind,
                value: ValueAt,
            ) {
                let next = plan
                    .prev
                    .map_or_else(|| self.holding_layer(plan.parent).first, |prev| self.row(prev).next);
                // The reservation in the command covers this push.
                self.rows.push(Row::authored(field, kind, plan.parent, next, value));
                match plan.prev {
                    Some(prev) => self.row_mut(prev).next = Some(id),
                    None => self.holding_layer_mut(plan.parent).first = Some(id),
                }
                if next.is_none() {
                    self.holding_layer_mut(plan.parent).last = Some(id);
                }
                self.log_push(id, Edit::InsertedDeleted(value));
                self.write_state(id, Edit::Inserted(value));
            }

            /// Inserts a varint record at the anchor.
            ///
            /// # Errors
            ///
            /// [`EditFault::DeadHandle`] for a dead anchor,
            /// [`EditFault::KindMismatch`] for a scalar container,
            /// [`EditFault::TargetUnopened`] for an undescended LEN,
            /// [`EditFault::InsideAuthoredBody`] under authored bytes,
            /// [`EditFault::Resource`]/[`EditFault::IndexSpaceExhausted`] when the
            /// row, log, or value cannot be stored. On any `Err` the
            #[doc = concat!(" ", $noun, " is unchanged.")]
            ///
            /// # Panics
            ///
            /// Panics if a handle inside the anchor was not minted by this
            #[doc = concat!(" ", $noun, " (the arena index contract).")]
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
                self.rows.try_reserve(1).map_err(edit_resource)?;
                self.log.try_reserve(1).map_err(edit_resource)?;
                let value = self.store.push_varint(value).map_err(edit_store_fault)?;
                self.apply_insert(&plan, id, field, RecordKind::Varint, value);
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
                self.rows.try_reserve(1).map_err(edit_resource)?;
                self.log.try_reserve(1).map_err(edit_resource)?;
                let value = self.store.push_bits32(bits).map_err(edit_store_fault)?;
                self.apply_insert(&plan, id, field, RecordKind::I32, value);
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
                self.rows.try_reserve(1).map_err(edit_resource)?;
                self.log.try_reserve(1).map_err(edit_resource)?;
                let value = self.store.push_bits64(bits).map_err(edit_store_fault)?;
                self.apply_insert(&plan, id, field, RecordKind::I64, value);
                Ok(Handle(id))
            }

            $crate::revise::groupless::revising_machine!(@insert_payload $pay $(<$plt>)?, Machine: $Machine, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod);
            $crate::revise::groupless::revising_machine!(@frame_doors $pay $(<$($lt),+>)?, Machine: $Machine, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod);
            $crate::revise::groupless::revising_machine!(@core_transfer_faces $cap, pay: $pay, acc: $acc, pay_lt: [$($plt)?], Machine: $Machine, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod);
            $crate::revise::groupless::revising_machine!(@import_zone $cap $pay, Machine: $Machine);
            $crate::revise::groupless::revising_machine!(@import_zone_row $cap, Machine: $Machine);
            // ── undo ──

            $crate::revise::groupless::revising_machine!(@core_undo $cap, Machine: $Machine, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod);

            /// Re-seals a flipped container: the parsed interior (clean by
            /// the transition argument above) is orphaned and the slot
            /// returns to unopened, ready to parse the new backing. The
            /// interior's layers and runs stay behind, unreachable and
            /// inert.
            fn orphan_interior(&mut self, id: RowId) {
                let first = self.slot_first(self.row(id).slot());
                self.row_mut(id).set_slot(Slot::Unopened);
                let mut cur = first;
                while let Some(orphan) = cur {
                    let row = self.row_mut(orphan);
                    debug_assert!(!row.edit.own_dirty(), "orphaned interiors are clean");
                    row.set_dead();
                    cur = preorder_next(&self.rows, &self.layers, orphan, id);
                }
            }

            /// The lattice oracle: pins the own-history marks to the log
            /// (every logged row is marked, and the marked-row count equals
            /// the fresh-entry count — reverts run last-in-first-out, so a
            /// logged row has exactly one fresh entry and the two counts
            /// coincide exactly when the marks name the logged rows), then
            /// re-derives every row's subtree marks from their local ground
            /// truths and walks every reachable layer's chain against its
            /// anchors and both counts — the local closures compose
            /// inductively from the leaves, so together they pin the global
            /// aggregates. O(rows + log), all threaded, no allocation;
            /// debug builds run it after every transition and publication.
            #[cfg(debug_assertions)]
            fn assert_lattices(&self) {
                let mut fresh = 0_usize;
                for t in &self.log {
                    debug_assert!(self.row(t.row()).own_hist(), "logged row without its own mark");
                    fresh += usize::from(t.fresh());
                }
                let marked = self.rows.iter().filter(|row| row.own_hist()).count();
                debug_assert_eq!(marked, fresh, "own-history marks drift from the log");
                for row in &self.rows {
                    let kids = |mark: Mark| match row.slot() {
                        Slot::Opened(layer) => self.layer(layer).count(mark) > 0,
                        Slot::Unopened | Slot::Fault(_) => false,
                    };
                    debug_assert_eq!(
                        row.hist(),
                        row.own_hist() || kids(Mark::Hist),
                        "subtree-history mark drift"
                    );
                    debug_assert_eq!(
                        row.dirty(),
                        row.edit.own_dirty() || kids(Mark::Dirt),
                        "subtree-dirt mark drift"
                    );
                }
                self.assert_layer(&self.root, None);
                for (index, row) in self.rows.iter().enumerate() {
                    if let Slot::Opened(layer) = row.slot() {
                        let owner = u32::try_from(index).ok().and_then(RowId::new);
                        debug_assert!(owner.is_some(), "arena index outside the row domain");
                        self.assert_layer(self.layer(layer), owner);
                    }
                }
            }

            /// One layer's oracle: the chain from `first` ends on `last`,
            /// every member names `owner` as parent, and both
            /// flagged-member counts match the maintained ones.
            #[cfg(debug_assertions)]
            fn assert_layer(&self, layer: &Layer, owner: Option<RowId>) {
                let mut dirty = 0u32;
                let mut marked = 0u32;
                let mut tail = None;
                let mut cur = layer.first;
                while let Some(id) = cur {
                    let row = self.row(id);
                    debug_assert!(row.parent == owner, "chain member outside its layer");
                    if row.dirty() {
                        dirty += 1;
                    }
                    if row.hist() {
                        marked += 1;
                    }
                    tail = Some(id);
                    cur = row.next;
                }
                debug_assert!(layer.last == tail, "layer tail drift");
                debug_assert_eq!(layer.dirty_kids, dirty, "layer dirt count drift");
                debug_assert_eq!(layer.history_kids, marked, "layer history count drift");
            }

            // ── saving ──

            $crate::revise::groupless::revising_machine!(@settle $cap $acc, Machine: $Machine, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod);
            $crate::revise::groupless::revising_machine!(@size_pass $cap $acc, prod: $prod, Machine: $Machine, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod);
            $crate::revise::groupless::revising_machine!(@emit_pass $cap $acc, Machine: $Machine, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod);
            $crate::revise::groupless::revising_machine!(@save $src $prod, Machine: $Machine, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod);
            $crate::revise::groupless::revising_machine!(@save_len $prod, src: $src, Machine: $Machine, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod);
            $crate::revise::groupless::revising_machine!(@save_into $prod, Machine: $Machine, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod);
            $crate::revise::groupless::revising_machine!(@save_sink $src $prod, Machine: $Machine, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod);
            $crate::revise::groupless::revising_machine!(@spans_face src: $src, Machine: $Machine, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod);
            $crate::revise::groupless::revising_machine!(@verbatim_spans Machine: $Machine, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod);
            $crate::revise::groupless::revising_machine!(@span_walk $cap $acc, Machine: $Machine, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod);
            $crate::revise::groupless::revising_machine!(@canonical $cap $acc, prod: $prod, Machine: $Machine, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod);
        }

    };
    (@views Machine: $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
        /// The output-order span table of one priced save: every emitted
        /// record's handle against its whole-record span in the output —
        #[doc = concat!(" [`", stringify!($Machine), "::save_spans`]'s product.")]
        ///
        /// Entries follow output order (a container precedes and encloses
        /// its interior), and the farthest span end is the save's exact
        /// length.
        #[must_use]
        #[derive(Debug)]
        pub struct SaveSpans {
            entries: Vec<(Handle, Span)>,
        }

        impl SaveSpans {
            /// The number of emitted records in the table.
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

        /// The table entry a machine-minted link names.
        ///
        /// # Safety
        ///
        /// `index` must come from a link this machine minted for
        /// `table` — row ids from arena appends and the `next`/`parent`
        /// links rows store, layer ids from the pushes that seal opened
        /// slots. The tables never shrink, so every minted link stays
        /// in-table for the machine's whole life.
        #[inline]
        unsafe fn linked<T>(table: &[T], index: usize) -> &T {
            debug_assert!(index < table.len(), "links are minted in-table");
            // SAFETY: the caller's link provenance covers the index.
            unsafe { table.get_unchecked(index) }
        }

        /// The next row of a preorder walk bounded to `root`'s subtree:
        /// down the first child, across the sibling chain, climbing on
        /// exhaustion — no stack, no recursion, no allocation.
        fn preorder_next(rows: &[Row], layers: &[Layer], from: RowId, root: RowId) -> Option<RowId> {
            // SAFETY: `from` is a minted row (the walk starts at one and
            // yields only minted links), and an `Opened` slot's layer id
            // was minted by the push that sealed it.
            if let Slot::Opened(layer) = unsafe { linked(rows, from.index()) }.slot()
                && let Some(kid) = unsafe { linked(layers, layer.index()) }.first
            {
                return Some(kid);
            }
            let mut cur = from;
            loop {
                if cur == root {
                    return None;
                }
                // SAFETY: `cur` starts at the minted `from` and advances
                // only through rows' own `parent` links.
                let row = unsafe { linked(rows, cur.index()) };
                if let Some(next) = row.next {
                    return Some(next);
                }
                cur = row.parent?;
            }
        }

        // ─── iterators ───

        /// Sibling records in wire order (shrouded records and ghosts
        /// included — topology is monotone, presentation filters).
        #[must_use]
        pub struct Children<'s> {
            rows: &'s [Row],
            cur: Option<RowId>,
        }

        impl<'s> Children<'s> {
            /// Narrows to records of one field, preserving wire order.
            #[inline]
            pub fn by_field(self, field: FieldNumber) -> impl Iterator<Item = Handle> + 's {
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
        pub struct Ancestors<'s> {
            rows: &'s [Row],
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

    };
    (@frames $Machine:ident $(<$lt:lifetime>)?, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal, frame_doc: [$(#[$frame_send:meta])*], sized_doc: [$(#[$sized_send:meta])*]) => {
        /// The command a staged payload frame closes with.
        #[derive(Clone, Copy)]
        enum FrameOp {
            /// Replace an existing LEN's payload.
            Set {
                /// The gated target.
                handle: Handle,
                /// The live-edit witness the gates produced.
                witness: LiveEdit,
            },
            /// Insert a fresh LEN record at a resolved splice point.
            Insert {
                /// The proven anchor.
                plan: InsertPlan,
                /// The new record's field.
                field: FieldNumber,
            },
        }

        /// Why a sized payload frame refused: the declaration
        /// judgments, plus exactly the two failure classes the
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
            /// The allocator refused growth at the publishing close;
            /// the staged bytes are reclaimed with the frame and the
            /// command may be restaged.
            Resource,
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
                    Self::Resource => f.write_str(concat!("allocator refused ", $noun, " growth")),
                    Self::IndexSpaceExhausted => f.write_str(concat!("the ", $noun, "'s edit storage is full")),
                }
            }
        }

        impl core::error::Error for FrameFault {}

        /// Maps the publishing close's faults onto the frame alphabet.
        /// Total by the close's own domain: it reserves and mints only,
        /// so only the resource and coordinate classes arise there.
        #[cold]
        fn close_fault(fault: EditFault) -> FrameFault {
            match fault {
                EditFault::Resource => FrameFault::Resource,
                EditFault::IndexSpaceExhausted => FrameFault::IndexSpaceExhausted,
                _ => unreachable!("the publishing close reserves and mints only"),
            }
        }

        /// A fallible staged payload frame.
        ///
        #[doc = concat!(" Chunks copy into the ", $noun, "'s store as they arrive, and")]
        /// exactly one command — one logged transition — applies at
        /// [`finish`](PayloadFrame::finish): before it, no row or log
        /// state changes, so a revert can never see a half-staged command
        #[doc = concat!(" and any refusal (allocator faults included) leaves the ", $noun)]
        /// unchanged. Dropping the frame unfinished reclaims its staged
        #[doc = concat!(" bytes — the ", $noun, "'s store returns to its pre-frame byte")]
        /// cursor, span table, and offset space; capacity gained while
        /// staging may be retained for reuse — and its exclusive borrow of the
        #[doc = concat!(" ", $noun, " keeps every other command out while it lives.")]
        $(#[$frame_send])*
        #[must_use = "a payload frame installs nothing until finished"]
        pub struct PayloadFrame<'s $(, $lt)?> {
            machine: &'s mut $Machine$(<$lt>)?,
            op: FrameOp,
            /// The store's byte-column tail at open: the staged extent is
            /// `mark..` for the frame's whole life. In `0..=At32::MAX + 1`
            /// by the column's push judgments.
            mark: u32,
        }

        impl<$($lt)?> Drop for PayloadFrame<'_ $(, $lt)?> {
            /// Reclaims the staged extent: only a publishing
            /// [`finish`](PayloadFrame::finish) keeps the staged bytes,
            /// so abandonment and every refusal path leave the store's
            /// byte cursor, span table, and offset space exactly as the
            /// door found them (reserved capacity may be retained).
            fn drop(&mut self) {
                self.machine.store.stage_abandon(self.mark);
            }
        }

        impl<$($lt)?> PayloadFrame<'_ $(, $lt)?> {
            /// Appends one chunk to the staged payload, copying it at the
            /// call — temporaries welcome; the store owns them. An empty
            /// chunk is a no-op.
            ///
            /// # Errors
            ///
            /// [`EditFault::PayloadTooLarge`] when the staged total would
            /// leave the length class, [`EditFault::Resource`] when the
            /// store cannot grow, [`EditFault::IndexSpaceExhausted`] when
            /// its coordinate space is spent. On `Err` the chunk is not
            /// staged and the frame stays usable.
            pub fn write(&mut self, chunk: &[u8]) -> Result<(), EditFault> {
                let staged = u64::from(self.machine.store.stage_mark() - self.mark);
                #[allow(clippy::as_conversions, reason = "chunk lengths widen losslessly to u64")]
                let total = staged.saturating_add(chunk.len() as u64);
                if total > u64::from(PayloadLen::MAX.as_inner()) {
                    let len = usize::try_from(total).unwrap_or(usize::MAX);
                    return Err(EditFault::PayloadTooLarge { len });
                }
                self.machine.store.stage_chunk(chunk).map_err(edit_store_fault)?;
                Ok(())
            }

            /// Installs the staged payload: the set flips its record, the
            /// insert splices exactly one fresh row — one logged
            /// transition either way, appended now. Returns the changed
            /// record's handle (the set's own target, or the minted
            /// insertion).
            ///
            /// # Errors
            ///
            /// [`EditFault::Resource`] when the row or log reservation is
            /// refused, [`EditFault::IndexSpaceExhausted`] when a
            #[doc = concat!(" coordinate space is spent. On `Err` the ", $noun, " is")]
            /// unchanged — the staged bytes are reclaimed with the frame,
            /// so the whole save may be restaged and retried.
            pub fn finish(mut self) -> Result<Handle, EditFault> {
                match self.apply() {
                    Ok(handle) => {
                        // Published: the span now covers the staged
                        // extent, so defuse the drop reclamation.
                        core::mem::forget(self);
                        Ok(handle)
                    }
                    // Dropping the frame reclaims the staged extent.
                    Err(fault) => Err(fault),
                }
            }

            /// The publishing close: reserves, mints the span, applies
            /// the one command.
            fn apply(&mut self) -> Result<Handle, EditFault> {
                match self.op {
                    FrameOp::Set { handle, witness } => {
                        // The gates judged at open; the frame's exclusive
                        // borrow kept the row exactly as they left it.
                        self.machine.log.try_reserve(1).map_err(edit_resource)?;
                        let at = self.machine.store.stage_finish(self.mark).map_err(edit_store_fault)?;
                        self.machine.apply_edit(handle.0, witness.set(at));
                        Ok(handle)
                    }
                    FrameOp::Insert { plan, field } => {
                        let id = self.machine.mint_insert()?;
                        self.machine.rows.try_reserve(1).map_err(edit_resource)?;
                        self.machine.log.try_reserve(1).map_err(edit_resource)?;
                        let at = self.machine.store.stage_finish(self.mark).map_err(edit_store_fault)?;
                        self.machine.apply_insert(&plan, id, field, RecordKind::Len, at);
                        Ok(Handle(id))
                    }
                }
            }
        }

        /// A fallible staged payload frame held to a declared length.
        ///
        /// The declaration was judged and its bytes reserved when the door
        #[doc = concat!(" opened ([`", stringify!($Machine), "::begin_set_payload_sized`],")]
        #[doc = concat!(" [`", stringify!($Machine), "::begin_insert_payload_sized`]), so staging never")]
        /// regrows the column; a write past the declaration refuses
        /// [`FrameFault::OverDeclared`] and [`finish`](Self::finish)
        /// installs only the exact declared extent —
        /// [`FrameFault::UnderDeclared`] otherwise. The declaration
        /// judgments live on the frame faces alone, so the sized faces
        /// speak [`FrameFault`]; everything else is the undeclared
        /// frame's contract: chunks copy in as they arrive, exactly one
        /// logged transition applies at the finish, and a dropped or
        /// refused frame reclaims its staged bytes.
        $(#[$sized_send])*
        #[must_use = "a payload frame installs nothing until finished"]
        pub struct SizedPayloadFrame<'s $(, $lt)?> {
            inner: PayloadFrame<'s $(, $lt)?>,
            /// The declared payload length, in the length class.
            declared: u32,
        }

        impl<$($lt)?> SizedPayloadFrame<'_ $(, $lt)?> {
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
                let staged = u64::from(self.inner.machine.store.stage_mark() - self.inner.mark);
                #[allow(clippy::as_conversions, reason = "chunk lengths widen losslessly to u64")]
                let total = staged.saturating_add(chunk.len() as u64);
                if total > u64::from(self.declared) {
                    return Err(FrameFault::OverDeclared { declared: self.declared, total });
                }
                // The door judged the declaration into the length class
                // and the byte column's offset domain and reserved its
                // bytes; the gate above bounds the staged total inside
                // the declaration, so this append stays inside both.
                self.inner.machine.store.stage_chunk_reserved(chunk);
                Ok(())
            }

            /// Installs the staged payload exactly as declared — the
            /// undeclared frame's [`finish`](PayloadFrame::finish), behind
            /// the declaration judgment.
            ///
            /// # Errors
            ///
            /// [`FrameFault::UnderDeclared`] when fewer bytes than declared
            /// were staged, then the publishing close's faults:
            /// [`FrameFault::Resource`] when the row or log reservation is
            /// refused, [`FrameFault::IndexSpaceExhausted`] when a
            #[doc = concat!(" coordinate space is spent. On `Err` the ", $noun, " is")]
            /// unchanged — the staged bytes are reclaimed with the frame.
            pub fn finish(self) -> Result<Handle, FrameFault> {
                let staged = self.inner.machine.store.stage_mark() - self.inner.mark;
                if staged != self.declared {
                    return Err(FrameFault::UnderDeclared { declared: self.declared, staged });
                }
                self.inner.finish().map_err(close_fault)
            }
        }

    };
    (@mix_frames $Machine:ident <$($lt:lifetime),+>, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal, frame_doc: [$(#[$frame_send:meta])*], sized_doc: [$(#[$sized_send:meta])*]) => {
        /// A fallible staged payload frame over the mixed-backing
        #[doc = concat!(" ", $noun, ".")]
        ///
        /// Chunks copy into the copied byte column as they arrive, and
        /// exactly one command — one logged transition, one fresh
        /// copied slot — applies at
        /// [`finish`](MixPayloadFrame::finish): before it, no row, log,
        /// or slot state changes, so a revert can never see a
        /// half-staged command and any refusal (allocator faults
        #[doc = concat!(" included) leaves the ", $noun, " unchanged. Dropping the frame")]
        /// unfinished reclaims its staged bytes — the copied byte
        /// column returns to its pre-frame cursor and offset space,
        /// while borrowed slots are never touched by staging; capacity
        /// gained while staging may be retained — and its exclusive
        #[doc = concat!(" borrow of the ", $noun, " keeps every other command out while")]
        /// it lives.
        $(#[$frame_send])*
        #[must_use = "a payload frame installs nothing until finished"]
        pub struct MixPayloadFrame<'s, $($lt),+> {
            machine: &'s mut $Machine<$($lt),+>,
            op: FrameOp,
            /// The store's byte-column tail at open: the staged extent is
            /// `mark..` for the frame's whole life. In `0..=At32::MAX + 1`
            /// by the column's push judgments.
            mark: u32,
        }

        impl<$($lt),+> Drop for MixPayloadFrame<'_, $($lt),+> {
            /// Reclaims the staged extent: only a publishing
            /// [`finish`](MixPayloadFrame::finish) keeps the staged
            /// bytes, so abandonment and every refusal path leave the
            /// store's byte cursor, slot table, and offset space exactly
            /// as the door found them (reserved capacity may be
            /// retained).
            fn drop(&mut self) {
                self.machine.store.stage_abandon(self.mark);
            }
        }

        impl<$($lt),+> MixPayloadFrame<'_, $($lt),+> {
            /// Appends one chunk to the staged payload, copying it at the
            /// call — temporaries welcome; the store owns them. An empty
            /// chunk is a no-op.
            ///
            /// # Errors
            ///
            /// [`EditFault::PayloadTooLarge`] when the staged total would
            /// leave the length class, [`EditFault::Resource`] when the
            /// store cannot grow, [`EditFault::IndexSpaceExhausted`] when
            /// its coordinate space is spent. On `Err` the chunk is not
            /// staged and the frame stays usable.
            pub fn write(&mut self, chunk: &[u8]) -> Result<(), EditFault> {
                let staged = u64::from(self.machine.store.stage_mark() - self.mark);
                #[allow(clippy::as_conversions, reason = "chunk lengths widen losslessly to u64")]
                let total = staged.saturating_add(chunk.len() as u64);
                if total > u64::from(PayloadLen::MAX.as_inner()) {
                    let len = usize::try_from(total).unwrap_or(usize::MAX);
                    return Err(EditFault::PayloadTooLarge { len });
                }
                self.machine.store.stage_chunk(chunk).map_err(edit_store_fault)?;
                Ok(())
            }

            /// Installs the staged payload: the set flips its record, the
            /// insert splices exactly one fresh row — one logged
            /// transition either way, appended now. Returns the changed
            /// record's handle (the set's own target, or the minted
            /// insertion).
            ///
            /// # Errors
            ///
            /// [`EditFault::Resource`] when the row or log reservation is
            /// refused, [`EditFault::IndexSpaceExhausted`] when a
            #[doc = concat!(" coordinate space is spent. On `Err` the ", $noun, " is")]
            /// unchanged — the staged bytes are reclaimed with the frame,
            /// so the whole save may be restaged and retried.
            pub fn finish(mut self) -> Result<Handle, EditFault> {
                match self.apply() {
                    Ok(handle) => {
                        // Published: the slot now covers the staged
                        // extent, so defuse the drop reclamation.
                        core::mem::forget(self);
                        Ok(handle)
                    }
                    // Dropping the frame reclaims the staged extent.
                    Err(fault) => Err(fault),
                }
            }

            /// The publishing close: reserves, mints the slot, applies
            /// the one command.
            fn apply(&mut self) -> Result<Handle, EditFault> {
                match self.op {
                    FrameOp::Set { handle, witness } => {
                        // The gates judged at open; the frame's exclusive
                        // borrow kept the row exactly as they left it.
                        self.machine.log.try_reserve(1).map_err(edit_resource)?;
                        let at = self.machine.store.stage_finish(self.mark).map_err(edit_store_fault)?;
                        self.machine.apply_edit(handle.0, witness.set(at));
                        Ok(handle)
                    }
                    FrameOp::Insert { plan, field } => {
                        let id = self.machine.mint_insert()?;
                        self.machine.rows.try_reserve(1).map_err(edit_resource)?;
                        self.machine.log.try_reserve(1).map_err(edit_resource)?;
                        let at = self.machine.store.stage_finish(self.mark).map_err(edit_store_fault)?;
                        self.machine.apply_insert(&plan, id, field, RecordKind::Len, at);
                        Ok(Handle(id))
                    }
                }
            }
        }

        /// A fallible staged payload frame held to a declared length,
        #[doc = concat!(" over the mixed-backing ", $noun, ".")]
        ///
        /// The declaration was judged and its bytes reserved when the door
        #[doc = concat!(" opened ([`", stringify!($Machine), "::begin_set_payload_sized`],")]
        #[doc = concat!(" [`", stringify!($Machine), "::begin_insert_payload_sized`]), so staging never")]
        /// regrows the column; a write past the declaration refuses
        /// [`FrameFault::OverDeclared`] and [`finish`](Self::finish)
        /// installs only the exact declared extent —
        /// [`FrameFault::UnderDeclared`] otherwise. The declaration
        /// judgments live on the frame faces alone, so the sized faces
        /// speak [`FrameFault`]; everything else is the undeclared
        /// frame's contract: chunks copy in as they arrive, exactly one
        /// logged transition applies at the finish, and a dropped or
        /// refused frame reclaims its staged bytes.
        $(#[$sized_send])*
        #[must_use = "a payload frame installs nothing until finished"]
        pub struct MixSizedPayloadFrame<'s, $($lt),+> {
            inner: MixPayloadFrame<'s, $($lt),+>,
            /// The declared payload length, in the length class.
            declared: u32,
        }

        impl<$($lt),+> MixSizedPayloadFrame<'_, $($lt),+> {
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
                let staged = u64::from(self.inner.machine.store.stage_mark() - self.inner.mark);
                #[allow(clippy::as_conversions, reason = "chunk lengths widen losslessly to u64")]
                let total = staged.saturating_add(chunk.len() as u64);
                if total > u64::from(self.declared) {
                    return Err(FrameFault::OverDeclared { declared: self.declared, total });
                }
                // The door judged the declaration into the length class
                // and the byte column's offset domain and reserved its
                // bytes; the gate above bounds the staged total inside
                // the declaration, so this append stays inside both.
                self.inner.machine.store.stage_chunk_reserved(chunk);
                Ok(())
            }

            /// Installs the staged payload exactly as declared — the
            /// undeclared frame's [`finish`](MixPayloadFrame::finish),
            /// behind the declaration judgment.
            ///
            /// # Errors
            ///
            /// [`FrameFault::UnderDeclared`] when fewer bytes than declared
            /// were staged, then the publishing close's faults:
            /// [`FrameFault::Resource`] when the row or log reservation is
            /// refused, [`FrameFault::IndexSpaceExhausted`] when a
            #[doc = concat!(" coordinate space is spent. On `Err` the ", $noun, " is")]
            /// unchanged — the staged bytes are reclaimed with the frame.
            pub fn finish(self) -> Result<Handle, FrameFault> {
                let staged = self.inner.machine.store.stage_mark() - self.inner.mark;
                if staged != self.declared {
                    return Err(FrameFault::UnderDeclared { declared: self.declared, staged });
                }
                self.inner.finish().map_err(close_fault)
            }
        }

    };
    (@priced_frozen plain, $Priced:ident over $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
    };
    (@priced_frozen $cap:ident, $Priced:ident over $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
        /// True when the state emits nothing at the save: shrouds,
        /// ghosts, and moved sources. A settling climb freezes at the
        /// first frozen ancestor — the subtree prices zero either way —
        /// and the reservation walk stops no later than the climb will.
        const fn priced_frozen(edit: Edit) -> bool {
            matches!(
                edit,
                Edit::Deleted(_)
                    | Edit::InsertedDeleted(_)
                    | Edit::Moved { .. }
                    | Edit::SourceRecordDeleted
                    | Edit::SourcePayloadDeleted(_)
                    | Edit::SourceInsertedDeleted(_)
                    | Edit::ImportedDeleted(_)
            )
        }
    };
    (@priced_seed plain, $Priced:ident over $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
        /// A container's body length with no ledger entry: the length
        /// its interior prices while every member is untouched. For a
        /// scanned LEN that is its source payload length; command-
        /// authored containers exist only in the grouped dialect.
        fn priced_seed(machine: &$Machine, row: &Row) -> u64 {
            row.at.map_or(0, |at| u64::from(machine.len_geometry(row, at).1))
        }
    };
    (@priced_seed transfer, $Priced:ident over $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
        /// A container's body length with no ledger entry: the length
        /// its interior prices while every member is untouched. For a
        /// scanned LEN that is its source payload length; for a
        /// designated payload it is the designated subspan's length;
        /// for an import root it is the slot's body length; command-
        /// authored containers exist only in the grouped dialect.
        fn priced_seed(machine: &$Machine, row: &Row) -> u64 {
            match row.edit {
                Edit::SourcePayload(src)
                | Edit::SourcePayloadDeleted(src)
                | Edit::SourceInserted(src)
                | Edit::SourceInsertedDeleted(src) => {
                    u64::from(machine.designated_payload(src).1)
                }
                Edit::Imported(value) | Edit::ImportedDeleted(value) => {
                    u64::from(crate::admission::admitted_u32(machine.import_payload(value).len()))
                }
                _ => row.at.map_or(0, |at| u64::from(machine.len_geometry(row, at).1)),
            }
        }
    };
    (@priced_seed $cap:ident, $Priced:ident over $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
        /// A container's body length with no ledger entry: the length
        /// its interior prices while every member is untouched. For a
        /// scanned LEN that is its source payload length; for a
        /// designated payload it is the designated subspan's length;
        /// command-authored containers exist only in the grouped
        /// dialect.
        fn priced_seed(machine: &$Machine, row: &Row) -> u64 {
            match row.edit {
                Edit::SourcePayload(src)
                | Edit::SourcePayloadDeleted(src)
                | Edit::SourceInserted(src)
                | Edit::SourceInsertedDeleted(src) => {
                    u64::from(machine.designated_payload(src).1)
                }
                _ => row.at.map_or(0, |at| u64::from(machine.len_geometry(row, at).1)),
            }
        }
    };
    (@priced_row_cost plain, $Priced:ident over $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
        /// One row's exact contribution to the save, under the row's
        /// current interior: the settle dispatch priced instead of
        /// emitted, so the save arms and their prices cannot drift
        /// apart. Container bodies read entry-or-seed, exact through
        /// over-cap states (`encoded_len64` extends the prefix width
        /// beyond the length class monotonically). Every arm's result
        /// is an exact sum of emission widths below the shared
        /// layer's `PRICE_CEILING` — the arithmetic theorem every
        /// downstream price operation spends.
        fn priced_row_cost(
            machine: &$Machine,
            bodies: &$crate::revise::FxMap<RowId, u64>,
            id: RowId,
            row: &Row,
        ) -> u64 {
            match machine.settle(row) {
                Arm::Skip => 0,
                Arm::Clean { at, end } => u64::from(end - at.as_inner()),
                Arm::Varint { head, word } => {
                    u64::from(encoded_len32(head)) + u64::from(encoded_len64(word))
                }
                Arm::Bits32 { head, .. } => u64::from(encoded_len32(head)) + 4,
                Arm::Bits64 { head, .. } => u64::from(encoded_len32(head)) + 8,
                Arm::Body { head, value } => {
                    let (_, len) = machine.store.span(value);
                    u64::from(encoded_len32(head)) + u64::from(encoded_len32(len)) + u64::from(len)
                }
                Arm::Spine { head, .. } => {
                    let body =
                        bodies.get(&id).copied().unwrap_or_else(|| priced_seed(machine, row));
                    u64::from(encoded_len32(head)) + u64::from(encoded_len64(body)) + body
                }
            }
        }
    };
    (@priced_row_cost $cap:ident, $Priced:ident over $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
        /// One row's exact contribution to the save, under the row's
        /// current interior: the settle dispatch priced instead of
        /// emitted, so the save arms and their prices cannot drift
        /// apart. Container bodies read entry-or-seed, exact through
        /// over-cap states (`encoded_len64` extends the prefix width
        /// beyond the length class monotonically). Every arm's result
        /// is an exact sum of emission widths below the shared
        /// layer's `PRICE_CEILING` — the arithmetic theorem every
        /// downstream price operation spends.
        fn priced_row_cost(
            machine: &$Machine,
            bodies: &$crate::revise::FxMap<RowId, u64>,
            id: RowId,
            row: &Row,
        ) -> u64 {
            match machine.settle(row) {
                Arm::Skip => 0,
                Arm::Clean { at, end } => u64::from(end - at.as_inner()),
                Arm::Varint { head, word } => {
                    u64::from(encoded_len32(head)) + u64::from(encoded_len64(word))
                }
                Arm::Bits32 { head, .. } => u64::from(encoded_len32(head)) + 4,
                Arm::Bits64 { head, .. } => u64::from(encoded_len32(head)) + 8,
                Arm::Body { head, value } => {
                    let (_, len) = machine.store.span(value);
                    u64::from(encoded_len32(head)) + u64::from(encoded_len32(len)) + u64::from(len)
                }
                Arm::BodyAlias { head, len, .. } => {
                    u64::from(encoded_len32(head)) + u64::from(encoded_len32(len)) + u64::from(len)
                }
                Arm::Import { value } => u64::from(machine.store.span(value).1),
                Arm::Spine { head, .. } => {
                    let body =
                        bodies.get(&id).copied().unwrap_or_else(|| priced_seed(machine, row));
                    u64::from(encoded_len32(head)) + u64::from(encoded_len64(body)) + body
                }
            }
        }
    };
    (@priced_admit plain, $Priced:ident over $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
        /// The admission walk: prices the whole visible tree in the
        /// emit pass's stackless parent-link form, with the ledger
        /// entries as the open containers' accumulators. Opened layers
        /// carrying dirt are entered even under shrouded rows — the
        /// sizing walk prunes those, but a missing entry would seed a
        /// later shroud lift from the source length instead of the
        /// edited interior.
        fn priced_admit(
            machine: &$Machine,
            bodies: &mut $crate::revise::FxMap<RowId, u64>,
        ) -> Result<(u64, u32), PriceFault> {
            let cap = u64::from(PayloadLen::MAX.as_inner());
            let mut total: u64 = 0;
            let mut over_caps: u32 = 0;
            let mut open: Option<RowId> = None;
            // Clean siblings tile their layer's source: a run prices as
            // one subtraction at its boundary.
            let mut run: Option<(u32, RowId)> = None;
            let mut cur = machine.root.first;
            loop {
                let Some(id) = cur else {
                    if let Some((from, last)) = run.take() {
                        let span = u64::from(machine.row(last).end - from);
                        priced_accumulate(bodies, &mut total, open, span);
                    }
                    let Some(container) = open else { break };
                    let row = machine.row(container);
                    let Some(&body) = bodies.get(&container) else {
                        unreachable!(concat!($noun, " price: a walked container lost its entry"))
                    };
                    // Each closing container is counted once, so the
                    // census stays a subset of the ledger:
                    // `over_caps <= bodies.len()` (the shared layer's
                    // census corollary).
                    if body > cap {
                        over_caps += 1;
                    }
                    let price = priced_row_cost(machine, bodies, container, row);
                    priced_accumulate(bodies, &mut total, row.parent, price);
                    cur = row.next;
                    open = row.parent;
                    continue;
                };
                let row = machine.row(id);
                if matches!(row.edit, Edit::Intact) && !row.dirty() {
                    // SAFETY: the Intact arm is outside the Inserted
                    // family.
                    let at = unsafe { scanned_at(row) };
                    match &mut run {
                        Some((_, last)) => *last = id,
                        None => run = Some((at.as_inner(), id)),
                    }
                    cur = row.next;
                    continue;
                }
                if let Some((from, last)) = run.take() {
                    let span = u64::from(machine.row(last).end - from);
                    priced_accumulate(bodies, &mut total, open, span);
                }
                let descend = match row.slot() {
                    Slot::Opened(layer) => {
                        (machine.layer(layer).dirty_kids > 0).then(|| machine.layer(layer).first)
                    }
                    Slot::Unopened | Slot::Fault(_) => None,
                };
                if let Some(first) = descend {
                    if bodies.try_reserve(1).is_err() {
                        return Err(PriceFault::Resource);
                    }
                    bodies.insert(id, 0);
                    open = Some(id);
                    cur = first;
                    continue;
                }
                let price = priced_row_cost(machine, bodies, id, row);
                priced_accumulate(bodies, &mut total, open, price);
                cur = row.next;
            }
            Ok((total, over_caps))
        }
    };
    (@priced_admit $cap:ident, $Priced:ident over $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
        /// The admission walk: prices the whole visible tree in the
        /// emit pass's stackless parent-link form, with the ledger
        /// entries as the open containers' accumulators. Opened layers
        /// carrying dirt are entered even under shrouded rows — the
        /// sizing walk prunes those, but a missing entry would seed a
        /// later shroud lift from the source length instead of the
        /// edited interior.
        fn priced_admit(
            machine: &$Machine,
            bodies: &mut $crate::revise::FxMap<RowId, u64>,
        ) -> Result<(u64, u32), PriceFault> {
            let cap = u64::from(PayloadLen::MAX.as_inner());
            let mut total: u64 = 0;
            let mut over_caps: u32 = 0;
            let mut open: Option<RowId> = None;
            // Clean siblings tile their layer's source: a run prices as
            // one subtraction at its boundary.
            let mut run: Option<(u32, RowId)> = None;
            let mut cur = machine.root.first;
            loop {
                let Some(id) = cur else {
                    if let Some((from, last)) = run.take() {
                        let span = u64::from(machine.row(last).end - from);
                        priced_accumulate(bodies, &mut total, open, span);
                    }
                    let Some(container) = open else { break };
                    let row = machine.row(container);
                    let Some(&body) = bodies.get(&container) else {
                        unreachable!(concat!($noun, " price: a walked container lost its entry"))
                    };
                    // Each closing container is counted once, so the
                    // census stays a subset of the ledger:
                    // `over_caps <= bodies.len()` (the shared layer's
                    // census corollary).
                    if body > cap {
                        over_caps += 1;
                    }
                    let price = priced_row_cost(machine, bodies, container, row);
                    priced_accumulate(bodies, &mut total, row.parent, price);
                    cur = row.next;
                    open = row.parent;
                    continue;
                };
                let row = machine.row(id);
                if matches!(row.edit, Edit::Intact) && !row.dirty() {
                    // SAFETY: the Intact arm is outside the Inserted
                    // family.
                    let at = unsafe { scanned_at(row) };
                    match &mut run {
                        Some((_, last)) => *last = id,
                        None => run = Some((at.as_inner(), id)),
                    }
                    cur = row.next;
                    continue;
                }
                if let Some((from, last)) = run.take() {
                    let span = u64::from(machine.row(last).end - from);
                    priced_accumulate(bodies, &mut total, open, span);
                }
                let descend = match row.slot() {
                    Slot::Opened(layer) => {
                        (machine.layer(layer).dirty_kids > 0).then(|| machine.layer(layer).first)
                    }
                    Slot::Unopened | Slot::Fault(_) => None,
                };
                if let Some(first) = descend {
                    if bodies.try_reserve(1).is_err() {
                        return Err(PriceFault::Resource);
                    }
                    bodies.insert(id, 0);
                    open = Some(id);
                    cur = first;
                    continue;
                }
                let price = priced_row_cost(machine, bodies, id, row);
                priced_accumulate(bodies, &mut total, open, price);
                cur = row.next;
            }
            Ok((total, over_caps))
        }
    };
    (@priced_climbs plain, $Priced:ident over $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// Reserves exactly the settling climb's missing ledger
            /// entries. Along any chain a climb can reach, entries
            /// form a suffix: a settling climb seeds every level it
            /// visits, from the leaf's parent contiguously up to its
            /// freeze point, the admission walk seeds ancestor-closed
            /// sets, a shroud lift re-seeds the levels it exposes
            /// through its own settling climb (a lift always moves the
            /// price: frozen states cost zero, live rows at least
            /// their head byte), and entries are never removed. The
            /// walk therefore prices only the missing prefix — it
            /// stops at the first level already carrying an entry, or
            /// with the first shrouded or ghost level, the climb's own
            /// stop — and reserves once for that count. A chain
            /// already carrying its entries reserves nothing and never
            /// touches the allocator.
            fn reserve_climb(&mut self, start: Option<RowId>) -> Result<(), EditFault> {
                let mut missing = 0usize;
                let mut cur = start;
                while let Some(id) = cur {
                    if self.bodies.contains_key(&id) {
                        break;
                    }
                    missing += 1;
                    let row = self.machine.row(id);
                    if matches!(row.edit, Edit::Deleted(_) | Edit::InsertedDeleted(_)) {
                        break;
                    }
                    cur = row.parent;
                }
                if missing == 0 {
                    return Ok(());
                }
                self.bodies.try_reserve(missing).map_err(priced_resource)
            }

            /// One row's price after a pending replacement, before the
            /// value lands in the store: the head stays (value commands
            /// move neither field nor kind), so the settle dispatch's
            /// verdict is the head width plus the incoming value's own
            /// width. Exact against [`priced_row_cost`] on the committed
            /// row: the committed arm prices the stored value it finds,
            /// which is this one.
            fn planned_value_cost(row: &Row, width: u64) -> u64 {
                u64::from(encoded_len32(head_word(row.field, row.kind))) + width
            }

            /// Carries a settled price delta from `from`'s parent to the
            /// root: per level the body updates (lazily seeded at first
            /// dirt), the length-class census counts the crossing, the
            /// climb freezes at the first shrouded or ghost ancestor
            /// (bodies below keep updating; nothing above can observe
            /// the change), and otherwise the delta grows by the prefix
            /// width's own movement. The root adds the surviving delta
            /// to the document total. Additions wrap in the signed
            /// domain and never wrap in truth: every ledger value is an
            /// exact sum below the shared layer's `PRICE_CEILING`, and
            /// the debug asserts are that theorem's checked form.
            fn settle_climb(&mut self, from: RowId, mut delta: i64) {
                if delta == 0 {
                    // A zero leaf delta moves no body, and the delta
                    // stays zero through every level (prefix widths move
                    // only with their bodies), so nothing can cross the
                    // census or reach the total.
                    return;
                }
                let cap = u64::from(PayloadLen::MAX.as_inner());
                let mut cur = self.machine.row(from).parent;
                while let Some(id) = cur {
                    let row = *self.machine.row(id);
                    let machine = &self.machine;
                    let body = self.bodies.entry(id).or_insert_with(|| priced_seed(machine, &row));
                    let old = *body;
                    let new = old.wrapping_add_signed(delta);
                    debug_assert!(new <= PRICE_CEILING, "a settled body left the ceiling");
                    *body = new;
                    if (old > cap) != (new > cap) {
                        if new > cap {
                            self.over_caps += 1;
                        } else {
                            // A downward crossing decrements the count
                            // its own upward crossing raised:
                            // `over_caps <= bodies.len()` (the shared
                            // layer's census corollary), so the
                            // subtraction cannot underflow.
                            self.over_caps -= 1;
                        }
                    }
                    if matches!(row.edit, Edit::Deleted(_) | Edit::InsertedDeleted(_)) {
                        // Frozen at the shroud: the subtree prices zero
                        // either way, and the updated bodies below wait
                        // for the lift.
                        return;
                    }
                    delta += i64::from(encoded_len64(new)) - i64::from(encoded_len64(old));
                    cur = row.parent;
                }
                self.total = self.total.wrapping_add_signed(delta);
                debug_assert!(self.total <= PRICE_CEILING, "the settled total left the ceiling");
            }
    };
    (@priced_climbs $cap:ident, $Priced:ident over $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// Reserves exactly the settling climb's missing ledger
            /// entries. Along any chain a climb can reach, entries
            /// form a suffix: a settling climb seeds every level it
            /// visits, from the leaf's parent contiguously up to its
            /// freeze point, the admission walk seeds ancestor-closed
            /// sets, a shroud lift re-seeds the levels it exposes
            /// through its own settling climb (a lift always moves the
            /// price: frozen states cost zero, live rows at least
            /// their head byte), and entries are never removed. The
            /// walk therefore prices only the missing prefix — it
            /// stops at the first level already carrying an entry, or
            /// with the first shrouded or ghost level, the climb's own
            /// stop.
            fn missing_climb(&self, start: Option<RowId>) -> usize {
                let mut missing = 0usize;
                let mut cur = start;
                while let Some(id) = cur {
                    if self.bodies.contains_key(&id) {
                        break;
                    }
                    missing += 1;
                    let row = self.machine.row(id);
                    if priced_frozen(row.edit) {
                        break;
                    }
                    cur = row.parent;
                }
                missing
            }

            /// Reserves once for one chain's missing count
            /// ([`missing_climb`](Self::missing_climb)); a chain
            /// already carrying its entries reserves nothing and
            /// never touches the allocator. Faces that settle two
            /// chains in one command reserve the counts' sum
            /// instead — see the move faces.
            fn reserve_climb(&mut self, start: Option<RowId>) -> Result<(), EditFault> {
                let missing = self.missing_climb(start);
                if missing == 0 {
                    return Ok(());
                }
                self.bodies.try_reserve(missing).map_err(priced_resource)
            }

            /// One row's price after a pending replacement, before the
            /// value lands in the store: the head stays (value commands
            /// move neither field nor kind), so the settle dispatch's
            /// verdict is the head width plus the incoming value's own
            /// width. Exact against [`priced_row_cost`] on the committed
            /// row: the committed arm prices the stored value it finds,
            /// which is this one.
            fn planned_value_cost(row: &Row, width: u64) -> u64 {
                u64::from(encoded_len32(head_word(row.field, row.kind))) + width
            }

            /// Carries a settled price delta from `from`'s parent to the
            /// root: per level the body updates (lazily seeded at first
            /// dirt), the length-class census counts the crossing, the
            /// climb freezes at the first shrouded or ghost ancestor
            /// (bodies below keep updating; nothing above can observe
            /// the change), and otherwise the delta grows by the prefix
            /// width's own movement. The root adds the surviving delta
            /// to the document total. Additions wrap in the signed
            /// domain and never wrap in truth: every ledger value is an
            /// exact sum below the shared layer's `PRICE_CEILING`, and
            /// the debug asserts are that theorem's checked form.
            fn settle_climb(&mut self, from: RowId, mut delta: i64) {
                if delta == 0 {
                    // A zero leaf delta moves no body, and the delta
                    // stays zero through every level (prefix widths move
                    // only with their bodies), so nothing can cross the
                    // census or reach the total.
                    return;
                }
                let cap = u64::from(PayloadLen::MAX.as_inner());
                let mut cur = self.machine.row(from).parent;
                while let Some(id) = cur {
                    let row = *self.machine.row(id);
                    let machine = &self.machine;
                    let body = self.bodies.entry(id).or_insert_with(|| priced_seed(machine, &row));
                    let old = *body;
                    let new = old.wrapping_add_signed(delta);
                    debug_assert!(new <= PRICE_CEILING, "a settled body left the ceiling");
                    *body = new;
                    if (old > cap) != (new > cap) {
                        if new > cap {
                            self.over_caps += 1;
                        } else {
                            // A downward crossing decrements the count
                            // its own upward crossing raised:
                            // `over_caps <= bodies.len()` (the shared
                            // layer's census corollary), so the
                            // subtraction cannot underflow.
                            self.over_caps -= 1;
                        }
                    }
                    if priced_frozen(row.edit) {
                        // Frozen at the shroud: the subtree prices zero
                        // either way, and the updated bodies below wait
                        // for the lift.
                        return;
                    }
                    delta += i64::from(encoded_len64(new)) - i64::from(encoded_len64(old));
                    cur = row.parent;
                }
                self.total = self.total.wrapping_add_signed(delta);
                debug_assert!(self.total <= PRICE_CEILING, "the settled total left the ceiling");
            }
    };
    (@priced_transfer_faces plain, $Priced:ident over $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {};
    (@priced_transfer_faces $cap:ident, $Priced:ident over $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            // ── source transfer ──

            /// Copies the designated record to the anchor and settles
            #[doc = concat!(" the price — [`", stringify!($Machine), "::copy_record`] under the")]
            /// maintenance protocol: the source and anchor gates first,
            /// the copy's exact span cost derived next, every base
            /// obligation and the ledger's exact missing entries
            /// reserved behind them, and the splice with its settling
            /// climb infallible.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::copy_record`]; [`EditFault::Resource`]")]
            /// also covers a refused ledger reservation. On any `Err`
            #[doc = concat!(" the ", $noun, " and its prices are unchanged.")]
            ///
            /// # Panics
            ///
            /// Panics if a handle inside the arguments was not minted by
            #[doc = concat!(" this ", $noun, " (the arena index contract).")]
            ///
            /// # Examples
            ///
            /// ```
            #[doc = concat!(" use ", $doc_mod, "::{InsertAt, ", stringify!($Machine), "};")]
            ///
            /// let msg = [0x08, 0x05, 0x10, 0x06];
            #[doc = concat!(" let ", $noun, " = ", $door, ".unwrap();")]
            #[doc = concat!(" let Ok(mut priced) = ", $noun, ".into_priced() else { unreachable!() };")]
            /// let first = priced.top().next().unwrap();
            /// priced.copy_record(first, InsertAt::TailOf(None)).unwrap();
            /// assert_eq!(priced.save_len(), Ok(6));
            /// assert_eq!(priced.save().unwrap()[..], [0x08, 0x05, 0x10, 0x06, 0x08, 0x05]);
            /// ```
            #[track_caller]
            pub fn copy_record(&mut self, source: Handle, at: InsertAt) -> Result<Handle, EditFault> {
                let src = self.machine.transfer_source(source)?;
                let plan = self.machine.resolve_anchor(at)?;
                let id = self.insert_obligations()?;
                // SAFETY: transfer sources are original occurrences with
                // geometry.
                let to = u64::from(src.end - unsafe { scanned_at(&src) }.as_inner());
                self.reserve_climb(plan.parent)?;
                let next = self.machine.plan_next(&plan);
                self.machine.apply_transfer(
                    &plan,
                    id,
                    src.cloned_alias(plan.parent, next),
                    Edit::SourceRecord,
                );
                self.settle_climb(id, priced_delta(to, 0));
                #[cfg(debug_assertions)]
                self.assert_prices();
                Ok(Handle(id))
            }

            /// Moves the designated record to the anchor and settles the
            #[doc = concat!(" price — [`", stringify!($Machine), "::move_record`] under the maintenance")]
            /// protocol. The destination's gain and the source's
            /// suppression are the same exact span cost, derived once:
            /// the two settling climbs carry `+cost` and `-cost`, so a
            /// move inside one container prices zero.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::move_record`]; [`EditFault::Resource`]")]
            /// also covers a refused ledger reservation. On any `Err`
            #[doc = concat!(" the ", $noun, " and its prices are unchanged.")]
            ///
            /// # Panics
            ///
            /// Panics if a handle inside the arguments was not minted by
            #[doc = concat!(" this ", $noun, " (the arena index contract).")]
            ///
            /// # Examples
            ///
            /// ```
            #[doc = concat!(" use ", $doc_mod, "::{InsertAt, ", stringify!($Machine), "};")]
            ///
            /// let msg = [0x08, 0x05, 0x10, 0x06];
            #[doc = concat!(" let ", $noun, " = ", $door, ".unwrap();")]
            #[doc = concat!(" let Ok(mut priced) = ", $noun, ".into_priced() else { unreachable!() };")]
            /// let tops: Vec<_> = priced.top().collect();
            /// priced.move_record(tops[0], InsertAt::After(tops[1])).unwrap();
            /// assert_eq!(priced.save_len(), Ok(4));
            /// assert_eq!(priced.save().unwrap()[..], [0x10, 0x06, 0x08, 0x05]);
            /// priced.revert();
            /// assert_eq!(priced.save().unwrap()[..], msg);
            /// ```
            #[track_caller]
            pub fn move_record(&mut self, source: Handle, at: InsertAt) -> Result<Handle, EditFault> {
                let src = self.machine.move_source(source)?;
                let plan = self.machine.resolve_anchor(at)?;
                self.machine.move_gap_gate(&plan, source.0)?;
                let id = self.insert_obligations()?;
                // SAFETY: move sources are original occurrences with
                // geometry.
                let cost = u64::from(src.end - unsafe { scanned_at(&src) }.as_inner());
                // Two chains can be missing disjoint ledger prefixes:
                // reserve their sum (a shared ancestor double-counts
                // into harmless spare capacity), so the infallible
                // settle suffix can never grow the ledger — a max-only
                // reservation would leave the second chain's seeds
                // unfunded.
                let missing =
                    self.missing_climb(plan.parent) + self.missing_climb(src.parent);
                if missing != 0 {
                    self.bodies.try_reserve(missing).map_err(priced_resource)?;
                }
                let next = self.machine.plan_next(&plan);
                self.machine.splice_ghost(&plan, id, src.cloned_alias(plan.parent, next));
                self.machine.apply_move(source.0, id);
                self.settle_climb(id, priced_delta(cost, 0));
                self.settle_climb(source.0, priced_delta(0, cost));
                #[cfg(debug_assertions)]
                self.assert_prices();
                Ok(Handle(id))
            }

            /// Copies the designated LEN's payload interior to the
            #[doc = concat!(" target and settles the price — [`", stringify!($Machine), "::copy_payload`]")]
            /// under the maintenance protocol
            #[doc = concat!(" ([`", stringify!($Priced), "::set_payload`]'s plan shape for a replacement,")]
            #[doc = concat!(" [`", stringify!($Priced), "::insert_payload`]'s for an insertion).")]
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::copy_payload`]; [`EditFault::Resource`]")]
            /// also covers a refused ledger reservation. On any `Err`
            #[doc = concat!(" the ", $noun, " and its prices are unchanged.")]
            ///
            /// # Panics
            ///
            /// Panics if a handle inside the arguments was not minted by
            #[doc = concat!(" this ", $noun, " (the arena index contract).")]
            #[track_caller]
            pub fn copy_payload(
                &mut self,
                source: Handle,
                target: PayloadTarget,
            ) -> Result<Handle, EditFault> {
                let src = self.machine.transfer_source(source)?;
                if !matches!(src.kind, RecordKind::Len) {
                    return Err(EditFault::KindMismatch { have: src.kind });
                }
                match target {
                    PayloadTarget::Replace(handle) => {
                        self.machine.value_gate(handle, RecordKind::Len)?;
                        self.machine.interior_gate(handle.0)?;
                        let id = handle.0;
                        let row = *self.machine.row(id);
                        let len = u64::from(self.machine.designated_payload(source.0).1);
                        let from = priced_row_cost(&self.machine, &self.bodies, id, &row);
                        let to =
                            Self::planned_value_cost(&row, u64::from(encoded_len64(len)) + len);
                        let delta = priced_delta(to, from);
                        self.machine.log.try_reserve(1).map_err(edit_resource)?;
                        if delta != 0 {
                            self.reserve_climb(row.parent)?;
                        }
                        self.machine.apply_edit(id, Edit::SourcePayload(source.0));
                        self.settle_climb(id, delta);
                        #[cfg(debug_assertions)]
                        self.assert_prices();
                        Ok(handle)
                    }
                    PayloadTarget::Insert { at, field } => {
                        let plan = self.machine.resolve_anchor(at)?;
                        let id = self.insert_obligations()?;
                        let len = u64::from(self.machine.designated_payload(source.0).1);
                        let to = u64::from(encoded_len32(head_word(field, RecordKind::Len)))
                            + u64::from(encoded_len64(len))
                            + len;
                        self.reserve_climb(plan.parent)?;
                        let next = self.machine.plan_next(&plan);
                        self.machine.apply_transfer(
                            &plan,
                            id,
                            Row::transfer_authored(
                                field,
                                RecordKind::Len,
                                plan.parent,
                                next,
                                Edit::SourceInsertedDeleted(source.0),
                            ),
                            Edit::SourceInserted(source.0),
                        );
                        self.settle_climb(id, priced_delta(to, 0));
                        #[cfg(debug_assertions)]
                        self.assert_prices();
                        Ok(Handle(id))
                    }
                }
            }

            /// Moves the designated LEN's payload interior to a fresh
            /// record at the anchor and settles the price —
            #[doc = concat!(" [`", stringify!($Machine), "::move_payload`] under the maintenance")]
            #[doc = concat!(" protocol ([`", stringify!($Priced), "::move_record`]'s plan shape; the")]
            /// destination's authored framing and the source's exact
            /// span leave as one derivation, two settling climbs).
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::move_payload`]; [`EditFault::Resource`]")]
            /// also covers a refused ledger reservation. On any `Err`
            #[doc = concat!(" the ", $noun, " and its prices are unchanged.")]
            ///
            /// # Panics
            ///
            /// Panics if a handle inside the arguments was not minted by
            #[doc = concat!(" this ", $noun, " (the arena index contract).")]
            #[track_caller]
            pub fn move_payload(
                &mut self,
                source: Handle,
                at: InsertAt,
                field: FieldNumber,
            ) -> Result<Handle, EditFault> {
                let src = self.machine.move_source(source)?;
                if !matches!(src.kind, RecordKind::Len) {
                    return Err(EditFault::KindMismatch { have: src.kind });
                }
                let plan = self.machine.resolve_anchor(at)?;
                self.machine.move_gap_gate(&plan, source.0)?;
                let id = self.insert_obligations()?;
                // SAFETY: move sources are original occurrences with
                // geometry.
                let from = u64::from(src.end - unsafe { scanned_at(&src) }.as_inner());
                let len = u64::from(self.machine.designated_payload(source.0).1);
                let to = u64::from(encoded_len32(head_word(field, RecordKind::Len)))
                    + u64::from(encoded_len64(len))
                    + len;
                // Two chains can be missing disjoint ledger prefixes:
                // reserve their sum (a shared ancestor double-counts
                // into harmless spare capacity), so the infallible
                // settle suffix can never grow the ledger — a max-only
                // reservation would leave the second chain's seeds
                // unfunded.
                let missing =
                    self.missing_climb(plan.parent) + self.missing_climb(src.parent);
                if missing != 0 {
                    self.bodies.try_reserve(missing).map_err(priced_resource)?;
                }
                let next = self.machine.plan_next(&plan);
                self.machine.splice_ghost(
                    &plan,
                    id,
                    Row::transfer_authored(
                        field,
                        RecordKind::Len,
                        plan.parent,
                        next,
                        Edit::SourceInsertedDeleted(source.0),
                    ),
                );
                self.machine.apply_move(source.0, id);
                self.settle_climb(id, priced_delta(to, 0));
                self.settle_climb(source.0, priced_delta(0, from));
                #[cfg(debug_assertions)]
                self.assert_prices();
                Ok(Handle(id))
            }

            /// Copies one designated external record to the anchor and
            #[doc = concat!(" settles the price — [`", stringify!($Machine), "::copy_record_from`] under")]
            /// the maintenance protocol: the record's exact byte count
            /// is the price.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::copy_record_from`];")]
            /// [`EditFault::Resource`] also covers a refused ledger
            #[doc = concat!(" reservation. On any `Err` the ", $noun, " and its prices are")]
            /// unchanged.
            ///
            /// # Panics
            ///
            /// Panics if a handle inside the anchor was not minted by
            #[doc = concat!(" this ", $noun, " (the arena index contract).")]
            #[track_caller]
            pub fn copy_record_from(
                &mut self,
                source: crate::source::groupless::CanonicalRecordRef<'_>,
                at: InsertAt,
            ) -> Result<Handle, EditFault> {
                let plan = self.machine.resolve_anchor(at)?;
                let id = self.insert_obligations()?;
                let bytes = source.as_bytes();
                #[allow(
                    clippy::as_conversions,
                    reason = "record lengths widen losslessly to u64"
                )]
                let to = bytes.len() as u64;
                let value =
                    self.machine.store.reserve_bytes(bytes.len()).map_err(edit_store_fault)?;
                self.reserve_climb(plan.parent)?;
                self.machine.store.push_bytes_reserved(bytes);
                let next = self.machine.plan_next(&plan);
                self.machine.apply_transfer(
                    &plan,
                    id,
                    Row::transfer_authored(
                        source.field(),
                        source.kind(),
                        plan.parent,
                        next,
                        Edit::ImportedDeleted(value),
                    ),
                    Edit::Imported(value),
                );
                self.settle_climb(id, priced_delta(to, 0));
                #[cfg(debug_assertions)]
                self.assert_prices();
                Ok(Handle(id))
            }
    };
    (@priced_shrouds plain, $Priced:ident over $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// Shrouds a record and settles the price —
            #[doc = concat!(" [`", stringify!($Machine), "::delete`] under the maintenance protocol:")]
            /// gates first, the shroud's delta derived on a shadow row,
            /// the log and the ledger's exact missing entries reserved
            /// next, and the commit behind them infallible.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::delete`]; [`EditFault::Resource`] also")]
            /// covers a refused ledger reservation. On any `Err` the
            #[doc = concat!(" ", $noun, " and its prices are unchanged.")]
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the")]
            /// arena index contract).
            #[track_caller]
            pub fn delete(&mut self, handle: Handle) -> Result<(), EditFault> {
                let row = self.machine.live(handle)?;
                if row.authored_zone() {
                    return Err(EditFault::InsideAuthoredBody);
                }
                let to = match row.edit {
                    Edit::Intact => Edit::Deleted(None),
                    Edit::Replaced(value) => Edit::Deleted(Some(value)),
                    Edit::Inserted(value) => Edit::InsertedDeleted(value),
                    Edit::Deleted(_) | Edit::InsertedDeleted(_) => {
                        return Err(EditFault::DeletedTarget);
                    }
                };
                self.transition(handle.0, to)
            }

            /// Lifts a shroud and settles the price —
            #[doc = concat!(" [`", stringify!($Machine), "::undelete`] under the maintenance protocol")]
            #[doc = concat!(" ([`", stringify!($Priced), "::delete`]'s plan shape; a restored container")]
            /// re-enters at its settled body, the edits under the
            /// shroud included).
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::undelete`]; [`EditFault::Resource`] also")]
            /// covers a refused ledger reservation. On any `Err` the
            #[doc = concat!(" ", $noun, " and its prices are unchanged.")]
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the")]
            /// arena index contract).
            #[track_caller]
            pub fn undelete(&mut self, handle: Handle) -> Result<(), EditFault> {
                let row = self.machine.live(handle)?;
                if row.authored_zone() {
                    return Err(EditFault::InsideAuthoredBody);
                }
                let to = match row.edit {
                    Edit::Deleted(None) => Edit::Intact,
                    Edit::Deleted(Some(value)) => Edit::Replaced(value),
                    Edit::InsertedDeleted(value) => Edit::Inserted(value),
                    Edit::Intact | Edit::Replaced(_) | Edit::Inserted(_) => {
                        return Err(EditFault::NotDeleted);
                    }
                };
                self.transition(handle.0, to)
            }

            /// Clears a replacement back to the scanned state and
            #[doc = concat!(" settles the price — [`", stringify!($Machine), "::clear_edit`] under the")]
            #[doc = concat!(" maintenance protocol ([`", stringify!($Priced), "::delete`]'s plan shape;")]
            /// a width-neutral clear reserves no ledger room and climbs
            /// nothing).
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::clear_edit`]; [`EditFault::Resource`] also")]
            /// covers a refused ledger reservation. On any `Err` the
            #[doc = concat!(" ", $noun, " and its prices are unchanged.")]
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the")]
            /// arena index contract).
            #[track_caller]
            pub fn clear_edit(&mut self, handle: Handle) -> Result<(), EditFault> {
                let row = self.machine.live(handle)?;
                if row.authored_zone() {
                    return Err(EditFault::InsideAuthoredBody);
                }
                match row.edit {
                    Edit::Replaced(_) => {}
                    Edit::Intact
                    | Edit::Deleted(_)
                    | Edit::Inserted(_)
                    | Edit::InsertedDeleted(_) => {
                        return Err(EditFault::NotClearable);
                    }
                }
                self.transition(handle.0, Edit::Intact)
            }
    };
    (@priced_shrouds $cap:ident, $Priced:ident over $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// Shrouds a record and settles the price —
            #[doc = concat!(" [`", stringify!($Machine), "::delete`] under the maintenance protocol:")]
            /// gates first, the shroud's delta derived on a shadow row,
            /// the log and the ledger's exact missing entries reserved
            /// next, and the commit behind them infallible.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::delete`]; [`EditFault::Resource`] also")]
            /// covers a refused ledger reservation. On any `Err` the
            #[doc = concat!(" ", $noun, " and its prices are unchanged.")]
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the")]
            /// arena index contract).
            #[track_caller]
            pub fn delete(&mut self, handle: Handle) -> Result<(), EditFault> {
                let row = self.machine.live(handle)?;
                if row.authored_zone() {
                    return Err(EditFault::InsideAuthoredBody);
                }
                let to = match row.edit {
                    Edit::Intact => Edit::Deleted(None),
                    Edit::Replaced(value) => Edit::Deleted(Some(value)),
                    Edit::Inserted(value) => Edit::InsertedDeleted(value),
                    Edit::SourceRecord => Edit::SourceRecordDeleted,
                    Edit::SourcePayload(src) => Edit::SourcePayloadDeleted(src),
                    Edit::SourceInserted(src) => Edit::SourceInsertedDeleted(src),
                    Edit::Imported(value) => Edit::ImportedDeleted(value),
                    Edit::Deleted(_)
                    | Edit::InsertedDeleted(_)
                    | Edit::Moved { .. }
                    | Edit::SourceRecordDeleted
                    | Edit::SourcePayloadDeleted(_)
                    | Edit::SourceInsertedDeleted(_)
                    | Edit::ImportedDeleted(_) => {
                        return Err(EditFault::DeletedTarget);
                    }
                };
                self.transition(handle.0, to)
            }

            /// Lifts a shroud and settles the price —
            #[doc = concat!(" [`", stringify!($Machine), "::undelete`] under the maintenance protocol")]
            #[doc = concat!(" ([`", stringify!($Priced), "::delete`]'s plan shape; a restored container")]
            /// re-enters at its settled body, the edits under the
            /// shroud included).
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::undelete`]; [`EditFault::Resource`] also")]
            /// covers a refused ledger reservation. On any `Err` the
            #[doc = concat!(" ", $noun, " and its prices are unchanged.")]
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the")]
            /// arena index contract).
            #[track_caller]
            pub fn undelete(&mut self, handle: Handle) -> Result<(), EditFault> {
                let row = self.machine.live(handle)?;
                if row.authored_zone() {
                    return Err(EditFault::InsideAuthoredBody);
                }
                let to = match row.edit {
                    Edit::Deleted(None) => Edit::Intact,
                    Edit::Deleted(Some(value)) => Edit::Replaced(value),
                    Edit::InsertedDeleted(value) => Edit::Inserted(value),
                    Edit::SourceRecordDeleted => Edit::SourceRecord,
                    Edit::SourcePayloadDeleted(src) => Edit::SourcePayload(src),
                    Edit::SourceInsertedDeleted(src) => Edit::SourceInserted(src),
                    Edit::ImportedDeleted(value) => Edit::Imported(value),
                    // A moved record is suppressed, not shrouded: one
                    // revert of the move restores it.
                    Edit::Intact
                    | Edit::Replaced(_)
                    | Edit::Inserted(_)
                    | Edit::Moved { .. }
                    | Edit::SourceRecord
                    | Edit::SourcePayload(_)
                    | Edit::SourceInserted(_)
                    | Edit::Imported(_) => {
                        return Err(EditFault::NotDeleted);
                    }
                };
                self.transition(handle.0, to)
            }

            /// Clears a replacement back to the scanned state and
            #[doc = concat!(" settles the price — [`", stringify!($Machine), "::clear_edit`] under the")]
            #[doc = concat!(" maintenance protocol ([`", stringify!($Priced), "::delete`]'s plan shape;")]
            /// a width-neutral clear reserves no ledger room and climbs
            /// nothing).
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::clear_edit`]; [`EditFault::Resource`] also")]
            /// covers a refused ledger reservation. On any `Err` the
            #[doc = concat!(" ", $noun, " and its prices are unchanged.")]
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the")]
            /// arena index contract).
            #[track_caller]
            pub fn clear_edit(&mut self, handle: Handle) -> Result<(), EditFault> {
                let row = self.machine.live(handle)?;
                if row.authored_zone() {
                    return Err(EditFault::InsideAuthoredBody);
                }
                match row.edit {
                    // A designated payload clears exactly like a stored
                    // replacement: back to the scanned reading. A copy's
                    // rows have no scanned state to restore.
                    Edit::Replaced(_) | Edit::SourcePayload(_) if !row.alias() => {}
                    _ => return Err(EditFault::NotClearable),
                }
                self.transition(handle.0, Edit::Intact)
            }
    };
    (@priced_revert plain, $Priced:ident over $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// Reverts the most recent command and settles the price;
            #[doc = concat!(" returns the touched row — [`", stringify!($Machine), "::revert`]. Zero")]
            /// allocation: the climb re-walks entries the forward path
            /// seeded, and undoing runs last-in-first-out, so every
            /// shroud the forward climb froze at is back in place when
            /// its delta returns.
            #[inline]
            pub fn revert(&mut self) -> Option<Handle> {
                let &logged = self.machine.log.last()?;
                let id = logged.row();
                let row = *self.machine.row(id);
                let current = priced_row_cost(&self.machine, &self.bodies, id, &row);
                // The shadow's state comes from the row's own history
                // (the settle dispatch's family witness holds).
                let shadow = Row { edit: logged.from, ..row };
                let restored = priced_row_cost(&self.machine, &self.bodies, id, &shadow);
                let handle = self.machine.revert();
                self.settle_climb(id, priced_delta(restored, current));
                #[cfg(debug_assertions)]
                self.assert_prices();
                handle
            }
    };
    (@priced_revert $cap:ident, $Priced:ident over $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// Reverts the most recent command and settles the price;
            #[doc = concat!(" returns the touched row — [`", stringify!($Machine), "::revert`]. Zero")]
            /// allocation: the climb re-walks entries the forward path
            /// seeded, and undoing runs last-in-first-out, so every
            /// shroud the forward climb froze at is back in place when
            /// its delta returns.
            #[inline]
            pub fn revert(&mut self) -> Option<Handle> {
                let &logged = self.machine.log.last()?;
                let id = logged.row();
                let row = *self.machine.row(id);
                let current = priced_row_cost(&self.machine, &self.bodies, id, &row);
                // A move entry carries its `Moved` state as the tag: the
                // source restores to the intact reading the move gate
                // admitted, and ghosting the destination alias takes its
                // price with it. Its chain's entries were seeded by the
                // move's own forward climb, so the second climb
                // allocates nothing. The shadow's state otherwise comes
                // from the row's own history (the settle dispatch's
                // family witness holds).
                let (restored_edit, coupled_dest) = match logged.from {
                    Edit::Moved { destination } => (Edit::Intact, Some(destination)),
                    from => (from, None),
                };
                let shadow = Row { edit: restored_edit, ..row };
                let restored = priced_row_cost(&self.machine, &self.bodies, id, &shadow);
                let coupled = coupled_dest.map(|destination| {
                    let dest = *self.machine.row(destination);
                    (destination, priced_row_cost(&self.machine, &self.bodies, destination, &dest))
                });
                let handle = self.machine.revert();
                self.settle_climb(id, priced_delta(restored, current));
                if let Some((destination, cost)) = coupled {
                    self.settle_climb(destination, priced_delta(0, cost));
                }
                #[cfg(debug_assertions)]
                self.assert_prices();
                handle
            }
    };
    (@priced_oracle plain, $Priced:ident over $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// The price oracle: re-derives every entry-tracked
            /// container's body from its member prices (entry-or-seed
            /// per member, so the local sums compose inductively from
            /// the leaves), the document total from the top layer, the
            /// seed fixpoint of every untracked entry, and the census
            /// from the ledger itself. A container tracks its interior exactly
            /// while its settle reads entry-or-seed — a source-backed
            /// interior; an authored backing prices wholesale, so its
            /// entry only holds the source seed for a later flip back.
            /// O(rows + entries), no allocation.
            #[cfg(debug_assertions)]
            fn assert_prices(&self) {
                let machine = &self.machine;
                let chain_cost = |first: Option<RowId>| {
                    let mut sum: u64 = 0;
                    let mut cur = first;
                    while let Some(id) = cur {
                        let row = machine.row(id);
                        sum += priced_row_cost(machine, &self.bodies, id, row);
                        cur = row.next;
                    }
                    sum
                };
                debug_assert_eq!(
                    chain_cost(machine.root.first),
                    self.total,
                    "the settled total drifts from the tree"
                );
                for (index, row) in machine.rows.iter().enumerate() {
                    let id = u32::try_from(index).ok().and_then(RowId::new);
                    debug_assert!(id.is_some(), "arena index outside the row domain");
                    let Some(id) = id else { continue };
                    let tracked =
                        matches!(row.slot(), Slot::Opened(_)) && row.edit.effective().is_none();
                    if tracked {
                        let Slot::Opened(layer) = row.slot() else { continue };
                        let body = chain_cost(machine.layer(layer).first);
                        let expect = self
                            .bodies
                            .get(&id)
                            .copied()
                            .unwrap_or_else(|| priced_seed(machine, row));
                        // No entry obligation rides the dirt alone: a
                        // zero-delta command (a fixed-width replacement
                        // prices its verbatim bytes exactly) dirties the
                        // interior without moving its body off the seed,
                        // and the equality above already pins that case.
                        debug_assert_eq!(body, expect, "a container body drifts from its interior");
                    } else if let Some(&body) = self.bodies.get(&id) {
                        debug_assert_eq!(
                            body,
                            priced_seed(machine, row),
                            "a stale ledger entry left its seed"
                        );
                    }
                }
                let cap = u64::from(PayloadLen::MAX.as_inner());
                let over = self.bodies.values().filter(|&&body| body > cap).count();
                debug_assert_eq!(over, usize_of(self.over_caps), "the length-class census drifts");
            }
    };
    (@priced_oracle transfer, $Priced:ident over $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// The price oracle: re-derives every entry-tracked
            /// container's body from its member prices (entry-or-seed
            /// per member, so the local sums compose inductively from
            /// the leaves), the document total from the top layer, the
            /// seed fixpoint of every untracked entry, and the census
            /// from the ledger itself. A container tracks its interior exactly
            /// while its settle reads entry-or-seed — a source-backed
            /// interior; an authored backing prices wholesale, so its
            /// entry only holds the source seed for a later flip back.
            /// O(rows + entries), no allocation.
            #[cfg(debug_assertions)]
            fn assert_prices(&self) {
                let machine = &self.machine;
                let chain_cost = |first: Option<RowId>| {
                    let mut sum: u64 = 0;
                    let mut cur = first;
                    while let Some(id) = cur {
                        let row = machine.row(id);
                        sum += priced_row_cost(machine, &self.bodies, id, row);
                        cur = row.next;
                    }
                    sum
                };
                debug_assert_eq!(
                    chain_cost(machine.root.first),
                    self.total,
                    "the settled total drifts from the tree"
                );
                for (index, row) in machine.rows.iter().enumerate() {
                    let id = u32::try_from(index).ok().and_then(RowId::new);
                    debug_assert!(id.is_some(), "arena index outside the row domain");
                    let Some(id) = id else { continue };
                    // Entry-or-seed containers are the scanned-speaker
                    // ones: their interiors price member by member. An
                    // import root joins them — its first-class interior
                    // walks, and the state's value is the zone witness,
                    // not an effective replacement.
                    let tracked = matches!(row.slot(), Slot::Opened(_))
                        && matches!(
                            row.edit,
                            Edit::Intact
                                | Edit::Deleted(None)
                                | Edit::Moved { .. }
                                | Edit::SourceRecord
                                | Edit::SourceRecordDeleted
                                | Edit::SourcePayload(_)
                                | Edit::SourcePayloadDeleted(_)
                                | Edit::SourceInserted(_)
                                | Edit::SourceInsertedDeleted(_)
                                | Edit::Imported(_)
                                | Edit::ImportedDeleted(_)
                        );
                    if tracked {
                        let Slot::Opened(layer) = row.slot() else { continue };
                        let body = chain_cost(machine.layer(layer).first);
                        let expect = self
                            .bodies
                            .get(&id)
                            .copied()
                            .unwrap_or_else(|| priced_seed(machine, row));
                        // No entry obligation rides the dirt alone: a
                        // zero-delta command (a fixed-width replacement
                        // prices its verbatim bytes exactly) dirties the
                        // interior without moving its body off the seed,
                        // and the equality above already pins that case.
                        debug_assert_eq!(body, expect, "a container body drifts from its interior");
                    } else if let Some(&body) = self.bodies.get(&id) {
                        debug_assert_eq!(
                            body,
                            priced_seed(machine, row),
                            "a stale ledger entry left its seed"
                        );
                    }
                }
                let cap = u64::from(PayloadLen::MAX.as_inner());
                let over = self.bodies.values().filter(|&&body| body > cap).count();
                debug_assert_eq!(over, usize_of(self.over_caps), "the length-class census drifts");
            }
    };
    (@priced_oracle $cap:ident, $Priced:ident over $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// The price oracle: re-derives every entry-tracked
            /// container's body from its member prices (entry-or-seed
            /// per member, so the local sums compose inductively from
            /// the leaves), the document total from the top layer, the
            /// seed fixpoint of every untracked entry, and the census
            /// from the ledger itself. A container tracks its interior exactly
            /// while its settle reads entry-or-seed — a source-backed
            /// interior; an authored backing prices wholesale, so its
            /// entry only holds the source seed for a later flip back.
            /// O(rows + entries), no allocation.
            #[cfg(debug_assertions)]
            fn assert_prices(&self) {
                let machine = &self.machine;
                let chain_cost = |first: Option<RowId>| {
                    let mut sum: u64 = 0;
                    let mut cur = first;
                    while let Some(id) = cur {
                        let row = machine.row(id);
                        sum += priced_row_cost(machine, &self.bodies, id, row);
                        cur = row.next;
                    }
                    sum
                };
                debug_assert_eq!(
                    chain_cost(machine.root.first),
                    self.total,
                    "the settled total drifts from the tree"
                );
                for (index, row) in machine.rows.iter().enumerate() {
                    let id = u32::try_from(index).ok().and_then(RowId::new);
                    debug_assert!(id.is_some(), "arena index outside the row domain");
                    let Some(id) = id else { continue };
                    // Entry-or-seed containers are the scanned-speaker
                    // ones: their interiors price member by member.
                    let tracked = matches!(row.slot(), Slot::Opened(_))
                        && matches!(
                            row.edit,
                            Edit::Intact
                                | Edit::Deleted(None)
                                | Edit::Moved { .. }
                                | Edit::SourceRecord
                                | Edit::SourceRecordDeleted
                                | Edit::SourcePayload(_)
                                | Edit::SourcePayloadDeleted(_)
                                | Edit::SourceInserted(_)
                                | Edit::SourceInsertedDeleted(_)
                        );
                    if tracked {
                        let Slot::Opened(layer) = row.slot() else { continue };
                        let body = chain_cost(machine.layer(layer).first);
                        let expect = self
                            .bodies
                            .get(&id)
                            .copied()
                            .unwrap_or_else(|| priced_seed(machine, row));
                        // No entry obligation rides the dirt alone: a
                        // zero-delta command (a fixed-width replacement
                        // prices its verbatim bytes exactly) dirties the
                        // interior without moving its body off the seed,
                        // and the equality above already pins that case.
                        debug_assert_eq!(body, expect, "a container body drifts from its interior");
                    } else if let Some(&body) = self.bodies.get(&id) {
                        debug_assert_eq!(
                            body,
                            priced_seed(machine, row),
                            "a stale ledger entry left its seed"
                        );
                    }
                }
                let cap = u64::from(PayloadLen::MAX.as_inner());
                let over = self.bodies.values().filter(|&&body| body > cap).count();
                debug_assert_eq!(over, usize_of(self.over_caps), "the length-class census drifts");
            }
    };
    (@priced_emit plain, $Priced:ident over $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
        /// The keyed-body emit pass: the sized emit's forward walk with
        /// every recursed container's LEN prefix answered from the
        /// settled ledger (entry-or-seed, the price reading every
        /// settle-mirror shares) instead of a sizing walk's recording.
        /// Runs only under a clear census, where every body sits in the
        /// length class and the prefix width is the value's own encoded
        /// length — the same bytes the sized emit writes.
        fn emit_pass_keyed<O: Out>(
            machine: &$Machine,
            emit: &mut O,
            bodies: &$crate::revise::FxMap<RowId, u64>,
        ) {
            let mut open: Option<RowId> = None;
            // Clean siblings tile their layer's source: a run costs one
            // discriminant-and-flag test per record and prices as a
            // single subtraction at its boundary.
            let mut run: Option<(u32, RowId)> = None;
            let mut cur = machine.root.first;
            loop {
                let Some(id) = cur else {
                    if let Some((from, last)) = run.take() {
                        emit.verbatim(from, machine.row(last).end);
                    }
                    let Some(container) = open else { break };
                    let row = machine.row(container);
                    cur = row.next;
                    open = row.parent;
                    continue;
                };
                let row = machine.row(id);
                if matches!(row.edit, Edit::Intact) && !row.dirty() {
                    // SAFETY: the Intact arm is outside the Inserted
                    // family.
                    let at = unsafe { scanned_at(row) };
                    match &mut run {
                        Some((_, last)) => *last = id,
                        None => run = Some((at.as_inner(), id)),
                    }
                    cur = row.next;
                    continue;
                }
                if let Some((from, last)) = run.take() {
                    emit.verbatim(from, machine.row(last).end);
                }
                match machine.settle(row) {
                    Arm::Skip => {}
                    // Clean rows join runs above; the arm stays for
                    // totality (settle is shared with the sized walks).
                    Arm::Clean { at, end } => emit.verbatim(at.as_inner(), end),
                    Arm::Varint { head, word } => {
                        emit.word(head);
                        emit.varint(word);
                    }
                    Arm::Bits32 { head, bits } => {
                        emit.word(head);
                        emit.bits32(bits);
                    }
                    Arm::Bits64 { head, bits } => {
                        emit.word(head);
                        emit.bits64(bits);
                    }
                    Arm::Body { head, value } => {
                        let (_, len) = machine.store.span(value);
                        emit.word(head);
                        emit.varint(u64::from(len));
                        emit.bytes(machine.store.span_bytes(value));
                    }
                    Arm::Spine { head, first, .. } => {
                        let body =
                            bodies.get(&id).copied().unwrap_or_else(|| priced_seed(machine, row));
                        emit.word(head);
                        emit.varint(body);
                        open = Some(id);
                        cur = first;
                        continue;
                    }
                }
                cur = row.next;
            }
            emit.flush();
        }
    };
    (@priced_emit $cap:ident, $Priced:ident over $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
    };
    (@priced_save plain, $Priced:ident over $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            /// Serializes the current state. While every rewritten body
            /// sits in the length class, one native emit walk runs, fed
            /// by the settled ledger — no sizing walk; the output length
            #[doc = concat!(" is the settled total. A clean ", $noun, " still hands back the")]
            /// carrier it opened, and the census clear with the total
            /// past the carrier answers the exact
            /// [`SaveFault::DocOverCap`] in O(1). A raised census
            /// delegates to the wrapped two-pass save, whose byte-exact
            /// fault (the walk's own offender choice included) — or its
            /// false-positive `Ok` on a shrouded over-cap spine — is the
            /// answer.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::save`], byte-exact, fault payloads")]
            /// included.
            ///
            /// # Panics
            ///
            /// If the settled prices and the emission disagree — a
            /// library bug caught at the seam — or as
            #[doc = concat!(" [`", stringify!($Machine), "::save`] on the delegating tiers.")]
            pub fn save(&self) -> Result<DocBytes, SaveFault> {
                if self.machine.root.dirty_kids == 0 || self.over_caps != 0 {
                    return self.machine.save();
                }
                if self.total > u64::from(DocBytes::CAP) {
                    return Err(SaveFault::DocOverCap { total: self.total });
                }
                #[allow(
                    clippy::cast_possible_truncation,
                    clippy::as_conversions,
                    reason = "just judged against the carrier cap, which is below u32::MAX"
                )]
                let out = RawDoc::alloc(self.total as u32).ok_or(SaveFault::Resource)?;
                let mut emit = Emit { out, doc: self.machine.source.as_slice(), run: None };
                emit_pass_keyed(&self.machine, &mut emit, &self.bodies);
                Ok(emit.out.finish())
            }
    };
    (@priced_save $cap:ident, $Priced:ident over $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal) => {
            #[doc = concat!(" Serializes the current state — [`", stringify!($Machine), "::save`], the")]
            /// base two-pass machinery unchanged.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::save`].")]
            ///
            /// # Panics
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::save`].")]
            #[inline]
            pub fn save(&self) -> Result<DocBytes, SaveFault> {
                self.machine.save()
            }
    };
    (@priced $cap:ident, $Priced:ident over $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal, mdoc: [$(#[$mdoc:meta])*]) => {
        /// Why the priced door refused.
        #[non_exhaustive]
        #[derive(Clone, Copy, PartialEq, Eq, Debug)]
        pub enum PriceFault {
            /// The allocator refused the price ledger.
            Resource,
        }

        impl core::fmt::Display for PriceFault {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                match *self {
                    Self::Resource => f.write_str("allocator refused the price ledger"),
                }
            }
        }

        impl core::error::Error for PriceFault {}

        #[cold]
        const fn priced_resource(_refused: hashbrown::TryReserveError) -> EditFault {
            EditFault::Resource
        }

        $crate::revise::groupless::revising_machine!(@priced_frozen $cap, $Priced over $Machine, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod);

        $crate::revise::groupless::revising_machine!(@priced_seed $cap, $Priced over $Machine, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod);

        $crate::revise::groupless::revising_machine!(@priced_row_cost $cap, $Priced over $Machine, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod);

        $crate::revise::groupless::revising_machine!(@priced_emit $cap, $Priced over $Machine, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod);

        /// A price difference in the signed domain — lossless: both
        /// operands are exact sums below the shared layer's
        /// `PRICE_CEILING`.
        #[allow(
            clippy::cast_possible_wrap,
            clippy::as_conversions,
            reason = "prices are exact sums below PRICE_CEILING (the shared layer's arithmetic
                      theorem), far below 2^63, so the signed widening is lossless"
        )]
        const fn priced_delta(to: u64, from: u64) -> i64 {
            debug_assert!(to <= PRICE_CEILING && from <= PRICE_CEILING);
            to as i64 - from as i64
        }

        /// Adds one settled amount to the enclosing accumulator: the
        /// open container's ledger entry, or the document total at the
        /// root. The plain additions cannot overflow: both sides stay
        /// exact sums below the shared layer's `PRICE_CEILING`, and
        /// the debug asserts are that theorem's checked form.
        fn priced_accumulate(
            bodies: &mut $crate::revise::FxMap<RowId, u64>,
            total: &mut u64,
            open: Option<RowId>,
            amount: u64,
        ) {
            match open {
                Some(container) => {
                    let Some(body) = bodies.get_mut(&container) else {
                        unreachable!(concat!($noun, " price: an open container without its entry"))
                    };
                    *body += amount;
                    debug_assert!(*body <= PRICE_CEILING, "an admitted body left the ceiling");
                }
                None => {
                    *total += amount;
                    debug_assert!(*total <= PRICE_CEILING, "the admitted total left the ceiling");
                }
            }
        }

        $crate::revise::groupless::revising_machine!(@priced_admit $cap, $Priced over $Machine, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod);

        impl $Machine {
            #[doc = concat!(" Admits this ", $noun, " into the priced typestate, building the")]
            /// container-body ledger, the exact document total, and the
            #[doc = concat!(" length-class census. A clean ", $noun, " admits in O(1) with no")]
            /// allocation (the total is the source length); a dirty one
            /// pays one walk over the layers that carry dirt. Over-cap
            /// state admits freely — the fault stays a save-time fact.
            ///
            /// # Errors
            ///
            #[doc = concat!(" [`PriceFault::Resource`] returns the ", $noun, " untouched beside")]
            /// the fault when the allocator refuses the ledger.
            ///
            /// # Examples
            ///
            /// ```
            #[doc = concat!(" use ", $doc_mod, "::", stringify!($Machine), ";")]
            ///
            /// let msg = [0x08, 0x96, 0x01];
            #[doc = concat!(" let mut ", $noun, " = ", $door, ".unwrap();")]
            #[doc = concat!(" let record = ", $noun, ".top().next().unwrap();")]
            #[doc = concat!(" ", $noun, ".set_varint(record, 7).unwrap();")]
            ///
            #[doc = concat!(" let Ok(priced) = ", $noun, ".into_priced() else { unreachable!() };")]
            /// assert_eq!(priced.save_len(), Ok(2));
            /// assert_eq!(priced.save().unwrap()[..], [0x08, 0x07]);
            /// ```
            #[allow(
                clippy::result_large_err,
                reason = "the refusal returns the machine intact beside its fault — transactional
                          tenure; boxing the pair would put an allocation on the allocator-refusal
                          path itself"
            )]
            pub fn into_priced(self) -> Result<$Priced, ($Machine, PriceFault)> {
                if self.root.dirty_kids == 0 {
                    let total = u64::from(self.source.len());
                    return Ok($Priced {
                        machine: self,
                        bodies: $crate::revise::FxMap::default(),
                        total,
                        over_caps: 0,
                    });
                }
                let mut bodies = $crate::revise::FxMap::default();
                match priced_admit(&self, &mut bodies) {
                    Ok((total, over_caps)) => {
                        let priced = $Priced { machine: self, bodies, total, over_caps };
                        #[cfg(debug_assertions)]
                        priced.assert_prices();
                        Ok(priced)
                    }
                    Err(fault) => Err((self, fault)),
                }
            }
        }

        $(#[$mdoc])*
        pub struct $Priced {
            machine: $Machine,
            /// Rewritten body lengths of the containers ever entered by
            /// a settling climb, exact through over-cap states. Entries
            /// are never removed: when the dirt under an entry falls,
            /// its body equals the seed again, so a stale entry answers
            /// exactly like the missing one; orphaned interiors are
            /// clean at the flip (the interior gate refuses history and
            /// undoing runs last-in-first-out), so their entries hold
            /// their seeds; and row coordinates are never reused.
            bodies: $crate::revise::FxMap<RowId, u64>,
            /// The exact rewritten document length.
            total: u64,
            /// Ledger entries whose body passes the length class. Never
            /// a false negative — every over-cap body differs from its
            /// in-class seed, so a settling climb built its entry and
            /// counted the crossing; shrouded over-cap spines keep the
            /// count raised (they cost the fast answer, never its
            /// truth).
            over_caps: u32,
        }

        impl $Priced {
            #[doc = concat!(" Releases the wrapped ", $noun, ", dissolving the price ledger.")]
            /// Pending edits and the revision log ride along untouched.
            #[inline]
            #[must_use]
            pub fn into_session(self) -> $Machine {
                self.machine
            }

            // ── delegated observation ──

            #[doc = concat!(" The sealed document this ", $noun, " opened.")]
            #[inline]
            #[must_use]
            pub const fn doc(&self) -> &DocBytes {
                self.machine.doc()
            }

            /// Revision-log length: the number of revertible steps.
            #[inline]
            #[must_use]
            pub const fn pending(&self) -> usize {
                self.machine.pending()
            }

            #[doc = concat!(" The record's wire kind — [`", stringify!($Machine), "::kind`].")]
            ///
            /// # Errors
            ///
            /// [`EditFault::DeadHandle`] for an orphaned row.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the")]
            /// arena index contract).
            #[inline]
            #[track_caller]
            pub fn kind(&self, handle: Handle) -> Result<RecordKind, EditFault> {
                self.machine.kind(handle)
            }

            #[doc = concat!(" The record's field number — [`", stringify!($Machine), "::field`].")]
            ///
            /// # Errors
            ///
            /// [`EditFault::DeadHandle`] for an orphaned row.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the")]
            /// arena index contract).
            #[inline]
            #[track_caller]
            pub fn field(&self, handle: Handle) -> Result<FieldNumber, EditFault> {
                self.machine.field(handle)
            }

            #[doc = concat!(" The record's edit status — [`", stringify!($Machine), "::status`].")]
            ///
            /// # Errors
            ///
            /// [`EditFault::DeadHandle`] for an orphaned row.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the")]
            /// arena index contract).
            #[inline]
            #[track_caller]
            pub fn status(&self, handle: Handle) -> Result<EditStatus, EditFault> {
                self.machine.status(handle)
            }

            /// True when the record's subtree carries any dirt —
            #[doc = concat!(" [`", stringify!($Machine), "::dirty`].")]
            ///
            /// # Errors
            ///
            /// [`EditFault::DeadHandle`] for an orphaned row.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the")]
            /// arena index contract).
            #[inline]
            #[track_caller]
            pub fn dirty(&self, handle: Handle) -> Result<bool, EditFault> {
                self.machine.dirty(handle)
            }

            #[doc = concat!(" The record's parent container — [`", stringify!($Machine), "::parent`].")]
            ///
            /// # Errors
            ///
            /// [`EditFault::DeadHandle`] for an orphaned row.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the")]
            /// arena index contract).
            #[inline]
            #[track_caller]
            pub fn parent(&self, handle: Handle) -> Result<Option<Handle>, EditFault> {
                self.machine.parent(handle)
            }

            #[doc = concat!(" The top layer, in wire order — [`", stringify!($Machine), "::top`].")]
            #[inline]
            pub fn top(&self) -> Children<'_> {
                self.machine.top()
            }

            /// The record's materialized children, in wire order —
            #[doc = concat!(" [`", stringify!($Machine), "::children`].")]
            ///
            /// # Errors
            ///
            /// [`EditFault::DeadHandle`] for an orphaned row.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the")]
            /// arena index contract).
            #[inline]
            #[track_caller]
            pub fn children(&self, handle: Handle) -> Result<Children<'_>, EditFault> {
                self.machine.children(handle)
            }

            /// The record's ancestor chain, innermost first —
            #[doc = concat!(" [`", stringify!($Machine), "::ancestors`].")]
            ///
            /// # Errors
            ///
            /// [`EditFault::DeadHandle`] for an orphaned row.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the")]
            /// arena index contract).
            #[inline]
            #[track_caller]
            pub fn ancestors(&self, handle: Handle) -> Result<Ancestors<'_>, EditFault> {
                self.machine.ancestors(handle)
            }

            /// The record's whole source span in document coordinates —
            #[doc = concat!(" [`", stringify!($Machine), "::span`].")]
            ///
            /// # Errors
            ///
            /// [`EditFault::DeadHandle`] for an orphaned row.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the")]
            /// arena index contract).
            #[inline]
            #[track_caller]
            pub fn span(&self, handle: Handle) -> Result<Option<Span>, EditFault> {
                self.machine.span(handle)
            }

            /// Source-document geometry of the record —
            #[doc = concat!(" [`", stringify!($Machine), "::source_spans`].")]
            ///
            /// # Errors
            ///
            /// [`EditFault::DeadHandle`] for an orphaned row.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the")]
            /// arena index contract).
            #[inline]
            #[track_caller]
            pub fn source_spans(&self, handle: Handle) -> Result<Option<RecordSpans>, EditFault> {
                self.machine.source_spans(handle)
            }

            /// The narrowest source-backed record covering `pos` —
            #[doc = concat!(" [`", stringify!($Machine), "::narrowest`].")]
            #[inline]
            #[must_use]
            pub fn narrowest(&self, pos: u32) -> Option<Handle> {
                self.machine.narrowest(pos)
            }

            /// The varint record's current word —
            #[doc = concat!(" [`", stringify!($Machine), "::varint_word`].")]
            ///
            /// # Errors
            ///
            /// [`EditFault::DeadHandle`] for an orphaned row,
            /// [`EditFault::KindMismatch`] off the varint kind.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the")]
            /// arena index contract).
            #[inline]
            #[track_caller]
            pub fn varint_word(&self, handle: Handle) -> Result<u64, EditFault> {
                self.machine.varint_word(handle)
            }

            /// The fixed 32-bit record's current bits —
            #[doc = concat!(" [`", stringify!($Machine), "::i32_bits`].")]
            ///
            /// # Errors
            ///
            /// [`EditFault::DeadHandle`] for an orphaned row,
            /// [`EditFault::KindMismatch`] off the I32 kind.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the")]
            /// arena index contract).
            #[inline]
            #[track_caller]
            pub fn i32_bits(&self, handle: Handle) -> Result<u32, EditFault> {
                self.machine.i32_bits(handle)
            }

            /// The fixed 64-bit record's current bits —
            #[doc = concat!(" [`", stringify!($Machine), "::i64_bits`].")]
            ///
            /// # Errors
            ///
            /// [`EditFault::DeadHandle`] for an orphaned row,
            /// [`EditFault::KindMismatch`] off the I64 kind.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the")]
            /// arena index contract).
            #[inline]
            #[track_caller]
            pub fn i64_bits(&self, handle: Handle) -> Result<u64, EditFault> {
                self.machine.i64_bits(handle)
            }

            /// The LEN record's current payload bytes —
            #[doc = concat!(" [`", stringify!($Machine), "::payload_bytes`].")]
            ///
            /// # Errors
            ///
            /// [`EditFault::DeadHandle`] for an orphaned row,
            /// [`EditFault::KindMismatch`] off the LEN kind.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the")]
            /// arena index contract).
            #[inline]
            #[track_caller]
            pub fn payload_bytes(&self, handle: Handle) -> Result<&[u8], EditFault> {
                self.machine.payload_bytes(handle)
            }

            // ── saving ──

            $crate::revise::groupless::revising_machine!(@priced_save $cap, $Priced over $Machine, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod);

            /// Serializes the current state by appending to `out` —
            #[doc = concat!(" [`", stringify!($Machine), "::save_into`].")]
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::save_into`].")]
            ///
            /// # Panics
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::save_into`].")]
            #[inline]
            pub fn save_into(&self, out: &mut Vec<u8>) -> Result<(), SaveFault> {
                self.machine.save_into(out)
            }

            /// Hands the save's bytes to `sink` as borrowed slices —
            #[doc = concat!(" [`", stringify!($Machine), "::save_sink`].")]
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::save_sink`].")]
            ///
            /// # Panics
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::save_sink`].")]
            #[inline]
            pub fn save_sink(&self, sink: impl FnMut(&[u8])) -> Result<(), SaveFault> {
                self.machine.save_sink(sink)
            }

            /// The output-order span table of the save —
            #[doc = concat!(" [`", stringify!($Machine), "::save_spans`].")]
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::save_spans`].")]
            ///
            /// # Panics
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::save_spans`].")]
            #[inline]
            pub fn save_spans(&self) -> Result<SaveSpans, SaveFault> {
                self.machine.save_spans()
            }

            #[doc = concat!(" The exact byte length [`", stringify!($Priced), "::save`] would seal,")]
            /// answered from the settled state — no sizing walk while
            /// every ledger body sits in the length class: the census
            /// clear and the total inside the carrier answer `Ok` in
            /// O(1); the census clear and the total past the carrier
            /// answer the exact [`SaveFault::DocOverCap`] in O(1); a
            /// raised census delegates to the wrapped sizing walk, whose
            /// byte-exact fault (the walk's own offender choice
            /// included) is the answer. A raised census can be a false
            /// positive — a shrouded over-cap spine prunes at the save —
            /// so delegation may still answer `Ok`; it is never a false
            /// negative.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::save_len`], byte-exact, fault payloads")]
            /// included.
            ///
            /// # Examples
            ///
            /// ```
            /// use protobuf_edit::FieldNumber;
            #[doc = concat!(" use ", $doc_mod, "::{InsertAt, ", stringify!($Machine), "};")]
            ///
            /// let msg = [0x08, 0x96, 0x01];
            #[doc = concat!(" let ", $noun, " = ", $door, ".unwrap();")]
            #[doc = concat!(" let Ok(mut priced) = ", $noun, ".into_priced() else { unreachable!() };")]
            /// let field = FieldNumber::new(2).unwrap();
            /// priced.insert_varint(InsertAt::TailOf(None), field, 42).unwrap();
            /// assert_eq!(priced.save_len(), Ok(5));
            /// assert_eq!(priced.save().unwrap().len(), 5);
            /// ```
            pub fn save_len(&self) -> Result<u32, SaveFault> {
                if self.over_caps == 0 {
                    return if self.total <= u64::from(DocBytes::CAP) {
                        #[allow(
                            clippy::cast_possible_truncation,
                            clippy::as_conversions,
                            reason = "just judged against the carrier cap, which is below u32::MAX"
                        )]
                        Ok(self.total as u32)
                    } else {
                        Err(SaveFault::DocOverCap { total: self.total })
                    };
                }
                self.machine.save_len()
            }

            // ── descending ──

            /// Parses a LEN payload into its interior layer, once —
            #[doc = concat!(" [`", stringify!($Machine), "::descend`]. No price moves: an opened")]
            /// interior prices exactly its container's payload until an
            /// edit lands inside it.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::descend`].")]
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the")]
            /// arena index contract).
            #[track_caller]
            pub fn descend(&mut self, handle: Handle) -> Result<Descent<'_>, EditFault> {
                #[cfg(debug_assertions)]
                {
                    // Parse first, then judge the untouched prices; the
                    // projection below re-answers the now-resident
                    // verdict.
                    let _ = self.machine.descend(handle)?;
                    self.assert_prices();
                }
                self.machine.descend(handle)
            }

            // ── the price maintenance protocol ──

            $crate::revise::groupless::revising_machine!(@priced_climbs $cap, $Priced over $Machine, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod);

            $crate::revise::groupless::revising_machine!(@priced_oracle $cap, $Priced over $Machine, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod);

            // ── mutation ──

            /// Replaces a varint record's value and settles the price —
            #[doc = concat!(" [`", stringify!($Machine), "::set_varint`] under the maintenance")]
            /// protocol: gates first, the value's delta derived before
            /// anything is occupied, every base obligation and the
            /// ledger's exact missing entries reserved next (a zero
            /// delta reserves no ledger room and climbs nothing), and
            /// the commit behind them infallible.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::set_varint`]; [`EditFault::Resource`] also")]
            /// covers a refused ledger reservation. On any `Err` the
            #[doc = concat!(" ", $noun, " and its prices are unchanged.")]
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the")]
            /// arena index contract).
            ///
            /// # Examples
            ///
            /// ```
            #[doc = concat!(" use ", $doc_mod, "::", stringify!($Machine), ";")]
            ///
            /// let msg = [0x08, 0x96, 0x01];
            #[doc = concat!(" let ", $noun, " = ", $door, ".unwrap();")]
            #[doc = concat!(" let Ok(mut priced) = ", $noun, ".into_priced() else { unreachable!() };")]
            /// let record = priced.top().next().unwrap();
            /// priced.set_varint(record, 7).unwrap();
            /// assert_eq!(priced.save_len(), Ok(2));
            /// priced.revert();
            /// assert_eq!(priced.save_len(), Ok(3));
            /// ```
            #[track_caller]
            pub fn set_varint(&mut self, handle: Handle, value: u64) -> Result<(), EditFault> {
                let witness = self.machine.value_gate(handle, RecordKind::Varint)?;
                let id = handle.0;
                let row = *self.machine.row(id);
                let from = priced_row_cost(&self.machine, &self.bodies, id, &row);
                let to = Self::planned_value_cost(&row, u64::from(encoded_len64(value)));
                let delta = priced_delta(to, from);
                self.machine.log.try_reserve(1).map_err(edit_resource)?;
                let at = self.machine.store.reserve_varint().map_err(edit_store_fault)?;
                if delta != 0 {
                    self.reserve_climb(row.parent)?;
                }
                self.machine.store.push_varint_reserved(value);
                self.machine.apply_edit(id, witness.set(at));
                self.settle_climb(id, delta);
                #[cfg(debug_assertions)]
                self.assert_prices();
                Ok(())
            }

            /// Replaces a fixed 32-bit record's bits —
            #[doc = concat!(" [`", stringify!($Machine), "::set_i32`], delegated whole: a fixed-width")]
            /// value is statically price-neutral (the head stays, the
            /// value side is always four bytes), so no ledger work
            /// exists to do.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::set_i32`]. On any `Err` the ", $noun)]
            /// and its prices are unchanged.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the")]
            /// arena index contract).
            #[inline]
            #[track_caller]
            pub fn set_i32(&mut self, handle: Handle, bits: u32) -> Result<(), EditFault> {
                self.machine.set_i32(handle, bits)?;
                #[cfg(debug_assertions)]
                self.assert_prices();
                Ok(())
            }

            /// Replaces a fixed 64-bit record's bits —
            #[doc = concat!(" [`", stringify!($Machine), "::set_i64`], delegated whole: a fixed-width")]
            /// value is statically price-neutral (the head stays, the
            /// value side is always eight bytes), so no ledger work
            /// exists to do.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::set_i64`]. On any `Err` the ", $noun)]
            /// and its prices are unchanged.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the")]
            /// arena index contract).
            #[inline]
            #[track_caller]
            pub fn set_i64(&mut self, handle: Handle, bits: u64) -> Result<(), EditFault> {
                self.machine.set_i64(handle, bits)?;
                #[cfg(debug_assertions)]
                self.assert_prices();
                Ok(())
            }

            /// Replaces a LEN record's payload wholesale and settles the
            #[doc = concat!(" price — [`", stringify!($Machine), "::set_payload`] under the maintenance")]
            #[doc = concat!(" protocol ([`", stringify!($Priced), "::set_varint`]'s plan shape).")]
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::set_payload`]; [`EditFault::Resource`] also")]
            /// covers a refused ledger reservation. On any `Err` the
            #[doc = concat!(" ", $noun, " and its prices are unchanged.")]
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the")]
            /// arena index contract).
            #[track_caller]
            pub fn set_payload(&mut self, handle: Handle, payload: &[u8]) -> Result<(), EditFault> {
                let witness = self.machine.value_gate(handle, RecordKind::Len)?;
                self.machine.interior_gate(handle.0)?;
                if payload.len() > usize_of(PayloadLen::MAX.as_inner()) {
                    return Err(EditFault::PayloadTooLarge { len: payload.len() });
                }
                let id = handle.0;
                let row = *self.machine.row(id);
                #[allow(clippy::as_conversions, reason = "payload lengths widen losslessly to u64")]
                let len = payload.len() as u64;
                let from = priced_row_cost(&self.machine, &self.bodies, id, &row);
                let to = Self::planned_value_cost(&row, u64::from(encoded_len64(len)) + len);
                let delta = priced_delta(to, from);
                self.machine.log.try_reserve(1).map_err(edit_resource)?;
                let at =
                    self.machine.store.reserve_bytes(payload.len()).map_err(edit_store_fault)?;
                if delta != 0 {
                    self.reserve_climb(row.parent)?;
                }
                self.machine.store.push_bytes_reserved(payload);
                self.machine.apply_edit(id, witness.set(at));
                self.settle_climb(id, delta);
                #[cfg(debug_assertions)]
                self.assert_prices();
                Ok(())
            }

            /// The insertion commands' shared base obligations: the row
            /// coordinate judged, the arena and log slots held. The
            /// caller reserves its value slot next, then the ledger —
            /// last — and commits behind them.
            fn insert_obligations(&mut self) -> Result<RowId, EditFault> {
                let id = self.machine.mint_insert()?;
                self.machine.rows.try_reserve(1).map_err(edit_resource)?;
                self.machine.log.try_reserve(1).map_err(edit_resource)?;
                Ok(id)
            }

            /// The insertion commands' shared commit suffix: the splice,
            /// the settling climb, and the oracle — every reservation
            /// already holds.
            fn insert_commit(
                &mut self,
                plan: &InsertPlan,
                id: RowId,
                field: FieldNumber,
                kind: RecordKind,
                value: ValueAt,
                to: u64,
            ) -> Handle {
                self.machine.apply_insert(plan, id, field, kind, value);
                self.settle_climb(id, priced_delta(to, 0));
                #[cfg(debug_assertions)]
                self.assert_prices();
                Handle(id)
            }

            /// Inserts a varint record at the anchor and settles the
            #[doc = concat!(" price — [`", stringify!($Machine), "::insert_varint`] under the")]
            /// maintenance protocol: the anchor gates first, the fresh
            /// record's price derived next, every base obligation and
            /// the ledger's exact missing entries reserved behind them,
            /// and the splice with its settling climb infallible.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::insert_varint`]; [`EditFault::Resource`]")]
            /// also covers a refused ledger reservation. On any `Err`
            #[doc = concat!(" the ", $noun, " and its prices are unchanged.")]
            ///
            /// # Panics
            ///
            /// Panics if a handle inside the anchor was not minted by
            #[doc = concat!(" this ", $noun, " (the arena index contract).")]
            #[track_caller]
            pub fn insert_varint(
                &mut self,
                at: InsertAt,
                field: FieldNumber,
                value: u64,
            ) -> Result<Handle, EditFault> {
                let plan = self.machine.resolve_anchor(at)?;
                let to = u64::from(encoded_len32(head_word(field, RecordKind::Varint)))
                    + u64::from(encoded_len64(value));
                let id = self.insert_obligations()?;
                let slot = self.machine.store.reserve_varint().map_err(edit_store_fault)?;
                self.reserve_climb(plan.parent)?;
                self.machine.store.push_varint_reserved(value);
                Ok(self.insert_commit(&plan, id, field, RecordKind::Varint, slot, to))
            }

            /// Inserts a fixed 32-bit record at the anchor and settles
            #[doc = concat!(" the price — [`", stringify!($Machine), "::insert_i32`] under the")]
            #[doc = concat!(" maintenance protocol ([`", stringify!($Priced), "::insert_varint`]'s plan")]
            /// shape).
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Priced), "::insert_varint`].")]
            ///
            /// # Panics
            ///
            /// Panics if a handle inside the anchor was not minted by
            #[doc = concat!(" this ", $noun, " (the arena index contract).")]
            #[track_caller]
            pub fn insert_i32(
                &mut self,
                at: InsertAt,
                field: FieldNumber,
                bits: u32,
            ) -> Result<Handle, EditFault> {
                let plan = self.machine.resolve_anchor(at)?;
                let to = u64::from(encoded_len32(head_word(field, RecordKind::I32))) + 4;
                let id = self.insert_obligations()?;
                let slot = self.machine.store.reserve_bits32().map_err(edit_store_fault)?;
                self.reserve_climb(plan.parent)?;
                self.machine.store.push_bits32_reserved(bits);
                Ok(self.insert_commit(&plan, id, field, RecordKind::I32, slot, to))
            }

            /// Inserts a fixed 64-bit record at the anchor and settles
            #[doc = concat!(" the price — [`", stringify!($Machine), "::insert_i64`] under the")]
            #[doc = concat!(" maintenance protocol ([`", stringify!($Priced), "::insert_varint`]'s plan")]
            /// shape).
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Priced), "::insert_varint`].")]
            ///
            /// # Panics
            ///
            /// Panics if a handle inside the anchor was not minted by
            #[doc = concat!(" this ", $noun, " (the arena index contract).")]
            #[track_caller]
            pub fn insert_i64(
                &mut self,
                at: InsertAt,
                field: FieldNumber,
                bits: u64,
            ) -> Result<Handle, EditFault> {
                let plan = self.machine.resolve_anchor(at)?;
                let to = u64::from(encoded_len32(head_word(field, RecordKind::I64))) + 8;
                let id = self.insert_obligations()?;
                let slot = self.machine.store.reserve_bits64().map_err(edit_store_fault)?;
                self.reserve_climb(plan.parent)?;
                self.machine.store.push_bits64_reserved(bits);
                Ok(self.insert_commit(&plan, id, field, RecordKind::I64, slot, to))
            }

            /// Inserts a LEN record with an authored payload at the
            #[doc = concat!(" anchor and settles the price — [`", stringify!($Machine), "::insert_payload`]")]
            #[doc = concat!(" under the maintenance protocol ([`", stringify!($Priced), "::insert_varint`]'s")]
            /// plan shape).
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::insert_payload`];")]
            /// [`EditFault::Resource`] also covers a refused ledger
            #[doc = concat!(" reservation. On any `Err` the ", $noun, " and its prices are")]
            /// unchanged.
            ///
            /// # Panics
            ///
            /// Panics if a handle inside the anchor was not minted by
            #[doc = concat!(" this ", $noun, " (the arena index contract).")]
            #[track_caller]
            pub fn insert_payload(
                &mut self,
                at: InsertAt,
                field: FieldNumber,
                payload: &[u8],
            ) -> Result<Handle, EditFault> {
                let plan = self.machine.resolve_anchor(at)?;
                let id = self.machine.mint_insert()?;
                if payload.len() > usize_of(PayloadLen::MAX.as_inner()) {
                    return Err(EditFault::PayloadTooLarge { len: payload.len() });
                }
                #[allow(clippy::as_conversions, reason = "payload lengths widen losslessly to u64")]
                let len = payload.len() as u64;
                let to = u64::from(encoded_len32(head_word(field, RecordKind::Len)))
                    + u64::from(encoded_len64(len))
                    + len;
                self.machine.rows.try_reserve(1).map_err(edit_resource)?;
                self.machine.log.try_reserve(1).map_err(edit_resource)?;
                let slot =
                    self.machine.store.reserve_bytes(payload.len()).map_err(edit_store_fault)?;
                self.reserve_climb(plan.parent)?;
                self.machine.store.push_bytes_reserved(payload);
                Ok(self.insert_commit(&plan, id, field, RecordKind::Len, slot, to))
            }

            /// The transition commands' shared plan-and-commit: the
            /// caller's gates proved `to` lawful, so the plan prices the
            /// transition on a shadow row (exact despite the stale dirt
            /// flag: under canonical admission a verbatim span and its
            /// re-emission price identically, and a container's two
            /// spine readings agree through entry-or-seed), reserves
            /// the log and — for a moving delta — the ledger's exact
            /// missing entries, and commits infallibly behind them.
            fn transition(&mut self, id: RowId, to: Edit) -> Result<(), EditFault> {
                let row = *self.machine.row(id);
                let from = priced_row_cost(&self.machine, &self.bodies, id, &row);
                let shadow = Row { edit: to, ..row };
                let planned = priced_row_cost(&self.machine, &self.bodies, id, &shadow);
                let delta = priced_delta(planned, from);
                self.machine.log.try_reserve(1).map_err(edit_resource)?;
                if delta != 0 {
                    self.reserve_climb(row.parent)?;
                }
                self.machine.apply_edit(id, to);
                self.settle_climb(id, delta);
                #[cfg(debug_assertions)]
                self.assert_prices();
                Ok(())
            }

            $crate::revise::groupless::revising_machine!(@priced_transfer_faces $cap, $Priced over $Machine, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod);

            $crate::revise::groupless::revising_machine!(@priced_shrouds $cap, $Priced over $Machine, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod);

            // ── undo ──

            $crate::revise::groupless::revising_machine!(@priced_revert $cap, $Priced over $Machine, noun: $noun, a_noun: $a_noun, A_noun: $A_noun, door: $door, doc_mod: $doc_mod);

            /// Reverts every pending command, newest first —
            #[doc = concat!(" [`", stringify!($Machine), "::revert_all`] under the maintenance")]
            /// protocol.
            #[inline]
            pub fn revert_all(&mut self) {
                while self.revert().is_some() {}
            }
        }

    };
    (@priced_frames $Priced:ident over $Machine:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal, door: $door:literal, doc_mod: $doc_mod:literal, frame_doc: [$(#[$frame_send:meta])*], sized_doc: [$(#[$sized_send:meta])*]) => {
        impl $Priced {
            // ── the staged payload frame ──

            /// Opens a staged replacement of the LEN record's payload —
            #[doc = concat!(" [`", stringify!($Machine), "::begin_set_payload`]'s protocol over the priced")]
            /// state: the gates judge here, chunks copy into the store
            /// through the returned frame, and exactly one logged
            /// transition applies — with its ledger reservation and
            /// settling climb — at
            /// [`finish`](PricedPayloadFrame::finish). Before it, no
            /// row, log, ledger, or price state changes.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::begin_set_payload`]. On `Err` the")]
            #[doc = concat!(" ", $noun, " and its prices are unchanged.")]
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the")]
            /// arena index contract).
            ///
            /// # Examples
            ///
            /// ```
            #[doc = concat!(" use ", $doc_mod, "::", stringify!($Machine), ";")]
            ///
            /// // LEN f2 "hi" — replaced from two chunks, one undo step.
            /// let msg = [0x12, 0x02, 0x68, 0x69];
            #[doc = concat!(" let ", $noun, " = ", $door, ".unwrap();")]
            #[doc = concat!(" let Ok(mut priced) = ", $noun, ".into_priced() else { unreachable!() };")]
            /// let record = priced.top().next().unwrap();
            ///
            /// let mut frame = priced.begin_set_payload(record).unwrap();
            /// frame.write(&[0x61]).unwrap();
            /// frame.write(&[0x62, 0x63]).unwrap();
            /// frame.finish().unwrap();
            /// assert_eq!(priced.save_len(), Ok(5));
            ///
            /// priced.revert();
            /// assert_eq!(priced.save_len(), Ok(4));
            /// ```
            #[track_caller]
            pub fn begin_set_payload(
                &mut self,
                handle: Handle,
            ) -> Result<PricedPayloadFrame<'_>, EditFault> {
                let witness = self.machine.value_gate(handle, RecordKind::Len)?;
                self.machine.interior_gate(handle.0)?;
                let mark = self.machine.store.stage_mark();
                Ok(PricedPayloadFrame { priced: self, op: FrameOp::Set { handle, witness }, mark })
            }

            /// Opens a staged insertion of a fresh LEN record at the
            #[doc = concat!(" anchor — [`", stringify!($Machine), "::begin_insert_payload`]'s protocol over")]
            /// the priced state
            #[doc = concat!(" ([`", stringify!($Priced), "::begin_set_payload`]'s frame contract).")]
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::begin_insert_payload`]. On `Err` the")]
            #[doc = concat!(" ", $noun, " and its prices are unchanged.")]
            ///
            /// # Panics
            ///
            /// Panics if a handle inside the anchor was not minted by
            #[doc = concat!(" this ", $noun, " (the arena index contract).")]
            #[track_caller]
            pub fn begin_insert_payload(
                &mut self,
                at: InsertAt,
                field: FieldNumber,
            ) -> Result<PricedPayloadFrame<'_>, EditFault> {
                let plan = self.machine.resolve_anchor(at)?;
                let mark = self.machine.store.stage_mark();
                Ok(PricedPayloadFrame { priced: self, op: FrameOp::Insert { plan, field }, mark })
            }

            #[doc = concat!(" [`begin_set_payload`](", stringify!($Priced), "::begin_set_payload)'s")]
            /// declared-length twin —
            #[doc = concat!(" [`", stringify!($Machine), "::begin_set_payload_sized`]'s door contract over")]
            /// the priced state.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::begin_set_payload_sized`]. On `Err` the")]
            #[doc = concat!(" ", $noun, " and its prices are unchanged.")]
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the")]
            /// arena index contract).
            #[track_caller]
            pub fn begin_set_payload_sized(
                &mut self,
                handle: Handle,
                len: usize,
            ) -> Result<PricedSizedPayloadFrame<'_>, EditFault> {
                let witness = self.machine.value_gate(handle, RecordKind::Len)?;
                self.machine.interior_gate(handle.0)?;
                let declared = self.machine.stage_declare(len)?;
                let mark = self.machine.store.stage_mark();
                Ok(PricedSizedPayloadFrame {
                    inner: PricedPayloadFrame {
                        priced: self,
                        op: FrameOp::Set { handle, witness },
                        mark,
                    },
                    declared,
                })
            }

            #[doc = concat!(" [`begin_insert_payload`](", stringify!($Priced), "::begin_insert_payload)'s")]
            /// declared-length twin —
            #[doc = concat!(" [`", stringify!($Machine), "::begin_insert_payload_sized`]'s door contract")]
            /// over the priced state.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::begin_insert_payload_sized`]. On `Err`")]
            #[doc = concat!(" the ", $noun, " and its prices are unchanged.")]
            ///
            /// # Panics
            ///
            /// Panics if a handle inside the anchor was not minted by
            #[doc = concat!(" this ", $noun, " (the arena index contract).")]
            #[track_caller]
            pub fn begin_insert_payload_sized(
                &mut self,
                at: InsertAt,
                field: FieldNumber,
                len: usize,
            ) -> Result<PricedSizedPayloadFrame<'_>, EditFault> {
                let plan = self.machine.resolve_anchor(at)?;
                let declared = self.machine.stage_declare(len)?;
                let mark = self.machine.store.stage_mark();
                Ok(PricedSizedPayloadFrame {
                    inner: PricedPayloadFrame {
                        priced: self,
                        op: FrameOp::Insert { plan, field },
                        mark,
                    },
                    declared,
                })
            }
        }

        /// A fallible staged payload frame over the priced state —
        /// [`PayloadFrame`]'s protocol re-emitted for the wrapper.
        ///
        /// Chunks copy into the store as they arrive, and exactly one
        /// command — one logged transition with its settling climb —
        /// applies at [`finish`](PricedPayloadFrame::finish). Before
        /// it, no row, log, or price state changes, so no undo step and
        /// no priced answer can see a half-staged command. Dropping the
        /// frame unfinished reclaims its staged bytes exactly as the
        /// plain frame does, and every price stays where the door found
        /// it.
        $(#[$frame_send])*
        #[must_use = "a payload frame installs nothing until finished"]
        pub struct PricedPayloadFrame<'s> {
            priced: &'s mut $Priced,
            op: FrameOp,
            /// The store's byte-column tail at open: the staged extent
            /// is `mark..` for the frame's whole life. In
            /// `0..=At32::MAX + 1` by the column's push judgments.
            mark: u32,
        }

        impl Drop for PricedPayloadFrame<'_> {
            /// Reclaims the staged extent: only a publishing
            /// [`finish`](PricedPayloadFrame::finish) keeps the staged
            /// bytes, so abandonment and every refusal path leave the
            /// store's byte cursor, span table, and offset space exactly
            /// as the door found them (reserved capacity may be
            /// retained).
            fn drop(&mut self) {
                self.priced.machine.store.stage_abandon(self.mark);
            }
        }

        impl PricedPayloadFrame<'_> {
            /// Appends one chunk to the staged payload, copying it at
            /// the call — [`PayloadFrame::write`]'s contract. An empty
            /// chunk is a no-op.
            ///
            /// # Errors
            ///
            /// As [`PayloadFrame::write`]. On `Err` the chunk is not
            /// staged and the frame stays usable.
            pub fn write(&mut self, chunk: &[u8]) -> Result<(), EditFault> {
                let staged = u64::from(self.priced.machine.store.stage_mark() - self.mark);
                #[allow(clippy::as_conversions, reason = "chunk lengths widen losslessly to u64")]
                let total = staged.saturating_add(chunk.len() as u64);
                if total > u64::from(PayloadLen::MAX.as_inner()) {
                    let len = usize::try_from(total).unwrap_or(usize::MAX);
                    return Err(EditFault::PayloadTooLarge { len });
                }
                self.priced.machine.store.stage_chunk(chunk).map_err(edit_store_fault)?;
                Ok(())
            }

            /// Installs the staged payload and settles its price: the
            /// set flips its record, the insert splices exactly one
            /// fresh row — one logged transition either way, its delta
            /// climbed now. Returns the changed record's handle.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`PayloadFrame::finish`]. On `Err` the ", $noun, " and its")]
            /// prices are unchanged — the staged bytes are reclaimed
            /// with the frame, so the whole save may be restaged and
            /// retried.
            pub fn finish(mut self) -> Result<Handle, EditFault> {
                match self.apply() {
                    Ok(handle) => {
                        // Published: the span now covers the staged
                        // extent, so defuse the drop reclamation.
                        core::mem::forget(self);
                        Ok(handle)
                    }
                    // Dropping the frame reclaims the staged extent.
                    Err(fault) => Err(fault),
                }
            }

            /// The publishing close under the command plan: the base
            /// close obligations first, the staged extent's delta
            /// derived next, the ledger's exact missing entries
            /// reserved last (a zero delta reserves no ledger room and
            /// climbs nothing), then the span mint, the one command,
            /// and its settling climb — infallible behind the
            /// reservations.
            fn apply(&mut self) -> Result<Handle, EditFault> {
                let staged = u64::from(self.priced.machine.store.stage_mark() - self.mark);
                match self.op {
                    FrameOp::Set { handle, witness } => {
                        // The gates judged at open; the frame's
                        // exclusive borrow kept the row exactly as they
                        // left it.
                        let id = handle.0;
                        let row = *self.priced.machine.row(id);
                        let from =
                            priced_row_cost(&self.priced.machine, &self.priced.bodies, id, &row);
                        let to = $Priced::planned_value_cost(
                            &row,
                            u64::from(encoded_len64(staged)) + staged,
                        );
                        let delta = priced_delta(to, from);
                        self.priced.machine.log.try_reserve(1).map_err(edit_resource)?;
                        let at = self
                            .priced
                            .machine
                            .store
                            .stage_finish_reserve()
                            .map_err(edit_store_fault)?;
                        if delta != 0 {
                            self.priced.reserve_climb(row.parent)?;
                        }
                        self.priced.machine.store.stage_finish_reserved(self.mark);
                        self.priced.machine.apply_edit(id, witness.set(at));
                        self.priced.settle_climb(id, delta);
                        #[cfg(debug_assertions)]
                        self.priced.assert_prices();
                        Ok(handle)
                    }
                    FrameOp::Insert { plan, field } => {
                        let to = u64::from(encoded_len32(head_word(field, RecordKind::Len)))
                            + u64::from(encoded_len64(staged))
                            + staged;
                        let id = self.priced.machine.mint_insert()?;
                        self.priced.machine.rows.try_reserve(1).map_err(edit_resource)?;
                        self.priced.machine.log.try_reserve(1).map_err(edit_resource)?;
                        let at = self
                            .priced
                            .machine
                            .store
                            .stage_finish_reserve()
                            .map_err(edit_store_fault)?;
                        self.priced.reserve_climb(plan.parent)?;
                        self.priced.machine.store.stage_finish_reserved(self.mark);
                        self.priced.machine.apply_insert(&plan, id, field, RecordKind::Len, at);
                        self.priced.settle_climb(id, priced_delta(to, 0));
                        #[cfg(debug_assertions)]
                        self.priced.assert_prices();
                        Ok(Handle(id))
                    }
                }
            }
        }

        /// A fallible staged payload frame over the priced state, held
        /// to a declared length — [`SizedPayloadFrame`]'s protocol
        /// re-emitted for the wrapper.
        ///
        /// The declaration was judged and its bytes reserved at the
        /// door, a write past it refuses [`FrameFault::OverDeclared`],
        /// a short finish refuses [`FrameFault::UnderDeclared`], and
        /// the publishing finish settles the one logged transition's
        /// price. Every non-publishing exit reclaims the staged bytes
        /// and leaves the prices where the door found them.
        $(#[$sized_send])*
        #[must_use = "a payload frame installs nothing until finished"]
        pub struct PricedSizedPayloadFrame<'s> {
            inner: PricedPayloadFrame<'s>,
            /// The declared payload length, in the length class.
            declared: u32,
        }

        impl PricedSizedPayloadFrame<'_> {
            /// Appends one chunk to the staged payload, copying it at
            /// the call into the bytes the door reserved —
            /// [`SizedPayloadFrame::write`]'s contract. An empty chunk
            /// is a no-op.
            ///
            /// # Errors
            ///
            /// [`FrameFault::OverDeclared`] when the staged total would
            /// pass the declaration. On `Err` the chunk is not staged
            /// and the frame stays usable.
            pub fn write(&mut self, chunk: &[u8]) -> Result<(), FrameFault> {
                let staged =
                    u64::from(self.inner.priced.machine.store.stage_mark() - self.inner.mark);
                #[allow(clippy::as_conversions, reason = "chunk lengths widen losslessly to u64")]
                let total = staged.saturating_add(chunk.len() as u64);
                if total > u64::from(self.declared) {
                    return Err(FrameFault::OverDeclared { declared: self.declared, total });
                }
                // The door judged the declaration into the length class
                // and the byte column's offset domain and reserved its
                // bytes; the gate above bounds the staged total inside
                // the declaration, so this append stays inside both.
                self.inner.priced.machine.store.stage_chunk_reserved(chunk);
                Ok(())
            }

            /// Installs the staged payload exactly as declared and
            /// settles its price — the undeclared frame's
            /// [`finish`](PricedPayloadFrame::finish), behind the
            /// declaration judgment.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`SizedPayloadFrame::finish`]. On `Err` the ", $noun, " and")]
            /// its prices are unchanged — the staged bytes are reclaimed
            /// with the frame.
            pub fn finish(self) -> Result<Handle, FrameFault> {
                let staged = self.inner.priced.machine.store.stage_mark() - self.inner.mark;
                if staged != self.declared {
                    return Err(FrameFault::UnderDeclared { declared: self.declared, staged });
                }
                self.inner.finish().map_err(close_fault)
            }
        }

    };
}

pub(crate) use revising_machine;
