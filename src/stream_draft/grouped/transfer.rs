//! The grouped stream-ingest draft's transfer siblings.
//!
//! The same revisable editing faces plus whole-record relocation
//! and external import, emitted as their own sealed machines so the
//! base draft pays none of the capability's carried state or
//! dispatch. The ingest phase is the base cell's [`Ingest`] whole —
//! feed grammar, custody, and truncation judgments untouched — and
//! [`Ingest::finish_transfer`] is this sibling's seal door: the
//! sealed rows re-tag into the transfer row form in one pass over
//! the row table (a field-for-field copy — every sealed row is
//! intact, the state both edit algebras share), the sealed group
//! layers re-mint their coordinates the same way, and the
//! accumulated source moves without a copy.
//! [`Ingest::finish_transfer_borrow`] seals the same parts into the
//! borrowed-payload sibling.
//!
//! Two machines split the payload-backing policies exactly like the
//! base siblings: [`TransferDraft`] copies payloads and imported
//! records into its store (no payload lifetime binds the caller),
//! and [`TransferBorrowDraft`] retains borrowed payload slices
//! and borrowed imported records — every owner must outlive the
//! machine. Both add the transfer faces: `copy_record` and
//! `move_record` relocate whole designated records, `copy_payload`
//! and `move_payload` relocate LEN interiors, and
//! `copy_record_from` imports one designated external record. A
//! move is one command, one pending step, one revert.

use alloc::collections::TryReserveError;
use alloc::vec::Vec;

use crate::Span;
use crate::admission::usize_of;
use crate::stream_draft::transfer::{Edit, Transition};
use crate::stream_draft::{At32, BorrowStore, Handle, RowId, Store, StoreFault, ValueAt, admit};
use crate::varint::slice::{self, ReadFault};
use crate::varint::{WordWidth, encoded_len32, encoded_len64, push64};
use crate::wire::grouped::{RecordKind, TagClass, classify, group_end_word, head_word};
use crate::wire::{FieldNumber, Low3, PayloadLen};
use super::{ChunkDisposition, Ingest, IngestFault, IngestFaultKind, ResourceSite};

pub use crate::stream_draft::command::InsertAt;
pub use crate::stream_draft::transfer::{EditStatus, PayloadTarget};

#[cfg(test)]
mod tests;

crate::revise::grouped::revising_machine! {
    vocabulary(
        Ancestors, Children, Descent, EditFault, Fault, FaultKind,
        RecordSpans, SaveFault, SaveSpans,
    ),
    capability: transfer,
    tenure: stream,
    acceptance: tolerant,
    product: vec,
    Machine: TransferDraft,
    noun: "draft",
    a_noun: "a draft",
    A_noun: "A draft",
    door: "{ let mut ingest = protobuf_edit::stream_draft::grouped::Ingest::new(); ingest.feed(&msg).unwrap(); ingest.finish_transfer() }",
    doc_mod: "protobuf_edit::stream_draft::grouped::transfer",
}

crate::revise::grouped::revising_machine! {
    #[doc = " An editing draft with the transfer capability, sealed from a"]
    #[doc = " chunked stream."]
    #[doc = ""]
    #[doc = " [`Draft`](super::Draft)'s faces plus whole-record"]
    #[doc = " relocation, payload relocation, and external import, with"]
    #[doc = " payloads and imported records copied into the machine at"]
    #[doc = " the command — temporaries welcome, no payload lifetime on"]
    #[doc = " the type. The only door is [`Ingest::finish_transfer`] —"]
    #[doc = " the input arrived as a stream, so no buffered open exists"]
    #[doc = " on this type."]
    #[doc = ""]
    #[doc = " Handles stay valid for the draft's life unless a payload"]
    #[doc = " replacement orphans the rows parsed out of the old payload;"]
    #[doc = " orphaned handles answer with [`EditFault::DeadHandle`]. Undo is"]
    #[doc = " exact: every command logs one step — a move included — and"]
    #[doc = " [`TransferDraft::revert`] restores the save-observable state"]
    #[doc = " of the previous step."]
    machine TransferDraft { source: Vec<u8> }
    capability: transfer,
    tenure: stream,
    acceptance: tolerant,
    product: vec,
    noun: "draft",
    a_noun: "a draft",
    A_noun: "A draft",
    door: "{ let mut ingest = protobuf_edit::stream_draft::grouped::Ingest::new(); ingest.feed(&msg).unwrap(); ingest.finish_transfer() }",
    doc_mod: "protobuf_edit::stream_draft::grouped::transfer",
}

crate::revise::grouped::revising_machine! {
    views,
    Machine: TransferDraft,
    noun: "draft",
    a_noun: "a draft",
    A_noun: "A draft",
    door: "{ let mut ingest = protobuf_edit::stream_draft::grouped::Ingest::new(); ingest.feed(&msg).unwrap(); ingest.finish_transfer() }",
    doc_mod: "protobuf_edit::stream_draft::grouped::transfer",
}

crate::revise::grouped::revising_machine! {
    #[doc = " An editing draft with the transfer capability, with borrowed"]
    #[doc = " payloads, sealed from a chunked stream."]
    #[doc = ""]
    #[doc = " [`TransferDraft`]'s sibling for callers whose payload"]
    #[doc = " bytes outlive the machine; its only door is"]
    #[doc = " [`Ingest::finish_transfer_borrow`]."]
    #[doc = ""]
    #[doc = " `set_payload`, `insert_payload`, and `copy_record_from` take"]
    #[doc = " `&'p [u8]` and retain the slice — no staging copy — as a"]
    #[doc = " fresh immutable slot per install; earlier installs keep"]
    #[doc = " their slots, so a revert restores the exact prior state."]
    #[doc = " Every payload and imported-record owner must outlive the"]
    #[doc = " draft, and `'p` rides the type beside the ingested source."]
    #[doc = " Everything else is [`TransferDraft`]'s contract."]
    machine TransferBorrowDraft<'p> { source: Vec<u8> }
    capability: transfer,
    payload: borrow,
    tenure: stream,
    acceptance: tolerant,
    product: vec,
    noun: "draft",
    a_noun: "a draft",
    A_noun: "A draft",
    door: "{ let mut ingest = protobuf_edit::stream_draft::grouped::Ingest::new(); ingest.feed(&msg).unwrap(); ingest.finish_transfer_borrow() }",
    doc_mod: "protobuf_edit::stream_draft::grouped::transfer",
}

// The machine layouts, pinned on every pointer width: the transfer
// twins carry the base machines' fields over the same stores, so
// the equalities are width-independent and the 32-bit check gate
// evaluates them; any drift lands here for review.
const _: () =
    assert!(core::mem::size_of::<TransferDraft>() == core::mem::size_of::<super::Draft>());
const _: () = assert!(
    core::mem::size_of::<TransferBorrowDraft<'_>>()
        == core::mem::size_of::<super::BorrowDraft<'_>>()
);

crate::revise::grouped::revising_machine! {
    frames for TransferDraft (PayloadFrame, SizedPayloadFrame, FrameFault),
    noun: "draft",
    a_noun: "a draft",
    A_noun: "A draft",
    door: "{ let mut ingest = protobuf_edit::stream_draft::grouped::Ingest::new(); ingest.feed(&msg).unwrap(); ingest.finish_transfer() }",
    doc_mod: "protobuf_edit::stream_draft::grouped::transfer",
    frame_doc: [],
    sized_doc: [],
}

/// Re-tags the sealed rows into the transfer row form: a
/// field-for-field copy over the row table. Every sealed row is
/// intact — commands exist only after the seal — so the edit column
/// re-mints as the state both algebras share.
fn transfer_rows(sealed: &[super::Row]) -> Result<Vec<Row>, TryReserveError> {
    let mut rows = Vec::new();
    rows.try_reserve_exact(sealed.len())?;
    rows.extend(sealed.iter().map(|row| Row {
        field: row.field,
        at: row.at,
        end: row.end,
        parent: row.parent,
        next: row.next,
        kids: row.kids,
        edit: Edit::Intact,
        kind: row.kind,
        flags: row.flags,
        tag_width: row.tag_width,
        delim_width: row.delim_width,
    }));
    Ok(rows)
}

/// One run coordinate under this module's own mint:
/// [`transfer_runs`] copies the sealed run table order-preserving,
/// so the sealed coordinate re-mints at its own index. (Today the
/// shared seal mints at most one run, at the table head.)
const fn transfer_run_id(id: super::SourceRunId) -> SourceRunId {
    SourceRunId::new(id.as_inner()).expect("the sealed and re-tagged run ids share one domain")
}

// The domain identity the re-mint's expect rides, pinned at compile
// time: equal heads and an equal admitted top, so every sealed run
// coordinate is in this module's own range.
const _: () = {
    assert!(SourceRunId::MIN.as_inner() == super::SourceRunId::MIN.as_inner());
    assert!(SourceRunId::new(4_294_967_294).is_some());
    assert!(super::SourceRunId::new(4_294_967_294).is_some());
};

/// One sealed layer under this module's own coordinate mint.
fn transfer_layer(layer: &super::Layer) -> Layer {
    Layer {
        first: layer.first,
        last: layer.last,
        dirty_kids: layer.dirty_kids,
        history_kids: layer.history_kids,
        source: layer.source.map(transfer_run_id),
    }
}

/// The sealed group layers under this module's own layer table.
fn transfer_layers(sealed: &[super::Layer]) -> Result<Vec<Layer>, TryReserveError> {
    let mut layers = Vec::new();
    layers.try_reserve_exact(sealed.len())?;
    layers.extend(sealed.iter().map(transfer_layer));
    Ok(layers)
}

/// The sealed source runs under this module's own run table.
fn transfer_runs(sealed: &[super::SourceRun]) -> Result<Vec<SourceRun>, TryReserveError> {
    let mut runs = Vec::new();
    runs.try_reserve_exact(sealed.len())?;
    runs.extend(sealed.iter().map(|run| SourceRun { first: run.first, end: run.end }));
    Ok(runs)
}

impl Ingest {
    /// Declares EOF and seals into the transfer editing draft —
    /// [`Ingest::finish`]'s twin for the transfer sibling. The
    /// truncation judgment and chunk custody are the shared seal's
    /// own; the sealed rows re-tag into the transfer row form in
    /// one pass over the row table (a field-for-field copy — every
    /// sealed row is intact, the state both edit algebras share),
    /// the sealed group layers re-mint their coordinates the same
    /// way, and the accumulated source moves without a copy.
    ///
    /// # Errors
    ///
    /// As [`Ingest::finish`], plus
    /// [`IngestFaultKind::Resource`] at [`ResourceSite::Rows`] when
    /// the allocator refuses the re-tagged row or layer tables.
    ///
    /// # Panics
    ///
    /// After a returned [`Failure`](super::Failure) — the shell is
    /// spent.
    ///
    /// # Examples
    ///
    /// ```
    /// use protobuf_edit::stream_draft::grouped::Ingest;
    /// use protobuf_edit::stream_draft::grouped::transfer::InsertAt;
    ///
    /// // group f1 { varint f2=5 } · varint f3=7.
    /// let mut ingest = Ingest::new();
    /// ingest.feed(&[0x0B, 0x10, 0x05, 0x0C, 0x18, 0x07]).unwrap();
    /// let mut draft = ingest.finish_transfer().unwrap();
    /// let tops: Vec<_> = draft.top().collect();
    /// draft.move_record(tops[0], InsertAt::TailOf(None)).unwrap();
    /// assert_eq!(draft.save().unwrap(), [0x18, 0x07, 0x0B, 0x10, 0x05, 0x0C]);
    /// draft.revert();
    /// assert_eq!(draft.save().unwrap(), [0x0B, 0x10, 0x05, 0x0C, 0x18, 0x07]);
    /// ```
    pub fn finish_transfer(self) -> Result<TransferDraft, super::Failure> {
        let parts = self.seal()?;
        let Ok(rows) = transfer_rows(&parts.rows) else {
            return Err(retag_refusal(parts));
        };
        let Ok(layers) = transfer_layers(&parts.layers) else {
            return Err(retag_refusal(parts));
        };
        let Ok(source_runs) = transfer_runs(&parts.source_runs) else {
            return Err(retag_refusal(parts));
        };
        Ok(TransferDraft {
            source: parts.source,
            rows,
            store: Store::new(),
            faults: Vec::new(),
            log: Vec::new(),
            root: transfer_layer(&parts.root),
            layers,
            source_runs,
        })
    }

    /// [`Ingest::finish_transfer`] into the borrowed-payload
    /// machine: the same sealed parts under
    /// [`TransferBorrowDraft`]'s payload supply.
    ///
    /// # Errors
    ///
    /// As [`Ingest::finish_transfer`].
    ///
    /// # Panics
    ///
    /// After a returned [`Failure`](super::Failure) — the shell is
    /// spent.
    pub fn finish_transfer_borrow<'p>(self) -> Result<TransferBorrowDraft<'p>, super::Failure> {
        let parts = self.seal()?;
        let Ok(rows) = transfer_rows(&parts.rows) else {
            return Err(retag_refusal(parts));
        };
        let Ok(layers) = transfer_layers(&parts.layers) else {
            return Err(retag_refusal(parts));
        };
        let Ok(source_runs) = transfer_runs(&parts.source_runs) else {
            return Err(retag_refusal(parts));
        };
        Ok(TransferBorrowDraft {
            source: parts.source,
            rows,
            store: BorrowStore::new(),
            faults: Vec::new(),
            log: Vec::new(),
            root: transfer_layer(&parts.root),
            layers,
            source_runs,
        })
    }
}

/// The re-tag reservation refused: the accumulated source rides
/// back absorbed, the fault naming the row-table site at the
/// stream's end.
#[cold]
#[allow(
    clippy::as_conversions,
    reason = "the accumulated source length caps at the u64 coordinate class"
)]
fn retag_refusal(parts: super::SealedParts) -> super::Failure {
    super::Failure {
        fault: IngestFault {
            at: parts.source.len() as u64,
            kind: IngestFaultKind::Resource(ResourceSite::Rows),
        },
        source: parts.source,
        chunk: ChunkDisposition::Absorbed,
    }
}
