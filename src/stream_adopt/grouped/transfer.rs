//! The grouped stream-ingest adopt's transfer sibling.
//!
//! The same commit-only editing faces plus whole-record relocation
//! and external import, emitted as its own sealed machine so the
//! base adopt pays none of the capability's carried state or
//! dispatch. The ingest phase is the base cell's [`Ingest`] whole —
//! feed grammar, custody, and truncation judgments untouched — and
//! [`Ingest::finish_transfer`] is this sibling's seal door: the
//! sealed rows re-tag into the transfer row form in one pass over
//! the row table (the transfer state byte extends the plain one
//! bit-for-bit and zero marks the plain zone, so a scanned row's
//! bits carry over unchanged), and the accumulated source moves.
//!
//! One machine carries both import policies on the mixed payload
//! store: `copy_record_from` retains the designated record's bytes
//! borrowed (the backing must outlive the adopt), and
//! `copy_record_from_copy` stages one exact record-length copy at
//! the command. The local transfer faces — `copy_record`,
//! `move_record`, `copy_payload`, `move_payload` — stage zero
//! bytes: the rows carry coordinates into the machine's own
//! ingested source.

use alloc::vec::Vec;

use crate::admission::{Coord, Extent, admitted_u32, usize_of};
use crate::stream_adopt::{Handle, PayloadAt, PayloadStore, RowId, WordAt, WordStore, parts_len_usize};
use crate::varint::slice::{self, ReadFault};
use crate::varint::{WordWidth, encoded_len32, encoded_len64, push64};
use crate::wire::grouped::{RecordKind, TagClass, classify, group_end_word, head_word};
use crate::wire::{FieldNumber, Low3, PayloadLen};
use crate::{DepthLimit, Span};

use super::Ingest;

pub use crate::stream_adopt::transfer::PayloadTarget;
pub use crate::stream_adopt::{EditStatus, InsertAt};

#[cfg(test)]
mod tests;

crate::editor::grouped::one_shot_machine! {
    vocabulary stream(
        Ancestors, Children, Descent, EditFault, Fault, FaultKind,
        FrameFault, PayloadWrite, RecordSpans, Refusal, SaveFault,
        SaveSpans, SizedPayloadWrite,
    ),
    capability: transfer,
    acceptance: tolerant,
    noun: "adopt",
    a_noun: "an adopt",
    A_noun: "An adopt",
}

crate::editor::grouped::one_shot_machine! {
    /// A one-shot editing adopt with the transfer capability,
    /// sealed from a chunked stream.
    ///
    /// [`Adopt`](super::Adopt)'s command and save faces plus
    /// whole-record relocation, payload relocation, and external
    /// import on the mixed payload supply, over the ingested
    /// source. Plain data over owned `Vec`s, `Send` like the base
    /// machine. Handles stay valid for the adopt's life; rows and
    /// stored values are never reclaimed (the commit-only trade).
    /// `'p` backs the borrowed payloads and borrowed imported
    /// records; the `_copy` faces stage a copy at the command
    /// instead. The only door is [`Ingest::finish_transfer`] — the
    /// input arrived as a stream, so no buffered open exists on
    /// this type.
    machine TransferAdopt<'p> { source: Vec<u8> }
    capability: transfer,
    payloads: PayloadStore<'p>,
    backing: mixed(PayloadWrite, SizedPayloadWrite),
    payload: 'p,
    tenure: stream,
    acceptance: tolerant,
    noun: "adopt",
    a_noun: "an adopt",
    A_noun: "An adopt",
    doc_mod: "protobuf_edit::stream_adopt::grouped::transfer",
    doc_open: "{ let mut ingest = protobuf_edit::stream_adopt::grouped::Ingest::new(DepthLimit::REFERENCE); ingest.feed(&msg).unwrap(); ingest.finish_transfer() }",
    doc_open_empty: "protobuf_edit::stream_adopt::grouped::Ingest::new(DepthLimit::REFERENCE).finish_transfer()",
    doc_recipes: " Price-reserve-save composes growth-free: reserve exactly [`TransferAdopt::save_len`]'s answer and [`TransferAdopt::save_into`] never grows the buffer.",
}

// The machine layout, pinned on every pointer width: the transfer
// sibling carries the base machine's fields over the same stores,
// so the equality is width-independent and the 32-bit check gate
// evaluates it; any drift lands here for review.
const _: () =
    assert!(core::mem::size_of::<TransferAdopt<'_>>() == core::mem::size_of::<super::Adopt<'_>>());

impl Ingest {
    /// Declares EOF and seals into the transfer editing adopt —
    /// [`Ingest::finish`]'s twin for the transfer sibling. The
    /// truncation judgment and chunk custody are the shared seal's
    /// own; the sealed rows re-tag into the transfer row form in
    /// one pass over the row table (a field-for-field copy — the
    /// transfer state byte extends the plain one bit-for-bit, and
    /// zero marks the plain zone), and the accumulated source
    /// moves without a copy.
    ///
    /// # Errors
    ///
    /// As [`Ingest::finish`].
    ///
    /// # Panics
    ///
    /// After a returned [`Failure`](super::Failure) — the shell is
    /// spent.
    ///
    /// # Examples
    ///
    /// ```
    /// use protobuf_edit::DepthLimit;
    /// use protobuf_edit::stream_adopt::grouped::Ingest;
    /// use protobuf_edit::stream_adopt::grouped::transfer::InsertAt;
    ///
    /// let mut ingest = Ingest::new(DepthLimit::REFERENCE);
    /// ingest.feed(&[0x08, 0x05, 0x12, 0x02, 0x68, 0x69]).unwrap();
    /// let mut adopt = ingest.finish_transfer().unwrap();
    /// let tops: Vec<_> = adopt.top().collect();
    /// adopt.copy_record(tops[1], InsertAt::HeadOf(None)).unwrap();
    /// assert_eq!(
    ///     adopt.save().unwrap(),
    ///     [0x12, 0x02, 0x68, 0x69, 0x08, 0x05, 0x12, 0x02, 0x68, 0x69]
    /// );
    /// ```
    pub fn finish_transfer<'p>(self) -> Result<TransferAdopt<'p>, super::Failure> {
        let sealed = self.seal()?;
        let mut rows = Vec::with_capacity(sealed.rows.len());
        rows.extend(sealed.rows.iter().map(|row| Row {
            field: row.field,
            start: row.start,
            payload_len: row.payload_len,
            parent: row.parent,
            next: row.next,
            kid: row.kid,
            value: row.value,
            kind: row.kind,
            tag_width: row.tag_width,
            delim_width: row.delim_width,
            state: row.state,
        }));
        Ok(TransferAdopt {
            source: sealed.source,
            rows,
            words: WordStore::new(),
            payloads: PayloadStore::new(),
            faults: Vec::new(),
            top: sealed.top,
            limit: sealed.limit,
            dirty: false,
        })
    }
}
