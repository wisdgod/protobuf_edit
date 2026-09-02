//! The group-capable dialect constructor: all six wire codes,
//! groups framed by tag pairs.
//!
//! Group frames carry no length, so the same value tree is cheaper
//! to author with groups than with LEN framing — closing a group
//! writes one literal tag, closing a message computes and patches a
//! prefix.
//!
//! Coordinates: author (outside the input axes) · grouped.
//!
//! # Examples
//!
//! ```
//! use protobuf_edit::FieldNumber;
//! use protobuf_edit::construct::grouped::Builder;
//!
//! let f1 = FieldNumber::new(1).unwrap();
//! let f2 = FieldNumber::new(2).unwrap();
//! let mut builder = Builder::new();
//! builder.push_varint(f1, 150);
//! builder.group(f2, |g| {
//!     g.push_varint(f1, 1);
//! });
//! assert_eq!(builder.finish().unwrap(), [0x08, 0x96, 0x01, 0x13, 0x08, 0x01, 0x14]);
//! ```

use alloc::vec::Vec;

use super::{CopyCore, Core, OverCap};
use crate::wire::FieldNumber;
use crate::wire::grouped::{RecordKind, group_end_word, head_word};

/// The root builder: complete typed records in, one message out.
///
/// A typed-only build is unconditionally lawful wire: the raw word
/// faces live only on [`BodyBuilder`], so the root cannot emit
/// headless bytes. Pushes are infallible at the call site — the one
/// data error, crossing the construction cap, poisons the builder
/// and surfaces once, at [`finish`](Self::finish). Frames open and
/// close by closure scope ([`message`](Self::message),
/// [`group`](Self::group)), so framing cannot be mismatched. `'p`
/// backs the borrowed payloads (`push_len`, `push_string`,
/// `raw_bytes`): each is held until the finish copies it into the
/// output.
#[must_use]
pub struct Builder<'p> {
    core: Core<'p>,
}

/// The frame-interior builder, lent to frame closures.
///
/// Carries the typed faces plus the raw word faces: inside a frame
/// the enclosing framing is already lawful, and a raw body plan
/// (packed elements, pre-encoded records) is the frame author's
/// declaration.
///
/// # Examples
///
/// ```
/// use protobuf_edit::FieldNumber;
/// use protobuf_edit::construct::grouped::Builder;
///
/// let f2 = FieldNumber::new(2).unwrap();
/// let mut builder = Builder::new();
/// // A pre-encoded record (varint f1=42) rides raw inside the
/// // message frame; its interior validity is the author's.
/// builder.message(f2, |m| m.raw_bytes(&[0x08, 0x2A]));
/// assert_eq!(builder.finish().unwrap(), [0x12, 0x02, 0x08, 0x2A]);
/// ```
pub struct BodyBuilder<'a, 'p> {
    core: &'a mut Core<'p>,
}

/// The copy-only root builder: [`Builder`]'s faces over the copied
/// payload supply alone.
///
/// Every payload copies into the staging store at its push under
/// the unsuffixed face names (`push_len`, `push_string`, the body
/// faces' `raw_bytes`), so no borrow table exists and no lifetime
/// parameter binds the caller; temporaries are welcome everywhere.
/// Scalar and packed pushes, framing (groups included), and the
/// finish family are the mixed machine's, face for face.
///
/// # Examples
///
/// ```
/// use protobuf_edit::FieldNumber;
/// use protobuf_edit::construct::grouped::CopyBuilder;
///
/// let f1 = FieldNumber::new(1).unwrap();
/// let f2 = FieldNumber::new(2).unwrap();
/// let mut builder = CopyBuilder::new();
/// {
///     // A temporary payload: the push copies it, so it may die
///     // before the finish — the borrowing machine refuses this.
///     let payload = vec![0xAB; 4];
///     builder.push_len(f1, &payload);
/// }
/// builder.group(f2, |g| {
///     g.push_varint(f1, 1);
/// });
/// assert_eq!(
///     builder.finish().unwrap(),
///     [0x0A, 0x04, 0xAB, 0xAB, 0xAB, 0xAB, 0x13, 0x08, 0x01, 0x14]
/// );
/// ```
#[must_use]
pub struct CopyBuilder {
    core: CopyCore,
}

/// The copy machine's frame-interior builder, lent to its frame
/// closures — [`BodyBuilder`]'s faces over the copied supply, no
/// payload lifetime.
pub struct CopyBodyBuilder<'a> {
    core: &'a mut CopyCore,
}

// The declension's saving, pinned at the machine on every pointer
// width: the copy-only builder drops the borrow table whole (one
// `Vec` — 24 bytes on 64-bit pointers; on 32-bit the reordered
// fields absorb part of it and the saving is eight).
const _: () = {
    let w64 = cfg!(target_pointer_width = "64");
    assert!(
        core::mem::size_of::<CopyBuilder>() + if w64 { 24 } else { 8 }
            == core::mem::size_of::<Builder<'_>>()
    );
};

root_faces!(mixed: Builder<'_>, Core);
root_faces!(copy: CopyBuilder, CopyCore);

impl<'p> Builder<'p> {
    typed_faces!(mixed: grouped, 'p, BodyBuilder);

    /// Pushes one designated external record as a canonical root
    /// record: the designation's exact bytes — a group's whole
    /// closure and end tag included — ride the borrow table and copy
    /// once, at the finish. This builder's output is canonical, so
    /// the argument is the proof-carrying form — a tolerant
    /// designation upgrades through `try_canonical`, which refuses
    /// padded framing anywhere in the closure. A padded record can
    /// still embed byte-exactly as an opaque LEN payload through
    /// [`push_len`](Self::push_len); it cannot be asserted as a
    /// canonical root record.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "inspect-grouped")] {
    /// use protobuf_edit::DepthLimit;
    /// use protobuf_edit::construct::grouped::Builder;
    /// use protobuf_edit::inspect::grouped::Tree;
    /// use protobuf_edit::inspect::{Admitted, NoAdvice};
    ///
    /// let source = [0x13, 0x08, 0x2A, 0x14];
    /// let input = Admitted::new(&source).unwrap();
    /// let tree = Tree::parse(input, DepthLimit::REFERENCE, &mut NoAdvice);
    /// let record = tree.record_ref(tree.top().next().unwrap()).unwrap();
    ///
    /// let mut builder = Builder::new();
    /// builder.push_record(record.try_canonical().unwrap());
    /// assert_eq!(builder.finish().unwrap(), source);
    /// # }
    /// ```
    #[inline]
    pub fn push_record(&mut self, source: crate::source::grouped::CanonicalRecordRef<'p>) {
        self.core.put_raw_bytes(source.as_bytes());
    }

    /// [`push_record`](Self::push_record)'s staging twin: copies the
    /// record's exact bytes into the builder at the push, for
    /// designations that cannot outlive it.
    #[inline]
    pub fn push_record_copy(&mut self, source: crate::source::grouped::CanonicalRecordRef<'_>) {
        self.core.put_raw_bytes_copy(source.as_bytes());
    }

    /// Frames `body`'s records as a group of `field`: open tag,
    /// body, matching end tag — no length prefix.
    ///
    /// # Examples
    ///
    /// Frames nest by closure scope, groups and messages alike:
    ///
    /// ```
    /// use protobuf_edit::FieldNumber;
    /// use protobuf_edit::construct::grouped::Builder;
    ///
    /// let f1 = FieldNumber::new(1).unwrap();
    /// let f2 = FieldNumber::new(2).unwrap();
    /// let mut builder = Builder::new();
    /// builder.group(f2, |g| {
    ///     g.message(f1, |m| m.push_bool(f1, true));
    /// });
    /// assert_eq!(builder.finish().unwrap(), [0x13, 0x0A, 0x02, 0x08, 0x01, 0x14]);
    /// ```
    #[inline]
    pub fn group(&mut self, field: FieldNumber, body: impl FnOnce(&mut BodyBuilder<'_, 'p>)) {
        self.core.group_frame(head_word(field, RecordKind::Group), group_end_word(field), |core| {
            body(&mut BodyBuilder { core })
        });
    }
}

impl<'p> BodyBuilder<'_, 'p> {
    typed_faces!(mixed: grouped, 'p, BodyBuilder);
    raw_faces!(mixed: 'p);

    /// Frames `body`'s records as a group of `field`: open tag,
    /// body, matching end tag — no length prefix.
    #[inline]
    pub fn group(&mut self, field: FieldNumber, body: impl FnOnce(&mut BodyBuilder<'_, 'p>)) {
        self.core.group_frame(head_word(field, RecordKind::Group), group_end_word(field), |core| {
            body(&mut BodyBuilder { core })
        });
    }
}

impl CopyBuilder {
    typed_faces!(copy: grouped, CopyBodyBuilder);

    /// Pushes one designated external record as a canonical root
    /// record: the designation's exact bytes — a group's whole
    /// closure and end tag included — land in the owned staging
    /// store at the push, so no designation lifetime binds the
    /// builder. This builder's output is canonical, so the argument
    /// is the proof-carrying form — a tolerant designation upgrades
    /// through `try_canonical`, which refuses padded framing
    /// anywhere in the closure.
    #[inline]
    pub fn push_record(&mut self, source: crate::source::grouped::CanonicalRecordRef<'_>) {
        self.core.put_raw_bytes_copy(source.as_bytes());
    }

    /// Frames `body`'s records as a group of `field`: open tag,
    /// body, matching end tag — no length prefix.
    #[inline]
    pub fn group(&mut self, field: FieldNumber, body: impl FnOnce(&mut CopyBodyBuilder<'_>)) {
        self.core.group_frame(head_word(field, RecordKind::Group), group_end_word(field), |core| {
            body(&mut CopyBodyBuilder { core })
        });
    }
}

impl CopyBodyBuilder<'_> {
    typed_faces!(copy: grouped, CopyBodyBuilder);
    raw_faces!(copy);

    /// Frames `body`'s records as a group of `field`: open tag,
    /// body, matching end tag — no length prefix.
    #[inline]
    pub fn group(&mut self, field: FieldNumber, body: impl FnOnce(&mut CopyBodyBuilder<'_>)) {
        self.core.group_frame(head_word(field, RecordKind::Group), group_end_word(field), |core| {
            body(&mut CopyBodyBuilder { core })
        });
    }
}

#[cfg(test)]
mod tests;
