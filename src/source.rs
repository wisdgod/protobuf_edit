//! Source-designation contract types: proof-backed names for one
//! parsed occurrence in an immutable source document.
//!
//! The carriers are minted only by the machines that proved them
//! and consumed by the transfer and import faces.
//!
//! A designation identifies the occurrence's exact byte range, its
//! field and wire kind, its framing geometry at the widths actually
//! met, and — for a LEN — the exact payload subspan. It never names
//! an editor's current effective value: on an edited handle the
//! designation still means the original admitted occurrence. The
//! carrier types have no public constructor; holding one is the
//! proof that a machine bound those facts to those bytes.
//!
//! Dialects are sibling modules, not parameters: `grouped` records
//! carry a structural group closure and its relative depth,
//! `groupless` records never contain a group. A groupless record
//! widens to a grouped one without judgment; a grouped record
//! narrows only after the common-kind proof (its outer kind is not
//! a group). The dialect-neutral [`PayloadRef`] is a LEN interior
//! detached from its framing: exact bytes, no record identity.
//!
//! Acceptance travels as proof, not policy: `try_canonical` walks
//! the record's framing words once and mints the canonical form at
//! the first success, refusing at the first non-minimal word. A LEN
//! interior is opaque and never participates in that judgment; a
//! group interior is structural and always does.

/// A LEN payload detached from its record: the exact interior
/// bytes, with the tag and length prefix stripped.
///
/// Minted by the dialect record types' `payload` projections. The
/// interior is the source's declaration: consumers install it as
/// opaque bytes through their existing payload faces, so a padded
/// word inside it is preserved, never judged.
///
/// # Examples
///
/// ```
/// # #[cfg(feature = "inspect-groupless")] {
/// use protobuf_edit::DepthLimit;
/// use protobuf_edit::inspect::{Admitted, NoAdvice};
/// use protobuf_edit::inspect::groupless::Tree;
///
/// // LEN f2 "hi": the payload view is the interior alone.
/// let msg = [0x12, 0x02, 0x68, 0x69];
/// let input = Admitted::new(&msg).unwrap();
/// let tree = Tree::parse(input, DepthLimit::REFERENCE, &mut NoAdvice);
/// let record = tree.record_ref(tree.top().next().unwrap()).unwrap();
/// assert_eq!(record.payload().unwrap().as_bytes(), [0x68, 0x69]);
/// # }
/// ```
#[must_use]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PayloadRef<'s> {
    bytes: &'s [u8],
}

impl<'s> PayloadRef<'s> {
    /// Crate-internal mint: the dialect projections hand the exact
    /// interior subspan.
    pub(crate) const fn new(bytes: &'s [u8]) -> Self {
        Self { bytes }
    }

    /// The exact payload interior bytes.
    #[inline]
    #[must_use]
    pub const fn as_bytes(&self) -> &'s [u8] {
        self.bytes
    }

    /// Interior length in bytes (in the length class: the minting
    /// machine admitted the record).
    #[inline]
    #[must_use]
    pub const fn len(&self) -> u32 {
        crate::admission::admitted_u32(self.bytes.len())
    }

    /// True for an empty interior.
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

#[cfg(any(
    feature = "inspect-grouped",
    feature = "fixed-inspect-grouped",
    feature = "retain-grouped",
    feature = "patch-grouped",
    feature = "fixed-patch-grouped",
    feature = "adopt-grouped",
    feature = "amend-grouped",
    feature = "intake-grouped",
    feature = "markup-grouped",
    feature = "draft-grouped",
    feature = "review-grouped",
    feature = "session-grouped",
    feature = "stream-adopt-grouped",
    feature = "stream-draft-grouped",
    feature = "stream-intake-grouped",
    feature = "collect-grouped",
    feature = "construct-grouped"
))]
pub mod grouped;
#[cfg(any(
    feature = "inspect-groupless",
    feature = "fixed-inspect-groupless",
    feature = "retain-groupless",
    feature = "patch-groupless",
    feature = "fixed-patch-groupless",
    feature = "adopt-groupless",
    feature = "amend-groupless",
    feature = "intake-groupless",
    feature = "markup-groupless",
    feature = "draft-groupless",
    feature = "review-groupless",
    feature = "session-groupless",
    feature = "stream-adopt-groupless",
    feature = "stream-draft-groupless",
    feature = "stream-intake-groupless",
    feature = "collect-groupless",
    feature = "construct-groupless"
))]
pub mod groupless;
