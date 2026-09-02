//! Rule-driven same-allocation in-place editing (write · buffered
//! · static), per wire dialect — the dialect-orthogonal shared
//! layer.
//!
//! One job: the caller's own mutable buffer, a compiled rule set,
//! one judge walk, then equal-width writes landed directly in that
//! buffer. No output allocation exists — the input allocation *is*
//! the product — and no length prefix is ever recomputed, because
//! the machine's one law defines the cascade problem away:
//!
//! **Equal width moves no offset.** Every byte offset of every
//! framing word and payload extent in a wire document is determined
//! by the widths of the constructs before it. An edit that replaces
//! a construct's bytes with the same number of bytes therefore
//! leaves every other construct's offset, width, and kind exactly
//! where the judge walk proved them — and the exclusive `&mut`
//! borrow held from the walk through the writes makes a foreign
//! write (the only thing that could void those proofs)
//! unrepresentable. No detached plan product exists for the same
//! reason, permanently: a plan split from the borrow would need a
//! full re-parse at apply to restore what the borrow proves for
//! free, and a pointer-identity check would buy a weaker guarantee
//! at a real runtime price.
//!
//! The job runs two phases behind one door:
//!
//! - **The judge walk** reborrows the buffer read-only, admits the
//!   length, runs the compiled matcher over it (paths commit,
//!   wildcards carry descend sets — the rewriter's designation
//!   language), and judges every matched rule's action against the
//!   record's met geometry: kind, width, extent. Every fault the
//!   job can raise surfaces here, and `Err` returns with the buffer
//!   byte-identical to entry — unconditionally, because nothing has
//!   been written.
//! - **The write loop** is past the fault barrier: infallible,
//!   allocation-free, panic-free. Each planned write re-derives its
//!   bytes from its own entry (no staged byte column exists) and
//!   lands them at proven offsets. All-or-nothing needs no rollback
//!   machinery — and because this phase allocates nothing, an
//!   allocator abort can only ever strike while zero bytes are
//!   written, which is what keeps the one-shot abort policy safe
//!   for the caller's buffer.
//!
//! Working memory is the matcher's layer tables plus one write
//! list of O(matched records) entries — the grouped dialect adds an
//! O(open renumbered groups) staging stack for its pair law, bounded
//! by depth: caller-commanded work, never document overhead — a job
//! whose rules match nothing allocates independently of document
//! size.
//!
//! Acceptance is value-level ([`crate::Standard`], the rewriter's
//! precedent): the `_standard` faces pick a monomorphized walk
//! instance once at entry, and the plain faces are the tolerant
//! instance. Under `Tolerant`, an authored word may be
//! continuation-padded out to the slot's met width; under
//! `CanonicalMinimal`, admission refuses padded input and every
//! authored word must be exactly minimal at exactly the slot's
//! width. Untouched bytes are not re-emitted — they are not written
//! at all — so fidelity of everything untouched is free under
//! either standard, and the buffer re-ingests under the declared
//! standard: tolerant jobs may author padding (ecosystems with
//! canonical-strict readers should declare `CanonicalMinimal`,
//! under which no padding is ever authored), canonical jobs keep a
//! canonical document canonical through any command sequence.
//!
//! What the vocabulary deliberately cannot spell: **insert** and
//! **true delete** (new or vanished bytes move geometry — those are
//! the splicer's and rewriter's jobs), and width-moving edits of
//! any kind. [`Action::Tombstone`] is delete's equal-width residue:
//! the record's whole extent is overwritten with machine-authored
//! filler record(s) of a caller-declared field number, so the
//! record leaves the schema-visible population (reference readers
//! skip unknown fields) while the wire keeps its shape; filler
//! payloads are zeroed, so no tombstoned content survives. The
//! filler field is wire-visible to schema-less consumers and
//! collides with real fields if chosen badly — the caller declares
//! it and owns that risk. [`Action::ReplaceRecord`] is the
//! whole-record escape hatch: equal-extent replacement bytes that
//! must re-parse as exactly one lawful record, which is how
//! kind-crossing and compound rewrites are spelled (never as bare
//! actions).
//!
//! Laws shared with the rewriter: one action rule per record (two
//! rules on one record is a `Conflict` fault); a record wholly
//! overwritten ([`Action::SetPayload`], [`Action::Tombstone`],
//! [`Action::ReplaceRecord`]) does not have its interior walked —
//! rules inside it do not fire, silently, and the zero [`Stats`]
//! count is the operator's signal. A renumbered container's
//! interior stays live: the tag write and any interior write are
//! disjoint by construction. Non-overlap of all planned writes
//! follows from those laws plus the record partition — the write
//! list needs no overlap scan.
//!
//! Each apply is a one-shot job on the buffer's current bytes.
//! Re-applying the same rules is a new job on the new document and
//! is not idempotent in general (a tombstone's filler field can
//! itself match a rule on the second pass). The machine never holds
//! a byte of the original, so undo is the caller's own snapshot,
//! taken or not taken before the call: commit-only is what
//! same-allocation means. The compiled [`RuleSet`] is the reusable
//! artifact — compile once, apply across a fleet of buffers; every
//! call re-judges its own buffer fully.
//!
//! Allocation policy: every allocation here is single-job working
//! memory — the matcher's layers and the write list — grown under
//! the global allocator's panic/abort discipline, with zero
//! fallible reservations. The write loop allocates nothing (the
//! abort-safety constraint above).
//!
//! Coordinates: write · buffered · static · Standard (value-level) · in-place · commit-only.
//!
//! # Choosing a face
//!
//! One authoring door and one job face per dialect: [`RuleSet::over`]
//! judges the rules' static shape once (const-capable — a `static`
//! rule set pays at compile time); `apply` runs one job under
//! tolerant acceptance, `apply_standard` under a declared
//! [`crate::Standard`]. The buffer is the product; [`Stats`] is the
//! receipt, and a zero count there is the silently-inapplicable-rule
//! signal.
//!
//! Elsewhere: edits that move widths (insert, delete, grow, shrink)
//! → `patch`, `splice`, or `rewrite`, each behind its feature —
//! composed with a copy-back when the result must land in the
//! source allocation, which is exactly the two extra document
//! passes and the document-sized allocation this cell exists to
//! delete. Reading what a path designates without writing →
//! `select`.
//!
//! # Examples
//!
//! ```
//! # #[cfg(feature = "inplace-groupless")] {
//! use protobuf_edit::inplace::groupless::apply;
//! use protobuf_edit::inplace::{Action, Rule, RuleSet};
//! use protobuf_edit::path::Segment;
//! use protobuf_edit::{DepthLimit, FieldNumber};
//!
//! // varint f1=150 · LEN f2 "hi": replace both values in place.
//! let mut msg = [0x08, 0x96, 0x01, 0x12, 0x02, 0x68, 0x69];
//! let f1 = FieldNumber::new(1).unwrap();
//! let f2 = FieldNumber::new(2).unwrap();
//! let rules = [
//!     Rule { path: &[Segment::Field(f1)], action: Action::SetVarint(200) },
//!     Rule { path: &[Segment::Field(f2)], action: Action::SetPayload(b"no") },
//! ];
//! let set = RuleSet::over(&rules).unwrap();
//!
//! let stats = apply(&mut msg, &set, DepthLimit::REFERENCE).unwrap();
//! assert_eq!(msg, [0x08, 0xC8, 0x01, 0x12, 0x02, b'n', b'o']);
//! assert_eq!(stats.replaced(), 2);
//! # }
//! ```
//!
//! # Recipes
//!
//! One compiled set, a fleet of buffers — each job re-judges its
//! own bytes, so no cross-buffer identity contract exists, and a
//! faulted buffer skips without poisoning the loop:
//!
//! ```
//! # #[cfg(feature = "inplace-groupless")] {
//! use protobuf_edit::inplace::groupless::apply;
//! use protobuf_edit::inplace::{Action, Rule, RuleSet};
//! use protobuf_edit::path::Segment;
//! use protobuf_edit::{DepthLimit, FieldNumber};
//!
//! let f1 = FieldNumber::new(1).unwrap();
//! let rules = [Rule { path: &[Segment::Field(f1)], action: Action::SetVarint(0) }];
//! let set = RuleSet::over(&rules).unwrap();
//!
//! let mut fleet = [[0x08, 0x05], [0x08, 0x7F]];
//! for buf in &mut fleet {
//!     apply(buf, &set, DepthLimit::REFERENCE).unwrap();
//! }
//! assert_eq!(fleet, [[0x08, 0x00], [0x08, 0x00]]);
//! # }
//! ```

use crate::admission::usize_of;
use crate::path::{self, Segment};
use crate::varint::{ValueWidth, WordWidth, encoded_len32, write32_at, write64_at};
use crate::wire::{FieldNumber, Low3, PayloadLen};

/// What happens to a record the rule's path matches, judged
/// against that record's met geometry (kind, width, extent).
///
/// Two width regimes, declared by the job's [`crate::Standard`]:
/// under `Tolerant` an authored varint word may be
/// continuation-padded to the slot's met width; under
/// `CanonicalMinimal` it must be exactly minimal at exactly the
/// slot's width — nothing else fits without moving geometry.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Action<'r> {
    /// Replace a varint record's value. Judged
    /// `encoded_len64(value) <= slot width` (`Tolerant`, padded
    /// fill) or `== slot width` (`CanonicalMinimal`); the refusal
    /// is `ValueWidth`.
    SetVarint(u64),
    /// Replace an I32 record's bits (width four equals four —
    /// always fits).
    SetI32(u32),
    /// Replace an I64 record's bits (width eight equals eight —
    /// always fits).
    SetI64(u64),
    /// Overwrite a LEN payload with equal-length bytes
    /// (`bytes.len() == payload_len`, exactly, under both
    /// standards; the refusal is `PayloadLength`). The bytes are
    /// opaque — a caller declaration, never parsed. The record's
    /// interior is not walked (module doc's ownership law).
    SetPayload(&'r [u8]),
    /// Rewrite the tag word(s) to a new field number at the met
    /// tag width, same wire kind (padded / exact by standard; the
    /// refusal is `TagWidth`). In the grouped dialect a group's
    /// start and end tags are judged and written as one atomic
    /// pair, each at its own met width. The record's interior
    /// stays live.
    Renumber(FieldNumber),
    /// Overwrite the whole record extent with caller-supplied
    /// bytes of exactly that length, which must re-parse as
    /// exactly one lawful record under the job's dialect and
    /// standard (refusals: `ReplacementLength`, `ReplacementWire`,
    /// `ReplacementShape`). The lawful spelling of kind-crossing
    /// and compound rewrites; LEN payloads inside the replacement
    /// are opaque, exactly as in source parsing. The replaced
    /// record's interior is not walked.
    ReplaceRecord(&'r [u8]),
    /// Overwrite the whole record extent with machine-authored
    /// filler record(s) of `field` — the equal-width form of
    /// delete. Solvable exactly when the extent holds the filler's
    /// tag plus one byte (else `FillerUnfit`); filler payloads are
    /// zeroed, so no tombstoned content survives. The filler field
    /// is wire-visible and the caller owns the collision risk
    /// (module doc). A grouped target's whole group extent
    /// tombstones as one.
    Tombstone {
        /// The unknown-field number the filler carries.
        field: FieldNumber,
    },
}

/// One in-place editing rule: a root-anchored path and the action
/// at its target (the last segment selects records, the prefix
/// selects and commits containers).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Rule<'r> {
    /// The path pattern.
    pub path: &'r [Segment<'r>],
    /// The action at the target.
    pub action: Action<'r>,
}

const _: () = {
    assert!(if cfg!(target_pointer_width = "64") {
        core::mem::size_of::<Rule<'_>>() == 40
    } else {
        // Narrower pointers are bounded by the same ceiling.
        core::mem::size_of::<Rule<'_>>() <= 40
    });
};

/// An authoring error, judged once at [`RuleSet::over`] — distinct
/// from document faults (different reader, different fix).
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RuleError {
    /// A rule with no segments selects nothing.
    EmptyPath {
        /// The offending rule's index.
        rule: u32,
    },
    /// The last segment is a wildcard: no selected field.
    WildcardTarget {
        /// The offending rule's index.
        rule: u32,
    },
    /// A wildcard with an empty descend set is a degenerate ε.
    EmptyDescendSet {
        /// The offending rule's index.
        rule: u32,
        /// The offending segment's index.
        segment: u32,
    },
    /// A descend set spelled out of canonical order. The set's one
    /// admitted spelling is strictly ascending field numbers:
    /// membership is order-blind, so admitting permutations (or
    /// repeats) would let two spellings of one set slip past the
    /// duplicate judgment and collide at match time instead.
    UnsortedDescend {
        /// The offending rule's index.
        rule: u32,
        /// The offending segment's index.
        segment: u32,
    },
    /// Two adjacent wildcards whose descend sets are comparable
    /// (equal, or one containing the other): since `B ⊆ A` makes
    /// `A* · B* = A*`, the pair is a redundant spelling of one
    /// wildcard, and admitting it would let two spellings of one
    /// path slip past the duplicate judgment (adjacent wildcards
    /// over incomparable sets are a real composition and stay
    /// admitted).
    AdjacentWildcards {
        /// The offending rule's index.
        rule: u32,
        /// The second wildcard's segment index.
        segment: u32,
    },
    /// Two rules with identical paths: every hit would be a
    /// guaranteed double-target conflict, judged early.
    DuplicatePath {
        /// The first rule's index.
        first: u32,
        /// The second rule's index.
        second: u32,
    },
    /// A rule's byte payload — [`Action::SetPayload`] or
    /// [`Action::ReplaceRecord`] — longer than the LEN class: no
    /// met extent could ever equal it, and the walk's width
    /// arithmetic lives in the class.
    OversizeValue {
        /// The offending rule's index.
        rule: u32,
    },
    /// More rules than the matcher's state domain (65,535) admits.
    TooManyRules {
        /// The number of rules offered.
        count: usize,
    },
    /// A path with more segments than the matcher's state domain
    /// (65,535) admits.
    PathTooLong {
        /// The offending rule's index.
        rule: u32,
    },
}

impl core::fmt::Display for RuleError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::EmptyPath { rule } => write!(f, "rule {rule} has an empty path"),
            Self::WildcardTarget { rule } => write!(f, "rule {rule} ends on a wildcard"),
            Self::EmptyDescendSet { rule, segment } => {
                write!(f, "rule {rule} segment {segment} is a wildcard with an empty descend set")
            }
            Self::UnsortedDescend { rule, segment } => {
                write!(
                    f,
                    "rule {rule} segment {segment} spells its descend set out of order \
                     (the canonical spelling is strictly ascending)"
                )
            }
            Self::AdjacentWildcards { rule, segment } => {
                write!(
                    f,
                    "rule {rule} segments {} and {segment} respell one wildcard \
                     (adjacent wildcards over comparable descend sets collapse \
                      into the wider one)",
                    segment - 1
                )
            }
            Self::DuplicatePath { first, second } => {
                write!(f, "rules {first} and {second} share one path")
            }
            Self::OversizeValue { rule } => {
                write!(f, "rule {rule}'s byte payload exceeds the LEN class")
            }
            Self::TooManyRules { count } => {
                write!(f, "{count} rules exceed the 65,535-rule limit")
            }
            Self::PathTooLong { rule } => {
                write!(f, "rule {rule}'s path exceeds the 65,535-segment limit")
            }
        }
    }
}

impl core::error::Error for RuleError {}

/// The authoring judgment behind the door: the state domain caps,
/// the shared path shape laws, the byte-payload class, and the
/// duplicate scan.
const fn judge(rules: &[Rule<'_>]) -> Result<(), RuleError> {
    // Admission for the matcher's (u16, u16) state domain: both
    // indices are minted below this cap, so the narrowing casts
    // at the mint sites are lossless by this proof.
    #[allow(clippy::as_conversions, reason = "u16::MAX widens losslessly for the cap check")]
    if rules.len() > u16::MAX as usize {
        return Err(RuleError::TooManyRules { count: rules.len() });
    }
    let mut index = 0;
    while index < rules.len() {
        let rule = &rules[index];
        let at = path::ix_u32(index);
        #[allow(clippy::as_conversions, reason = "u16::MAX widens losslessly for the cap check")]
        if rule.path.len() > u16::MAX as usize {
            return Err(RuleError::PathTooLong { rule: at });
        }
        if let Err(breach) = path::judge_path(rule.path) {
            return Err(shape_error(breach, at));
        }
        // Byte payloads must be able to equal a met extent, and
        // the walk's width arithmetic lives in the LEN class —
        // judged here so the walk stores lengths as u32 by proof.
        match rule.action {
            Action::SetPayload(bytes) | Action::ReplaceRecord(bytes)
                if bytes.len() > usize_of(PayloadLen::MAX.as_inner()) =>
            {
                return Err(RuleError::OversizeValue { rule: at });
            }
            _ => {}
        }
        index += 1;
    }
    // The direct quadratic duplicate scan reports the smallest
    // (first, second) pair: outer index ascends, inner index
    // ascends past it. Admission-time cost, never per job — and
    // const-capable, so a static rule set pays it at compile time.
    let mut first = 0;
    while first < rules.len() {
        let mut second = first + 1;
        while second < rules.len() {
            if path::paths_equal(rules[first].path, rules[second].path) {
                return Err(RuleError::DuplicatePath {
                    first: path::ix_u32(first),
                    second: path::ix_u32(second),
                });
            }
            second += 1;
        }
        first += 1;
    }
    Ok(())
}

/// Maps a shared shape breach onto this module's error vocabulary.
const fn shape_error(breach: path::ShapeBreach, rule: u32) -> RuleError {
    match breach {
        path::ShapeBreach::EmptyPath => RuleError::EmptyPath { rule },
        path::ShapeBreach::WildcardTarget => RuleError::WildcardTarget { rule },
        path::ShapeBreach::EmptyDescendSet { segment } => {
            RuleError::EmptyDescendSet { rule, segment }
        }
        path::ShapeBreach::UnsortedDescend { segment } => {
            RuleError::UnsortedDescend { rule, segment }
        }
        path::ShapeBreach::AdjacentWildcards { segment } => {
            RuleError::AdjacentWildcards { rule, segment }
        }
    }
}

/// A compiled rule set: authoring judged once, jobs downstream are
/// judgment-free.
///
/// Pure borrowed data (`Copy`, `Send + Sync`), the reusable
/// artifact of the cell: compile once — at compile time itself for
/// a `static` set — and apply across any number of buffers.
#[must_use]
#[derive(Clone, Copy, Debug)]
pub struct RuleSet<'r> {
    rules: &'r [Rule<'r>],
}

impl<'r> RuleSet<'r> {
    /// Judges the rules' static shape (paths, descend sets,
    /// duplicates, byte-payload class) and seals the set.
    ///
    /// # Errors
    ///
    /// [`RuleError::TooManyRules`] and [`RuleError::PathTooLong`]
    /// when either axis leaves the matcher's state domain;
    /// [`RuleError::EmptyPath`], [`RuleError::WildcardTarget`],
    /// and [`RuleError::EmptyDescendSet`] for degenerate paths;
    /// [`RuleError::UnsortedDescend`] for a descend set spelled
    /// out of its canonical strictly-ascending order (repeats
    /// included); [`RuleError::AdjacentWildcards`] for two
    /// wildcards in a row over comparable descend sets — equal, or
    /// one containing the other — a redundant spelling of the
    /// wider one; [`RuleError::OversizeValue`] for a byte payload
    /// outside the LEN class; [`RuleError::DuplicatePath`] when
    /// two rules would target every hit twice.
    ///
    /// # Examples
    ///
    /// ```
    /// use protobuf_edit::FieldNumber;
    /// use protobuf_edit::inplace::{Action, Rule, RuleError, RuleSet};
    /// use protobuf_edit::path::Segment;
    ///
    /// // Two rules sharing one path would double-target every hit.
    /// let field = FieldNumber::new(7).unwrap();
    /// let twice = [
    ///     Rule { path: &[Segment::Field(field)], action: Action::SetVarint(1) },
    ///     Rule { path: &[Segment::Field(field)], action: Action::SetVarint(2) },
    /// ];
    /// assert_eq!(
    ///     RuleSet::over(&twice).err(),
    ///     Some(RuleError::DuplicatePath { first: 0, second: 1 })
    /// );
    /// ```
    #[inline]
    pub const fn over(rules: &'r [Rule<'r>]) -> Result<Self, RuleError> {
        if let Err(refusal) = judge(rules) {
            return Err(refusal);
        }
        Ok(Self { rules })
    }

    /// The admitted rules, verbatim — the fixed twins' matcher and
    /// capacity derivation read paths and actions straight off the
    /// sealed set (the heap walks read through the shared matcher's
    /// path lookup instead).
    #[cfg(any(feature = "fixed-inplace-grouped", feature = "fixed-inplace-groupless"))]
    #[inline]
    pub(crate) const fn rules(&self) -> &'r [Rule<'r>] {
        self.rules
    }
}

#[cfg(any(feature = "inplace-grouped", feature = "inplace-groupless"))]
impl<'r> path::Paths<'r> for RuleSet<'r> {
    // No insert vocabulary exists here: the unit gap store keeps
    // this matcher as free of gap machinery as the read programs.
    type Gaps = ();

    #[inline]
    fn count(&self) -> u16 {
        // Lossless: `over` admitted the count to u16.
        #[allow(clippy::as_conversions, reason = "over admitted the count to u16")]
        {
            self.rules.len() as u16
        }
    }

    #[inline]
    fn path(&self, id: u16) -> &'r [Segment<'r>] {
        debug_assert!(usize::from(id) < self.rules.len(), "ids are minted below count()");
        // SAFETY: the matcher mints every id below `count()` (the
        // trait contract), and `count()` is this slice's length.
        unsafe { self.rules.get_unchecked(usize::from(id)) }.path
    }
}

/// The action of a rule the matcher quoted. Private to the walks:
/// its ids come from the matcher alone.
#[inline]
pub(crate) fn action<'r>(set: &RuleSet<'r>, rule: u16) -> Action<'r> {
    let rules = set.rules;
    debug_assert!(usize::from(rule) < rules.len(), "hits quote admitted rules");
    // SAFETY: every quoted rule id is minted by the matcher's
    // flatten from states enumerated over this same admitted
    // slice, so it is below `rules.len()`.
    unsafe { rules.get_unchecked(usize::from(rule)) }.action
}

/// The job receipt: what each action class landed.
///
/// The exposure face for silently-inapplicable rules (a pattern
/// that never matched, an interior rule under a wholly overwritten
/// record) — zero counts are the operator's signal.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct Stats {
    replaced: u32,
    renumbered: u32,
    tombstoned: u32,
    substituted: u32,
}

impl Stats {
    /// Values replaced in place ([`Action::SetVarint`],
    /// [`Action::SetI32`], [`Action::SetI64`],
    /// [`Action::SetPayload`] landings).
    #[inline]
    #[must_use]
    pub const fn replaced(self) -> u32 {
        self.replaced
    }

    /// Records renumbered (a grouped pair counts once).
    #[inline]
    #[must_use]
    pub const fn renumbered(self) -> u32 {
        self.renumbered
    }

    /// Records tombstoned (a whole group counts once).
    #[inline]
    #[must_use]
    pub const fn tombstoned(self) -> u32 {
        self.tombstoned
    }

    /// Whole records substituted ([`Action::ReplaceRecord`]
    /// landings).
    #[inline]
    #[must_use]
    pub const fn substituted(self) -> u32 {
        self.substituted
    }
}

// ─── the write list and the write loop (machine-internal) ───

/// One planned write: a proven destination extent and the facts
/// its bytes re-derive from at the loop (no staged byte column —
/// re-derivation keeps entries small and makes the loop's bytes a
/// pure function of the judged entry, with nothing to fall out of
/// coherence).
pub(crate) enum Write<'r> {
    /// A varint value at exactly `width` bytes (padded when wider
    /// than minimal — tolerant jobs only author those).
    Varint {
        /// Destination offset (the value site).
        at: u32,
        /// The met slot width; `encoded_len64(value) <= width`
        /// was judged.
        width: ValueWidth,
        /// The new value.
        value: u64,
    },
    /// An I32 record's four little-endian payload bytes.
    Fixed32 {
        /// Destination offset (the payload site).
        at: u32,
        /// The new bits.
        bits: u32,
    },
    /// An I64 record's eight little-endian payload bytes.
    Fixed64 {
        /// Destination offset (the payload site).
        at: u32,
        /// The new bits.
        bits: u64,
    },
    /// Borrowed bytes at exactly their proven extent (a LEN
    /// payload overwrite, or a whole-record replacement) — the
    /// single copy of the job.
    Payload {
        /// Destination offset.
        at: u32,
        /// The bytes; `bytes.len()` equals the judged extent.
        bytes: &'r [u8],
    },
    /// A tag word at exactly `width` bytes (a renumber; a grouped
    /// pair plans two of these).
    Tag {
        /// Destination offset (the tag site).
        at: u32,
        /// The met tag width; `encoded_len32(word) <= width` was
        /// judged.
        width: WordWidth,
        /// The new tag word.
        word: u32,
    },
    /// A tombstone: the whole record extent, refilled with the
    /// filler shape the solvability judgment proved.
    Filler {
        /// Destination offset (the record head).
        at: u32,
        /// The whole record extent; `width >= filler_need(field)`
        /// was judged.
        width: u32,
        /// The filler field.
        field: FieldNumber,
    },
}

const _: () = {
    assert!(if cfg!(target_pointer_width = "64") {
        core::mem::size_of::<Write<'_>>() == 24
    } else {
        // Narrower pointers are bounded by the same ceiling.
        core::mem::size_of::<Write<'_>>() <= 24
    });
};

/// The authored-word width judgment: a narrower word pads to the
/// slot under `Tolerant`; `CanonicalMinimal` admits the exact
/// width alone.
pub(crate) const fn width_fits<const MINIMAL: bool>(need: u32, have: u32) -> bool {
    if MINIMAL { need == have } else { need <= have }
}

/// The varint and LEN codes shared verbatim by both dialect
/// tables — the filler authoring below is dialect-orthogonal
/// because of exactly this coincidence.
const VARINT_CODE: Low3 = match Low3::new(0) {
    Some(code) => code,
    None => unreachable!(),
};
const LEN_CODE: Low3 = match Low3::new(2) {
    Some(code) => code,
    None => unreachable!(),
};

/// The smallest record extent a tombstone of `field` can fill:
/// the filler's own minimal tag width plus one value byte. The
/// solvability theorem (below, at [`fill`]) makes this bound
/// exact under both standards.
pub(crate) const fn filler_need(field: FieldNumber) -> u32 {
    encoded_len32(crate::wire::tag_word(field, LEN_CODE)) + 1
}

/// True when a canonical LEN filler's interior `n = prefix +
/// payload` has no minimal-prefix solution: `p =
/// encoded_len32(n − p)` is unsolvable exactly on the isolated
/// set `n = 2^(7k) + k` — the widths where the interior lands
/// between the prefix classes. Those extents split into two
/// minimal fillers instead.
const fn gap_split(n: u32) -> bool {
    matches!(n, 129 | 16_386 | 2_097_155 | 268_435_460)
}

/// The minimal LEN-prefix width for an interior of `n` bytes
/// (`n = prefix + payload`, `n >= 2` and off the gap set): the
/// unique `p` with `encoded_len32(n − p) == p`, read off the
/// prefix classes directly so the loop below carries no search
/// and no failure edge.
const fn split_prefix(n: u32) -> u32 {
    if n <= 128 {
        1
    } else if n <= 16_385 {
        2
    } else if n <= 2_097_154 {
        3
    } else if n <= 268_435_459 {
        4
    } else {
        5
    }
}

/// Overwrites `width` bytes at `ptr` with the tombstone filler
/// record(s) of `field`.
///
/// The solvability theorem this authors under (with `t` the
/// filler's minimal tag width and `n = width − t ≥ 1` by the
/// walk's `FillerUnfit` judgment):
///
/// - Tolerant: `n ≤ 10` is one varint filler, value zero padded
///   to `n`; `n ≥ 11` is one LEN filler with the prefix padded to
///   five bytes over a zeroed payload of `n − 5`.
/// - Canonical: `n = 1` is the one-byte varint filler; other `n`
///   off the gap set are one LEN filler at the minimal prefix
///   width ([`split_prefix`]); `n` on the gap set
///   ([`gap_split`]) peels one minimal varint filler of extent
///   `t + 1` first, leaving an interior that is provably off the
///   gap set (every gap value exceeds the next-lower prefix class
///   top by more than `t + 1` for every `t ≤ 5`).
///
/// Every byte of the extent is written — filler payloads are
/// zeroed — and every branch lands on a total emission, so the
/// write loop keeps its no-fault, no-panic discipline through
/// this, its one composite arm.
///
/// # Safety
///
/// `ptr` must be valid for writes of `width` bytes, and
/// `width >= filler_need(field)` (the walk's judgment).
unsafe fn fill<const MINIMAL: bool>(mut ptr: *mut u8, mut width: u32, field: FieldNumber) {
    let varint_tag = crate::wire::tag_word(field, VARINT_CODE);
    let len_tag = crate::wire::tag_word(field, LEN_CODE);
    // The tag width is code-independent: the code occupies three
    // bits below the field, so both words share one bit width.
    let t = encoded_len32(len_tag);
    debug_assert!(width > t, "the walk judged width >= filler_need(field)");
    let mut n = width - t;
    if MINIMAL && gap_split(n) {
        // SAFETY: `t + 1 <= width` (judged), inside the caller's
        // extent.
        unsafe {
            write32_at(ptr, varint_tag, t);
            write64_at(ptr.add(usize_of(t)), 0, 1);
            ptr = ptr.add(usize_of(t + 1));
        }
        width -= t + 1;
        n = width - t;
    }
    if if MINIMAL { n == 1 } else { n <= 10 } {
        // SAFETY: `t + n == width` bytes at `ptr`; `n` is inside
        // the value window and zero's minimal width is one.
        unsafe {
            write32_at(ptr, varint_tag, t);
            write64_at(ptr.add(usize_of(t)), 0, n);
        }
        return;
    }
    // One LEN filler: tag, prefix (minimal or padded to the full
    // window by standard), zeroed payload — the three spans tile
    // the extent exactly.
    let p = if MINIMAL { split_prefix(n) } else { 5 };
    let payload = n - p;
    debug_assert!(encoded_len32(payload) <= p, "the prefix class holds the payload length");
    // SAFETY: `t + p + payload == width` bytes at `ptr`; the
    // prefix width is in the u32 window and at least the payload
    // length's own encoded width (the debug assertion's fact —
    // padded under Tolerant, exact under CanonicalMinimal).
    unsafe {
        write32_at(ptr, len_tag, t);
        write32_at(ptr.add(usize_of(t)), payload, p);
        core::ptr::write_bytes(ptr.add(usize_of(t + p)), 0, usize_of(payload));
    }
}

/// Phase two: lands every planned write at its proven extent.
///
/// Infallible, allocation-free, and panic-free: every fault
/// surfaced in the judge walk (the barrier), every entry's bytes
/// re-derive from the entry itself, and no write moves an offset.
/// Freedom from allocation is load-bearing — it is what confines
/// a global-allocator abort to the walk, where zero bytes have
/// been written (the module doc's abort-safety constraint); any
/// future edge added here must re-prove that.
pub(crate) fn commit<const MINIMAL: bool>(buf: &mut [u8], writes: &[Write<'_>]) {
    let base = buf.as_mut_ptr();
    for write in writes {
        // SAFETY (every arm): the walk judged each entry against
        // cursor-delivered geometry over these same admitted bytes
        // — every extent lies inside `buf` — and the exclusive
        // borrow held from the walk through this loop means no
        // foreign write voided those proofs. Entries are pairwise
        // disjoint (one rule per record, owned interiors fire no
        // rules, distinct records' extents are disjoint), and rule
        // payloads cannot alias `buf` through the safe doors, so
        // `copy_nonoverlapping`'s contract holds.
        match *write {
            Write::Varint { at, width, value } => {
                debug_assert!(usize_of(at) + usize::from(width.as_inner()) <= buf.len());
                // SAFETY: the walk judged
                // `encoded_len64(value) <= width <= 10` (met slot).
                unsafe { write64_at(base.add(usize_of(at)), value, u32::from(width.as_inner())) }
            }
            Write::Fixed32 { at, bits } => {
                debug_assert!(usize_of(at) + 4 <= buf.len());
                // SAFETY: four bytes at a cursor-proven payload
                // site; unaligned by contract.
                unsafe { base.add(usize_of(at)).cast::<u32>().write_unaligned(bits.to_le()) }
            }
            Write::Fixed64 { at, bits } => {
                debug_assert!(usize_of(at) + 8 <= buf.len());
                // SAFETY: eight bytes at a cursor-proven payload
                // site; unaligned by contract.
                unsafe { base.add(usize_of(at)).cast::<u64>().write_unaligned(bits.to_le()) }
            }
            Write::Payload { at, bytes } => {
                debug_assert!(usize_of(at) + bytes.len() <= buf.len());
                // SAFETY: `bytes.len()` equals the judged extent;
                // disjointness per the loop header.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        bytes.as_ptr(),
                        base.add(usize_of(at)),
                        bytes.len(),
                    );
                }
            }
            Write::Tag { at, width, word } => {
                debug_assert!(usize_of(at) + usize::from(width.as_inner()) <= buf.len());
                // SAFETY: the walk judged
                // `encoded_len32(word) <= width <= 5` (met tag).
                unsafe { write32_at(base.add(usize_of(at)), word, u32::from(width.as_inner())) }
            }
            Write::Filler { at, width, field } => {
                debug_assert!(usize_of(at) + usize_of(width) <= buf.len());
                // SAFETY: the record extent is cursor-proven and
                // `width >= filler_need(field)` was judged.
                unsafe { fill::<MINIMAL>(base.add(usize_of(at)), width, field) }
            }
        }
    }
}

#[cfg(feature = "inplace-grouped")]
pub mod grouped;
#[cfg(feature = "inplace-groupless")]
pub mod groupless;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::path::Segment;

    fn f(n: u32) -> FieldNumber {
        FieldNumber::new(n).unwrap()
    }

    #[test]
    fn authoring_errors_are_judged_at_construction() {
        assert_eq!(
            RuleSet::over(&[Rule { path: &[], action: Action::SetVarint(0) }]).err(),
            Some(RuleError::EmptyPath { rule: 0 })
        );
        assert_eq!(
            RuleSet::over(&[Rule {
                path: &[Segment::AnyDepth { descend: &[] }],
                action: Action::SetVarint(0)
            }])
            .err(),
            Some(RuleError::WildcardTarget { rule: 0 })
        );
        let (one, two, seven) = (f(1), f(2), f(7));
        assert_eq!(
            RuleSet::over(&[Rule {
                path: &[Segment::AnyDepth { descend: &[] }, Segment::Field(one)],
                action: Action::SetVarint(0)
            }])
            .err(),
            Some(RuleError::EmptyDescendSet { rule: 0, segment: 0 })
        );
        assert_eq!(
            RuleSet::over(&[Rule {
                path: &[Segment::AnyDepth { descend: &[two, one] }, Segment::Field(seven)],
                action: Action::SetVarint(0)
            }])
            .err(),
            Some(RuleError::UnsortedDescend { rule: 0, segment: 0 })
        );
        assert_eq!(
            RuleSet::over(&[Rule {
                path: &[
                    Segment::AnyDepth { descend: &[one] },
                    Segment::AnyDepth { descend: &[one, two] },
                    Segment::Field(seven)
                ],
                action: Action::SetVarint(0)
            }])
            .err(),
            Some(RuleError::AdjacentWildcards { rule: 0, segment: 1 })
        );
        let dup = [
            Rule { path: &[Segment::Field(one)], action: Action::SetVarint(0) },
            Rule { path: &[Segment::Field(one)], action: Action::Renumber(two) },
        ];
        assert_eq!(
            RuleSet::over(&dup).err(),
            Some(RuleError::DuplicatePath { first: 0, second: 1 })
        );
    }

    #[test]
    fn state_domain_admission_caps_rules_and_path_lengths() {
        // One over the (u16, u16) matcher state domain on each axis.
        let long_path = alloc::vec![Segment::Field(f(1)); (u16::MAX as usize) + 1];
        assert_eq!(
            RuleSet::over(&[Rule { path: &long_path, action: Action::SetVarint(0) }]).err(),
            Some(RuleError::PathTooLong { rule: 0 })
        );
        let many = alloc::vec![Rule { path: &long_path[..1], action: Action::SetVarint(0) };
            (u16::MAX as usize) + 1];
        assert_eq!(
            RuleSet::over(&many).err(),
            Some(RuleError::TooManyRules { count: (u16::MAX as usize) + 1 })
        );
    }

    // The giant class-top fixture follows the streaming twin's law: a
    // 32-bit wasm heap cannot host it, and under Miri it is byte-bulk
    // without provenance value. The judgment itself is
    // target-independent.
    #[cfg(all(not(target_family = "wasm"), not(miri)))]
    #[test]
    fn byte_payloads_face_the_len_class_judgment() {
        // Exactly at the class top is admitted (the largest lawful
        // extent a record can meet).
        let top = alloc::vec![0u8; usize::try_from(PayloadLen::MAX.as_inner()).unwrap()];
        assert!(
            RuleSet::over(&[Rule {
                path: &[Segment::Field(f(1))],
                action: Action::SetPayload(&top)
            }])
            .is_ok()
        );
        // One byte over the class refuses. A 64-bit-only row: on
        // the crate's 32-bit targets the class top is `isize::MAX`
        // itself, so an over-class byte slice cannot exist and the
        // refusal is unreachable by construction.
        #[cfg(target_pointer_width = "64")]
        {
            let big = alloc::vec![0u8; usize::try_from(PayloadLen::MAX.as_inner()).unwrap() + 1];
            for action in [Action::SetPayload(&big), Action::ReplaceRecord(&big)] {
                assert_eq!(
                    RuleSet::over(&[Rule { path: &[Segment::Field(f(1))], action }]).err(),
                    Some(RuleError::OversizeValue { rule: 0 })
                );
            }
        }
    }

    #[test]
    fn filler_need_is_the_tag_width_plus_one() {
        // The tag-width steps of the field domain: 1..=15 is one
        // byte, 16..=2047 two, up to the domain top's five.
        for (field, need) in [(1, 2), (15, 2), (16, 3), (2047, 3), (2048, 4), ((1 << 29) - 1, 6)] {
            assert_eq!(filler_need(f(field)), need, "field {field}");
        }
    }

    #[test]
    fn the_gap_set_is_exactly_the_unsolvable_prefix_interiors() {
        // Directly against the defining equation: n is a gap iff
        // no p in 1..=5 solves encoded_len32(n − p) == p. Scanning
        // the u32 domain is infeasible; the class boundaries ±2
        // and the gap set itself are the complete edge inventory,
        // since solvability is monotone between boundaries.
        let mut edges = alloc::vec::Vec::new();
        for k in 1..=4u32 {
            let boundary = 1u32 << (7 * k);
            for delta in 0..=(k + 2) {
                edges.push(boundary + delta - 1);
                edges.push(boundary + delta);
            }
        }
        for n in edges {
            if n < 2 {
                continue;
            }
            let solvable = (1..=5u32).any(|p| n >= p && encoded_len32(n - p) == p);
            assert_eq!(solvable, !gap_split(n), "n = {n}");
            if !gap_split(n) {
                let p = split_prefix(n);
                assert_eq!(encoded_len32(n - p), p, "n = {n}");
            }
        }
    }
}
