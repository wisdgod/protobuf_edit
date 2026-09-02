//! Rule-driven batch rewriting (write · buffered · static),
//! per wire dialect — the dialect-orthogonal shared layer.
//!
//! One job: borrowed input bytes, a compiled rule set, two passes
//! (measure, then emit), new output bytes. Zero retention — no
//! handles, no undo (re-running is undo), no cross-job state; the
//! inter-pass slot table is single-job working memory.
//!
//! Rules are pure data: a path (root-anchored segments) paired with
//! an action. Determinism across the two passes is satisfied by
//! construction — both passes run the same matcher over the same
//! bytes — so the emit pass sits past the fault barrier: its
//! refusal channel is uninhabited, and its assertions pin library
//! invariants, not caller behavior. Paths commit: every LEN a
//! pattern crosses is a Commit — the payload is committed to be a
//! message, and a parse fault inside it is a real fault (this
//! library never guesses messageness; speculative downgrade would
//! rewrite blobs that merely parse). Wildcards carry an explicit
//! descend set — the caller's transcription of "which fields are
//! messages" — because an unrestricted wildcard would fault on the
//! first string field of exactly the recursive schemas it exists
//! to serve.
//!
//! The dialect modules read through the crate's private cursor
//! engines — the same walks the `traverse` faces re-export —
//! so selecting a rewrite cell compiles no traverse surface.
//!
//! Output acceptance: replacement payloads, every word a
//! `Normalize` touches, and every inserted record are emitted
//! minimally, everything else — tags, kept records, crossed
//! framing — rides verbatim; the output always re-ingests under
//! `Tolerant`, and closes under `CanonicalMinimal` exactly when
//! every padded word either was absent from the source or fell
//! under a `Normalize` target (inserted words are minimal by
//! construction and never break closure).
//!
//! Allocation policy: every allocation here is single-job working
//! memory — the compiled rule layers, the walk's frame stack, the
//! inter-pass slot ledger, and the output buffer — grown under the
//! global allocator's panic/abort discipline, with zero fallible
//! reservations. A job holds nothing a re-run cannot replay from
//! the caller's own inputs (borrowed bytes, rules as pure data),
//! so allocation refusal is never a structured `Err`.
//!
//! Coordinates: write · buffered · static · Standard (value-level) · borrowed · commit-only.
//!
//! # Choosing a face
//!
//! Two authoring doors, three job faces:
//!
//! - [`RuleSet::over`] judges the rules' static shape once;
//!   compile one set and run it across documents — jobs
//!   downstream are judgment-free. It refuses [`Action::Insert`]:
//!   the insert-free set is the thin form, whose matcher carries
//!   no gap machinery at all. [`InsertRuleSet::over`] is the
//!   insert-admitting door — same judgments, plus the gap
//!   machinery the Insertion section describes; its receipt
//!   ([`InsertStats`]) alone carries the inserted count.
//! - `rewrite` runs one job into a fresh buffer; `rewrite_into`
//!   appends into yours (untouched on `Err`) — the reuse face for
//!   batch loops; `rewrite_sink` hands the same bytes to a caller
//!   sink slice by slice — choose the `Vec` faces when the
//!   product accumulates locally, the sink face when the bytes
//!   leave through a writer and an intermediate buffer would only
//!   be copied out again (every fault precedes the first handoff,
//!   so the sink receives nothing on `Err`). All three return
//!   [`Stats`], and a zero count there is the
//!   silently-inapplicable-rule signal.
//! - Each job face has a `_standard` twin taking the input
//!   acceptance [`Standard`](crate::Standard): the value picks a
//!   monomorphized walk instance once at entry, so the plain
//!   faces are exactly the tolerant instances and a canonical job
//!   refuses padded widths where the stream machines would.
//! - A third authoring door under feature `transfer-rewrite-*`:
//!   `TransferRuleSet::over` compiles copy/move rules
//!   (`RecordTransferRule`, `PayloadCopyRule`, `PayloadMoveRule`)
//!   relocating path-designated records and payloads inside one
//!   document, beside the ordinary actions; its jobs —
//!   `rewrite_transfers`, `rewrite_transfers_into`,
//!   `rewrite_transfers_sink`, each with a `_standard` twin —
//!   walk the document three times where plain jobs walk twice.
//!
//! Authoring is data: a [`Rule`] is a path of [`Segment`]s (the
//! [`crate::path`] stratum's vocabulary) times an [`Action`].
//! [`Segment::Field`] hops one level; [`Segment::AnyDepth`]
//! crosses containers restricted to its descend set — your
//! transcription of "these fields are messages".
//! [`Action::Delete`] removes the target; [`Action::Replace`]
//! re-emits its payload from a [`Value`] of wire words (typed
//! semantics are your `crate::scalar` composition, as on the
//! read side); [`Action::Normalize`] re-emits the target's own
//! words at minimal width — choose `Replace` to change what a
//! record says, `Normalize` to keep what it says and erase how
//! its producer padded it (untouched records keep their padding:
//! fidelity and normalization are both on offer, per record);
//! [`Action::Insert`] authors a new record into a gap the path
//! anchors (the Insertion section below is its contract), and is
//! admitted through [`InsertRuleSet::over`] alone.
//!
//! # Insertion
//!
//! [`Action::Insert`] authors one record into a gap its rule's
//! path anchors: the [`InsertRule`] behind the reference names the
//! [`Gap`] side, the inserted field, and its [`Value`] — the tag
//! and framing are crate-authored minimal, exactly as replacement
//! payloads emit (no pre-encoded-record payload exists, and group
//! records are not spellable: no `Value` variant frames one).
//! Insert rules ride [`InsertRuleSet`]; the insert-free
//! [`RuleSet`] refuses them at authoring.
//!
//! - **Gap kinds.** `HeadOf`/`TailOf` designate the interior
//!   head/tail of each *container* occurrence the anchor selects;
//!   the empty anchor path is lawful for insert rules alone and
//!   designates the root interior (exactly one occurrence — the
//!   0→1 door). They commit their terminal: a scalar occurrence
//!   faults `KindMismatch`, a LEN occurrence is a committed
//!   descent whose interior wire faults are real (grouped group
//!   anchors are containers by syntax).
//! - **Multiplicity.** A gap rule fires once per anchor
//!   occurrence; zero occurrences emit nothing and fault nothing —
//!   [`InsertStats::inserted`] is the operator's signal.
//! - **Ownership.** A gap belongs to its anchor's own interior,
//!   and it emits iff that interior is walked and emitted.
//!   Consequences: interior inserts die silently with a deleted,
//!   replaced, or LEN-normalized owner (the zero count shows it);
//!   and the one dialect asymmetry — a grouped group-`Normalize`
//!   keeps its interior with the walk, so interior inserts
//!   *compose* with it, while a LEN-`Normalize` rides its interior
//!   verbatim and suppresses them.
//! - **Order.** Emissions follow walk-event order, rule index
//!   within one event: `HeadOf` at descent commit (after the
//!   container's head emission), `TailOf` at interior exhaustion,
//!   before any end tag. Head and tail of an empty container are
//!   coincident in bytes yet distinct events, and never tie.
//! - **Conflicts.** Insert rules are exempt from the
//!   duplicate-path judgment and never conflict — not with each
//!   other (same-gap inserts all emit, ordered; identical rules
//!   are lawful and emit twice) and not with action rules (the
//!   ownership law governs). Two *action* rules on one record
//!   remain the existing `Conflict` fault.
//! - **Inertness.** Inserted records are output-only: never
//!   matched, never walked, never depth-charged; a `Value::Len`
//!   interior is the caller's declaration, as for `Replace`.
//! - **Cost.** Insertion is a type-level capability. The
//!   insert-free [`RuleSet`] instantiates a matcher with no gap
//!   store at all, so its jobs carry no gap table, no pending-gap
//!   state, and no gap test in the record fold or at container
//!   events — those paths exist only in [`InsertRuleSet`]'s
//!   instantiation. There, insert anchors compile into their own
//!   per-layer table (the record fold's target table is
//!   untouched), and every gap scan sits behind a per-walk
//!   any-insert flag: the record fold consults it for the
//!   commitment check, container events consult it for the gap
//!   sides, and the per-hit work is the layer's own gap entries.
//! - **Growth.** Insert bytes enter the measuring ledger at the
//!   gap event (the Replace-growth accounting): interior
//!   overgrowth faults `Growth`, root overgrowth faults `Output`,
//!   as today.
//! - **Record-adjacent gaps are absent.** Inserting before or
//!   after a *record* (rather than at a container's head or tail)
//!   would require the record fold itself to classify every hit by
//!   rule kind — a cost every rule set pays, insertions or not.
//!   The container-gap vocabulary needs none of that: gaps fire at
//!   container events, and the record fold is untouched.
//!
//! Both dialects ship the same faces. Elsewhere: reading what a
//! path program designates, without writing → `select` (same path
//! language, same stratum); editing records you pick by handle,
//! not by pattern → `patch` or `session`; equal-length rewriting
//! of a stream → `transcode` (each behind its feature).
//!
//! # Examples
//!
//! ```
//! # #[cfg(feature = "rewrite-groupless")] {
//! use protobuf_edit::path::Segment;
//! use protobuf_edit::rewrite::groupless::rewrite;
//! use protobuf_edit::rewrite::{Action, Rule, RuleSet};
//! use protobuf_edit::{DepthLimit, FieldNumber};
//!
//! // Delete every top-level field 1 record.
//! let field1 = FieldNumber::new(1).unwrap();
//! let rules = [Rule { path: &[Segment::Field(field1)], action: Action::Delete }];
//! let set = RuleSet::over(&rules).unwrap();
//!
//! // varint f1=150 · varint f2=42
//! let msg = [0x08, 0x96, 0x01, 0x10, 0x2A];
//! let (out, stats) = rewrite(&msg, &set, DepthLimit::REFERENCE).unwrap();
//! assert_eq!(out, [0x10, 0x2A]);
//! assert_eq!(stats.deleted(), 1);
//! # }
//! ```
//!
//! # Recipes
//!
//! One compiled set, a batch of documents, one output buffer:
//! [`RuleSet::over`] judges the rules once, and `rewrite_into`
//! reuses the buffer across jobs (untouched on `Err`, so a faulted
//! document skips without poisoning the loop):
//!
//! ```
//! # #[cfg(feature = "rewrite-groupless")] {
//! use protobuf_edit::path::Segment;
//! use protobuf_edit::rewrite::groupless::rewrite_into;
//! use protobuf_edit::rewrite::{Action, Rule, RuleSet};
//! use protobuf_edit::{DepthLimit, FieldNumber};
//!
//! let f1 = FieldNumber::new(1).unwrap();
//! let rules = [Rule { path: &[Segment::Field(f1)], action: Action::Delete }];
//! let set = RuleSet::over(&rules).unwrap();
//!
//! let batch: [&[u8]; 2] = [&[0x08, 0x02], &[0x08, 0x01, 0x10, 0x2A]];
//! let mut out = Vec::new();
//! for doc in batch {
//!     out.clear();
//!     let stats =
//!         rewrite_into(doc, &set, DepthLimit::REFERENCE, &mut out).unwrap();
//!     assert_eq!(stats.deleted(), 1);
//!     // ...ship `out`...
//! }
//! assert_eq!(out, [0x10, 0x2A]);
//! # }
//! ```

use alloc::vec::Vec;

use crate::DepthLimit;
use crate::admission::usize_of;
use crate::path::{self, Lane, Segment};
use crate::wire::{FieldNumber, PayloadLen};

/// What happens to a targeted record — or, for [`Insert`], at a
/// gap the rule's path anchors.
///
/// [`Insert`]: Self::Insert
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Action<'r> {
    /// The record vanishes (a targeted group vanishes whole, after
    /// its pairing is verified).
    Delete,
    /// The record's payload is replaced: tag bytes verbatim (field
    /// and kind unchanged), payload re-emitted canonically. The
    /// value's wire kind must equal the record's — a mismatch is
    /// the caller's schema error, faulted loudly.
    Replace(Value<'r>),
    /// The record re-emits at minimal width: tag, LEN length
    /// prefix, and varint value all minimal; fixed payloads have
    /// one width and a LEN payload's interior rides verbatim (the
    /// interior is the producer's declared domain — normalizing
    /// nested records is the path pattern's own job, `**/f`). A
    /// grouped target's two framing tags re-emit minimally around
    /// its interior, which stays subject to the walk and the other
    /// rules. Kind-free, so it never faults `KindMismatch` — the
    /// record itself supplies every word. The fidelity pole's
    /// opposite: `patch` and untouched records preserve padding,
    /// `Normalize` erases it.
    Normalize,
    /// One record is authored into a gap the rule's path anchors —
    /// the rule's `path` names the anchor, the [`InsertRule`]
    /// behind the reference names the gap side, the inserted
    /// field, and its value. The full contract (gap kinds, the
    /// ownership law, ordering, conflicts, inertness) lives in the
    /// module doc's Insertion section.
    Insert(&'r InsertRule<'r>),
}

/// Where an inserted record lands relative to its anchor — the
/// interior gaps of the containers the anchor path selects.
///
/// Record-adjacent gap kinds (before/after a record occurrence)
/// are a named residual: they would require the shared record
/// fold itself to classify every hit by rule kind — a per-record
/// cost on every job — where the container-gap vocabulary fires
/// at container events alone. They land behind that fold
/// surgery, if its cost story ever closes.
///
/// The crate's other gap-designation vocabularies are this job
/// refitted to other machines: the handle-driven editors'
/// `InsertAt` names one gap of one parsed sibling chain
/// (record-adjacent gaps included), and the splice transfer
/// overlay's `OnlineGap` names gaps whose ownership a streaming
/// walk already knows at the ask.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Gap {
    /// The interior head of each container occurrence the anchor
    /// path selects (first position inside — in the grouped
    /// dialect, after the open tag). The empty anchor path is
    /// lawful for insert rules alone and designates the root
    /// interior.
    HeadOf,
    /// The interior tail of each container occurrence (last
    /// position inside — in the grouped dialect, before the end
    /// tag). The empty anchor path designates the root interior.
    TailOf,
}

/// One insertion's data — the gap side, the inserted record's
/// field, and its value — held behind [`Action::Insert`]'s
/// reference so [`Rule`] keeps its 40-byte layout.
///
/// The tag and framing are crate-authored minimal from
/// `(field, value)`, exactly as replacement payloads emit; there
/// is no pre-encoded-record payload, so inserted words can never
/// break the module's output-acceptance theorem. Group-record
/// insertion is out of scope (no [`Value`] variant spells one);
/// a `Value::Len` interior is the caller's declaration, as for
/// `Replace`.
///
/// # Examples
///
/// ```
/// # #[cfg(feature = "rewrite-groupless")] {
/// use protobuf_edit::path::Segment;
/// use protobuf_edit::rewrite::groupless::rewrite;
/// use protobuf_edit::rewrite::{Action, Gap, InsertRule, InsertRuleSet, Rule, Value};
/// use protobuf_edit::{DepthLimit, FieldNumber};
///
/// // Append one record to the document (the empty anchor path is
/// // the root interior), and prepend one into every field-2
/// // container.
/// let f2 = FieldNumber::new(2).unwrap();
/// let f9 = FieldNumber::new(9).unwrap();
/// let tail = InsertRule { gap: Gap::TailOf, field: f9, value: Value::Len(b"hi") };
/// let head = InsertRule { gap: Gap::HeadOf, field: f9, value: Value::Varint(7) };
/// let rules = [
///     Rule { path: &[], action: Action::Insert(&tail) },
///     Rule { path: &[Segment::Field(f2)], action: Action::Insert(&head) },
/// ];
/// let set = InsertRuleSet::over(&rules).unwrap();
///
/// // varint f1=42 · LEN f2 [ varint f3=1 ]
/// let msg = [0x08, 0x2A, 0x12, 0x02, 0x18, 0x01];
/// let (out, stats) = rewrite(&msg, &set, DepthLimit::REFERENCE).unwrap();
/// assert_eq!(
///     out,
///     [0x08, 0x2A, 0x12, 0x04, 0x48, 0x07, 0x18, 0x01, 0x4A, 0x02, 0x68, 0x69]
/// );
/// assert_eq!(stats.inserted(), 2);
/// # }
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct InsertRule<'r> {
    /// Which side of the anchor the record lands on.
    pub gap: Gap,
    /// The inserted record's field number.
    pub field: FieldNumber,
    /// The inserted record's payload (the wire kind follows the
    /// value: `Varint`/`I32`/`I64` scalars, `Len`/`LenParts` LEN
    /// records).
    pub value: Value<'r>,
}

const _: () = {
    assert!(if cfg!(target_pointer_width = "64") {
        core::mem::size_of::<InsertRule<'_>>() == 32
    } else {
        // Narrower pointers only bound the layout.
        core::mem::size_of::<InsertRule<'_>>() <= 32
    });
};

/// A replacement payload, as wire words (typed semantics are the
/// caller's `crate::scalar` composition, mirroring the read
/// side).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Value<'r> {
    /// A varint record's new word.
    Varint(u64),
    /// An I32 record's new bits.
    I32(u32),
    /// An I64 record's new bits.
    I64(u64),
    /// A LEN record's new payload.
    Len(&'r [u8]),
    /// A LEN record's new payload as borrowed scatter: the pieces
    /// concatenate behind one minimal prefix, gathered by the emit
    /// walk with zero staging copies. Borrowed means re-readable —
    /// a rule hitting more than once re-emits the same pieces at
    /// every hit, exactly as [`Value::Len`] re-reads its slice.
    /// The concatenated length is judged against the LEN class at
    /// [`RuleSet::over`], like the whole-slice form.
    LenParts(&'r [&'r [u8]]),
}

impl Value<'_> {
    /// The payload's canonical wire size.
    fn size(self) -> u64 {
        match self {
            Self::Varint(word) => u64::from(crate::varint::encoded_len64(word)),
            Self::I32(_) => 4,
            Self::I64(_) => 8,
            Self::Len(bytes) => {
                // Lossless: `RuleSet::over` judged the length inside
                // the LEN class.
                #[allow(
                    clippy::as_conversions,
                    reason = "replacement length admitted to the LEN class"
                )]
                {
                    u64::from(crate::varint::encoded_len32(bytes.len() as u32)) + bytes.len() as u64
                }
            }
            Self::LenParts(parts) => {
                let total = parts_total(parts);
                // Lossless: `RuleSet::over` judged the concatenated
                // length inside the LEN class.
                #[allow(
                    clippy::as_conversions,
                    reason = "replacement length admitted to the LEN class"
                )]
                {
                    u64::from(crate::varint::encoded_len32(total as u32)) + total
                }
            }
        }
    }
}

/// True when a scatter payload's concatenated length leaves the
/// LEN class — [`RuleSet::over`]'s judgment.
const fn parts_oversize(parts: &[&[u8]]) -> bool {
    #[allow(clippy::as_conversions, reason = "the class cap widens losslessly to u64")]
    {
        parts_total(parts) > PayloadLen::MAX.as_inner() as u64
    }
}

/// The concatenated length of a scatter payload. Saturating: the
/// admission at [`RuleSet::over`] refuses anything past the LEN
/// class, so a saturated sum is already over every cap it will be
/// judged against.
const fn parts_total(parts: &[&[u8]]) -> u64 {
    let mut total: u64 = 0;
    let mut index = 0;
    while index < parts.len() {
        #[allow(clippy::as_conversions, reason = "slice lengths widen losslessly to u64")]
        {
            total = total.saturating_add(parts[index].len() as u64);
        }
        index += 1;
    }
    total
}

/// One rewriting rule: a root-anchored path and the action at its
/// target (the last segment selects records, the prefix selects
/// and commits containers).
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
    /// A rule's value payload — a `Value::Len` slice or a
    /// `Value::LenParts` concatenation, replaced or inserted —
    /// longer than the LEN class.
    OversizeValue {
        /// The offending rule's index.
        rule: u32,
    },
    /// An insert rule offered to the insert-free door
    /// ([`RuleSet::over`]) — inserts compile through
    /// [`InsertRuleSet::over`], whose matcher carries the gap
    /// machinery.
    InsertRefused {
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
                write!(f, "rule {rule}'s value payload exceeds the LEN class")
            }
            Self::InsertRefused { rule } => {
                write!(f, "rule {rule} is an insert rule, which the insert-free door refuses")
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

/// The shared authoring judgment behind both doors: the state
/// domain caps, the path shape laws, the value class, and the
/// duplicate scan. `inserts` selects the door — the insert-free
/// door refuses [`Action::Insert`] outright; the insert door
/// admits it, waives `EmptyPath` for it (the empty anchor path
/// designates the root interior), and exempts it from the
/// duplicate judgment.
const fn judge(rules: &[Rule<'_>], inserts: bool) -> Result<(), RuleError> {
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
        if !inserts && matches!(rule.action, Action::Insert(_)) {
            return Err(RuleError::InsertRefused { rule: at });
        }
        #[allow(clippy::as_conversions, reason = "u16::MAX widens losslessly for the cap check")]
        if rule.path.len() > u16::MAX as usize {
            return Err(RuleError::PathTooLong { rule: at });
        }
        if rule.path.is_empty() {
            // The empty anchor path is lawful exactly for insert
            // rules: it designates the root interior, which has
            // one occurrence and no record — nothing else can
            // select it.
            if !matches!(rule.action, Action::Insert(_)) {
                return Err(RuleError::EmptyPath { rule: at });
            }
        } else if let Err(breach) = path::judge_path(rule.path) {
            // The shared shape core judges the path laws; the
            // write-specific value law follows below.
            return Err(shape_error(breach, at));
        }
        let value = match rule.action {
            Action::Replace(value) => Some(value),
            Action::Insert(insert) => Some(insert.value),
            Action::Delete | Action::Normalize => None,
        };
        match value {
            Some(Value::Len(bytes)) if bytes.len() > usize_of(PayloadLen::MAX.as_inner()) => {
                return Err(RuleError::OversizeValue { rule: at });
            }
            Some(Value::LenParts(parts)) if parts_oversize(parts) => {
                return Err(RuleError::OversizeValue { rule: at });
            }
            _ => {}
        }
        index += 1;
    }
    // The direct quadratic duplicate scan reports the smallest
    // (first, second) pair: outer index ascends, inner index
    // ascends past it. Admission-time cost, never per job — and
    // const-capable, so a static rule set pays it at compile
    // time. Insert rules are exempt on both sides: two actions on
    // one record are indeterminate, but same-gap inserts all emit
    // (in rule order — repeated fields are the use case) and an
    // insert beside an action is governed by the ownership law,
    // never a conflict.
    let mut first = 0;
    while first < rules.len() {
        if matches!(rules[first].action, Action::Insert(_)) {
            first += 1;
            continue;
        }
        let mut second = first + 1;
        while second < rules.len() {
            if !matches!(rules[second].action, Action::Insert(_))
                && path::paths_equal(rules[first].path, rules[second].path)
            {
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

/// A compiled insert-free rule set: authoring judged once, jobs
/// downstream are judgment-free.
///
/// This is the thin door: [`over`](Self::over) refuses
/// [`Action::Insert`], so the set's matcher instantiates no gap
/// storage and its jobs execute none of the insertion machinery —
/// the receipt is [`Stats`], which carries no inserted count.
/// Insert-bearing rule sets compile through [`InsertRuleSet`].
#[must_use]
#[derive(Clone, Copy, Debug)]
pub struct RuleSet<'r> {
    rules: &'r [Rule<'r>],
}

impl<'r> RuleSet<'r> {
    /// Judges the rules' static shape (paths, descend sets,
    /// duplicates, replacement sizes) — and, at this insert-free
    /// door, refuses insert rules.
    ///
    /// # Errors
    ///
    /// [`RuleError::InsertRefused`] for an [`Action::Insert`] rule
    /// (compile those through [`InsertRuleSet::over`]);
    /// [`RuleError::TooManyRules`] and [`RuleError::PathTooLong`]
    /// when either axis leaves the matcher's state domain;
    /// [`RuleError::EmptyPath`], [`RuleError::WildcardTarget`], and
    /// [`RuleError::EmptyDescendSet`] for degenerate paths;
    /// [`RuleError::UnsortedDescend`] for a descend set spelled
    /// out of its canonical strictly-ascending order (repeats
    /// included); [`RuleError::AdjacentWildcards`] for two
    /// wildcards in a row over comparable descend sets — equal, or
    /// one containing the other — a redundant spelling of the
    /// wider one; [`RuleError::OversizeValue`] for a replaced
    /// value payload outside the LEN class;
    /// [`RuleError::DuplicatePath`] when two rules would target
    /// every hit twice.
    ///
    /// # Examples
    ///
    /// ```
    /// use protobuf_edit::FieldNumber;
    /// use protobuf_edit::path::Segment;
    /// use protobuf_edit::rewrite::{Action, Rule, RuleError, RuleSet};
    ///
    /// // Two rules sharing one path would double-target every hit.
    /// let field = FieldNumber::new(7).unwrap();
    /// let twice = [
    ///     Rule { path: &[Segment::Field(field)], action: Action::Delete },
    ///     Rule { path: &[Segment::Field(field)], action: Action::Delete },
    /// ];
    /// assert_eq!(
    ///     RuleSet::over(&twice).err(),
    ///     Some(RuleError::DuplicatePath { first: 0, second: 1 })
    /// );
    /// ```
    #[inline]
    pub const fn over(rules: &'r [Rule<'r>]) -> Result<Self, RuleError> {
        if let Err(refusal) = judge(rules, false) {
            return Err(refusal);
        }
        Ok(Self { rules })
    }
}

impl<'r> path::Paths<'r> for RuleSet<'r> {
    // Insert-free by admission: the unit gap store keeps this
    // matcher as free of gap machinery as every Program-backed
    // one, and the default unlaned form folds the lane fetch away.
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

/// A compiled rule set admitting [`Action::Insert`] beside the
/// action rules — the gap-machinery door.
///
/// [`over`](Self::over) runs [`RuleSet::over`]'s judgments with
/// the insert laws on top: the empty anchor path is lawful for
/// insert rules (it designates the root interior), and inserts
/// are exempt from the duplicate-path judgment. The matcher
/// behind this set carries the per-layer gap table, its walks run
/// the gap gates, and its receipt is [`InsertStats`] — the form
/// that carries the inserted count. Insert-free rule sets belong
/// in [`RuleSet`], whose jobs pay none of that.
#[must_use]
#[derive(Clone, Copy, Debug)]
pub struct InsertRuleSet<'r> {
    rules: &'r [Rule<'r>],
}

impl<'r> InsertRuleSet<'r> {
    /// Judges the rules' static shape, insert rules admitted.
    ///
    /// # Errors
    ///
    /// As [`RuleSet::over`], with the insert laws in place of the
    /// insert refusal: [`RuleError::DuplicatePath`] judges *action*
    /// rules only (insert rules are exempt — same-gap inserts all
    /// emit, in rule order, and an insert never conflicts with an
    /// action: the module doc's ownership law governs their
    /// composition), and [`RuleError::EmptyPath`] is waived
    /// exactly for `Insert` rules — the empty anchor path
    /// designates the root interior.
    ///
    /// # Examples
    ///
    /// ```
    /// use protobuf_edit::FieldNumber;
    /// use protobuf_edit::path::Segment;
    /// use protobuf_edit::rewrite::{Action, Gap, InsertRule, InsertRuleSet, Rule, Value};
    ///
    /// // The root-interior anchor and a same-path action compose.
    /// let f9 = FieldNumber::new(9).unwrap();
    /// let tail = InsertRule { gap: Gap::TailOf, field: f9, value: Value::Varint(7) };
    /// let rules = [
    ///     Rule { path: &[], action: Action::Insert(&tail) },
    ///     Rule { path: &[Segment::Field(f9)], action: Action::Delete },
    /// ];
    /// assert!(InsertRuleSet::over(&rules).is_ok());
    /// ```
    #[inline]
    pub const fn over(rules: &'r [Rule<'r>]) -> Result<Self, RuleError> {
        if let Err(refusal) = judge(rules, true) {
            return Err(refusal);
        }
        Ok(Self { rules })
    }
}

impl<'r> path::Paths<'r> for InsertRuleSet<'r> {
    // This door carries insert rules, so its matcher instantiation
    // folds the lane fetch in and stores gap terminals for real;
    // the insert-free door and the Program-backed machines keep
    // the defaults and pay nothing.
    const LANED: bool = true;

    type Gaps = path::GapTable;

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

    #[inline]
    fn lane(&self, id: u16) -> Lane {
        debug_assert!(usize::from(id) < self.rules.len(), "ids are minted below count()");
        // SAFETY: the matcher mints every id below `count()` (the
        // trait contract), and `count()` is this slice's length.
        match unsafe { self.rules.get_unchecked(usize::from(id)) }.action {
            Action::Insert(insert) => match insert.gap {
                Gap::HeadOf => Lane::Head,
                Gap::TailOf => Lane::Tail,
            },
            Action::Delete | Action::Replace(_) | Action::Normalize => Lane::Target,
        }
    }
}

mod sealed {
    /// The compiled-set axis is closed: the two doors are its
    /// whole domain.
    pub trait Sealed {}
    impl Sealed for super::RuleSet<'_> {}
    impl Sealed for super::InsertRuleSet<'_> {}
}

/// The per-layer tail-gap payload, keyed by door: walk layers
/// store [`Sets::Tails`], so the insert-free door stores no flag
/// at all and its exit test folds to a constant.
pub(crate) trait TailFlag: Copy {
    /// Packs the pending answer at descent.
    fn set(pending: bool) -> Self;
    /// The pending answer at the layer's exhaustion.
    fn pending(self) -> bool;
}

impl TailFlag for () {
    #[inline]
    fn set(_pending: bool) -> Self {}

    #[inline]
    fn pending(self) -> bool {
        false
    }
}

impl TailFlag for bool {
    #[inline]
    fn set(pending: bool) -> Self {
        pending
    }

    #[inline]
    fn pending(self) -> bool {
        self
    }
}

/// The compiled-set axis the job faces are generic over:
/// [`RuleSet`] (insert-free — thin matcher, [`Stats`] receipt) or
/// [`InsertRuleSet`] (gap machinery, [`InsertStats`] receipt).
///
/// Sealed: the two doors are the whole domain, and every job face
/// monomorphizes per door — no union type exists, so neither form
/// ever pays the other's machinery at runtime.
#[allow(
    private_bounds,
    reason = "sealing: the path-machinery supertrait is crate-internal by design, and hiding it \
              is exactly what keeps the axis closed"
)]
pub trait Sets<'r>: sealed::Sealed + path::Paths<'r> + Copy {
    /// The job receipt this door yields.
    type Stats: Copy + PartialEq + core::fmt::Debug;

    /// The tail-pending payload a walk layer stores for this
    /// door: the unit form (no byte, folded exit test) for the
    /// insert-free door, the pending flag for the insert door.
    #[doc(hidden)]
    type Tails: TailFlag;

    /// The admitted rule slice this door compiled from — the one
    /// slice its path faces read, so every id the matcher mints
    /// indexes it. Safe: it only hands the slice back; the walks
    /// do their quoted-rule indexing crate-side.
    #[doc(hidden)]
    fn rules(&self) -> &'r [Rule<'r>];

    /// Feeds every root-gap insert rule of `gap`'s kind to `fire`,
    /// in authoring order. Empty-anchor rules never enter the
    /// matcher's NFA — no segment exists to compile — so the walks
    /// fire them at the root interior's own events (start for
    /// [`Gap::HeadOf`], exhaustion for [`Gap::TailOf`]). A no-op
    /// for the insert-free door, which admits no insert rule.
    #[doc(hidden)]
    fn root_inserts(&self, gap: Gap, fire: impl FnMut(&'r InsertRule<'r>));

    /// Projects the walk's full tally onto this door's receipt.
    #[doc(hidden)]
    fn receipt(full: InsertStats) -> Self::Stats;
}

impl<'r> Sets<'r> for RuleSet<'r> {
    type Stats = Stats;

    // The unit tail payload keeps the walk's layer stack flag-free.
    type Tails = ();

    #[inline]
    fn rules(&self) -> &'r [Rule<'r>] {
        self.rules
    }

    #[inline]
    fn root_inserts(&self, _gap: Gap, _fire: impl FnMut(&'r InsertRule<'r>)) {}

    #[inline]
    fn receipt(full: InsertStats) -> Stats {
        debug_assert!(full.inserted == 0, "insert-free walks fire no gaps");
        Stats {
            deleted: full.deleted,
            replaced: full.replaced,
            normalized: full.normalized,
            descended: full.descended,
        }
    }
}

impl<'r> Sets<'r> for InsertRuleSet<'r> {
    type Stats = InsertStats;

    // TailOf rules fire at layer exhaustion: the walk stores the
    // pending flag per layer for this door alone.
    type Tails = bool;

    #[inline]
    fn rules(&self) -> &'r [Rule<'r>] {
        self.rules
    }

    fn root_inserts(&self, gap: Gap, mut fire: impl FnMut(&'r InsertRule<'r>)) {
        for rule in self.rules {
            if rule.path.is_empty()
                && let Action::Insert(insert) = rule.action
                && insert.gap == gap
            {
                fire(insert);
            }
        }
    }

    #[inline]
    fn receipt(full: InsertStats) -> InsertStats {
        full
    }
}

/// The action of a rule the matcher quoted. Private to the walks:
/// its ids come from the matcher alone, so the public trait keeps
/// no index-taking face.
#[inline]
fn action<'r, R: Sets<'r>>(set: &R, rule: u16) -> Action<'r> {
    let rules = set.rules();
    debug_assert!(usize::from(rule) < rules.len(), "hits quote admitted rules");
    // SAFETY: every quoted rule id is minted by the matcher's
    // flatten from states enumerated over this same admitted
    // slice — `rules()` and the path faces the matcher compiles
    // from all read the one slice field — so it is below
    // `rules.len()`.
    unsafe { rules.get_unchecked(usize::from(rule)) }.action
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

/// The insert-free job receipt: what each action class touched.
///
/// The exposure face for silently-inapplicable rules (a scalar
/// where the route expected a container, a kind the pattern never
/// meets) — zero counts are the operator's signal. No inserted
/// count exists here: the insert-free door cannot insert, so its
/// receipt does not carry the word — [`InsertStats`] is the
/// insert door's receipt.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct Stats {
    deleted: u32,
    replaced: u32,
    normalized: u32,
    descended: u32,
}

impl Stats {
    /// Records deleted (a deleted group counts once).
    #[inline]
    #[must_use]
    pub const fn deleted(self) -> u32 {
        self.deleted
    }

    /// Records replaced.
    #[inline]
    #[must_use]
    pub const fn replaced(self) -> u32 {
        self.replaced
    }

    /// Records re-emitted at minimal width (a normalized group
    /// counts once).
    #[inline]
    #[must_use]
    pub const fn normalized(self) -> u32 {
        self.normalized
    }

    /// LEN payloads descended into (committed as messages).
    #[inline]
    #[must_use]
    pub const fn descended(self) -> u32 {
        self.descended
    }
}

/// The insert door's job receipt: [`Stats`]'s counts plus the
/// inserted tally.
///
/// Doubles as the walks' internal tally — the insert-free faces
/// project it onto [`Stats`] at the seam, so their public receipt
/// never carries the inserted word.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct InsertStats {
    deleted: u32,
    replaced: u32,
    normalized: u32,
    inserted: u32,
    descended: u32,
}

impl InsertStats {
    /// Records deleted (a deleted group counts once).
    #[inline]
    #[must_use]
    pub const fn deleted(self) -> u32 {
        self.deleted
    }

    /// Records replaced.
    #[inline]
    #[must_use]
    pub const fn replaced(self) -> u32 {
        self.replaced
    }

    /// Records re-emitted at minimal width (a normalized group
    /// counts once).
    #[inline]
    #[must_use]
    pub const fn normalized(self) -> u32 {
        self.normalized
    }

    /// Records inserted — one per firing gap occurrence, so an
    /// anchor with N occurrences counts N per insert rule. Zero is
    /// the silently-inapplicable signal (the anchor never
    /// occurred, or its owning interior was never emitted — the
    /// ownership law's suppressions land here, deliberately
    /// visible).
    #[inline]
    #[must_use]
    pub const fn inserted(self) -> u32 {
        self.inserted
    }

    /// LEN payloads descended into (committed as messages).
    #[inline]
    #[must_use]
    pub const fn descended(self) -> u32 {
        self.descended
    }
}

// ─── the slot table (private contract type) ───

/// Pre-order slots, one per descended LEN (uniform). Bit 31 is the
/// dirty bit: a dirty slot's low 31 bits carry the new interior
/// length (≤ 2^31 − 1; the Growth judgment upstream of the fill
/// proves it); a clean slot's low 31 bits carry its descendant
/// slot count (strictly under 2^30 — see `fill`), letting pass two
/// skip the whole subtree and memcpy the record. The bit
/// discipline lives behind these three methods; raw masks never
/// leak.
struct SlotTable {
    slots: Vec<u32>,
}

const DIRTY: u32 = 1 << 31;

impl SlotTable {
    const fn new() -> Self {
        Self { slots: Vec::new() }
    }

    /// Pass one: claims the next pre-order slot, returning its
    /// index for the fill at descent exit.
    fn claim(&mut self) -> usize {
        self.slots.push(0);
        self.slots.len() - 1
    }

    /// Pass one: fills a claimed slot. `payload` is 31-bit by
    /// class either way. A dirty payload is in the LEN class
    /// (≤ 2^31 − 1; the caller judged Growth first). A clean
    /// payload is a descendant count, and every descendant is a
    /// descended LEN costing at least two source bytes (its tag
    /// and its length prefix) out of an input under 2^31 bytes —
    /// so counts stay strictly under 2^30, clear of the flag bit
    /// with a bit to spare.
    fn fill(&mut self, slot: usize, dirty: bool, payload: u32) {
        debug_assert!(payload & DIRTY == 0, "slot payloads are 31-bit by class");
        debug_assert!(slot < self.slots.len(), "fills follow claims");
        // SAFETY: `slot` was minted by `claim` as `len - 1`, and the
        // table only ever grows — every claimed index stays in
        // bounds.
        *unsafe { self.slots.get_unchecked_mut(slot) } =
            if dirty { payload | DIRTY } else { payload };
    }

    /// The number of slots claimed so far.
    const fn claimed(&self) -> usize {
        self.slots.len()
    }

    /// Pass two: consumes the slot at the cursor.
    fn read(&self, cursor: usize) -> SlotValue {
        debug_assert!(cursor < self.slots.len(), "the cursor replays pass one's claims");
        // SAFETY: the cursor stays inside the claimed prefix by
        // induction. It starts at 0; a dirty slot advances it by
        // one, a clean slot by one plus its descendant count — and
        // that count is exactly how many slots pass one claimed
        // inside the subtree (filled by the same walk), so every
        // step lands on a claimed index or on `claimed()` itself,
        // where the walk has ended. The replay premise is typed:
        // the emit walk's input, rules, and limit come from the
        // `Plan` that sealed this table, and no callback runs
        // between the passes, so pass two re-makes pass one's
        // dirty/clean decisions verbatim. (`Emit::finish`
        // additionally witnesses full consumption after the fact;
        // the bound does not rest on it.)
        let raw = *unsafe { self.slots.get_unchecked(cursor) };
        if raw & DIRTY != 0 {
            SlotValue::Dirty { new_len: raw & !DIRTY }
        } else {
            SlotValue::Clean { descendants: raw }
        }
    }
}

/// A consumed slot's meaning.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum SlotValue {
    /// The subtree changed: emit the new interior length and walk
    /// in.
    Dirty {
        /// The payload's new length.
        new_len: u32,
    },
    /// The subtree is byte-identical: memcpy the whole record and
    /// skip its descendant slots.
    Clean {
        /// How many slots the subtree claimed.
        descendants: u32,
    },
}

// ─── the measured plan (private contract type) ───

/// The measuring pass's sealed verdict and the replay identity
/// that produced it: the exact input, rules, and depth limit whose
/// walk claimed the slot ledger, the measured output size (judged
/// into the LEN class at construction), and the walk's judgment
/// tallies. A `Plan` in hand is the emit pass's whole admission —
/// the emit walk draws input, rules, and limit from the plan
/// itself, so the replay the slot reads rely on cannot be driven
/// with mismatched arguments: the mismatch is unspellable, not
/// asserted.
struct Plan<'i, R> {
    input: &'i [u8],
    rules: R,
    limit: DepthLimit,
    /// The measuring walk's tallies (the emit walk repeats them).
    stats: InsertStats,
    slots: SlotTable,
    /// The measured output size, in class.
    total: u32,
}

impl<'i, R> Plan<'i, R> {
    /// Seals the measurement; `None` when the rewritten root
    /// outgrows the LEN class.
    fn new(
        input: &'i [u8],
        rules: R,
        limit: DepthLimit,
        stats: InsertStats,
        slots: SlotTable,
        total: u64,
    ) -> Option<Self> {
        if total > u64::from(PayloadLen::MAX.as_inner()) {
            return None;
        }
        // In class: judged above.
        #[allow(clippy::as_conversions, reason = "class-judged total narrows losslessly")]
        Some(Self { input, rules, limit, stats, slots, total: total as u32 })
    }
}

// The source-transfer stratum: the third compiled plan type and
// its vocabulary, emitted only under the transfer capability.
#[cfg(any(feature = "transfer-rewrite-grouped", feature = "transfer-rewrite-groupless"))]
pub mod transfer;

#[cfg(any(feature = "transfer-rewrite-grouped", feature = "transfer-rewrite-groupless"))]
pub use transfer::{
    Claim, CopyPairing, PathBreach, PathRole, PayloadCopyRule, PayloadCopyTarget, PayloadMoveRule,
    RecordTransfer, RecordTransferRule, TransferBreach, TransferRuleError, TransferRuleSet,
    TransferStats, TransferTable,
};

#[cfg(feature = "rewrite-grouped")]
pub mod grouped;
#[cfg(feature = "rewrite-groupless")]
pub mod groupless;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::FieldNumber;

    fn f(n: u32) -> FieldNumber {
        FieldNumber::new(n).unwrap()
    }

    // The giant class-top fixture follows the streaming twin's law: a
    // 32-bit wasm heap cannot host it, and under Miri it is byte-bulk
    // without provenance value. The judgment itself is
    // target-independent.
    #[cfg(all(not(target_family = "wasm"), not(miri)))]
    #[test]
    fn a_scatter_replacement_is_judged_by_its_concatenated_length() {
        // Two parts summing to one byte over the LEN class: refused
        // where a single oversize slice would be, at authoring.
        let big = alloc::vec![0u8; usize::try_from(PayloadLen::MAX.as_inner()).unwrap()];
        let parts: [&[u8]; 2] = [&big, &[0u8][..]];
        assert_eq!(
            RuleSet::over(&[Rule {
                path: &[Segment::Field(f(1))],
                action: Action::Replace(Value::LenParts(&parts)),
            }])
            .err(),
            Some(RuleError::OversizeValue { rule: 0 })
        );
        // Exactly at the class top: admitted.
        let parts: [&[u8]; 1] = [&big];
        assert!(
            RuleSet::over(&[Rule {
                path: &[Segment::Field(f(1))],
                action: Action::Replace(Value::LenParts(&parts)),
            }])
            .is_ok()
        );
    }

    #[test]
    fn state_domain_admission_caps_rules_and_path_lengths() {
        // One over the (u16, u16) matcher state domain on each axis.
        let long_path = alloc::vec![Segment::Field(f(1)); (u16::MAX as usize) + 1];
        assert_eq!(
            RuleSet::over(&[Rule { path: &long_path, action: Action::Delete }]).err(),
            Some(RuleError::PathTooLong { rule: 0 })
        );
        let many = alloc::vec![Rule { path: &long_path[..1], action: Action::Delete };
            (u16::MAX as usize) + 1];
        assert_eq!(
            RuleSet::over(&many).err(),
            Some(RuleError::TooManyRules { count: (u16::MAX as usize) + 1 })
        );
    }

    #[test]
    fn authoring_errors_are_judged_at_construction() {
        assert_eq!(
            RuleSet::over(&[Rule { path: &[], action: Action::Delete }]).err(),
            Some(RuleError::EmptyPath { rule: 0 })
        );
        assert_eq!(
            RuleSet::over(&[Rule {
                path: &[Segment::AnyDepth { descend: &[] }],
                action: Action::Delete
            }])
            .err(),
            Some(RuleError::WildcardTarget { rule: 0 })
        );
        let one = f(1);
        assert_eq!(
            RuleSet::over(&[Rule {
                path: &[Segment::AnyDepth { descend: &[] }, Segment::Field(one)],
                action: Action::Delete
            }])
            .err(),
            Some(RuleError::EmptyDescendSet { rule: 0, segment: 0 })
        );
        // The descend set has one canonical spelling: strictly
        // ascending. A permutation and a repeat are both refused at
        // authoring, so set-equal paths cannot dodge the duplicate
        // judgment below by respelling.
        let (two, seven) = (f(2), f(7));
        assert_eq!(
            RuleSet::over(&[Rule {
                path: &[Segment::AnyDepth { descend: &[two, one] }, Segment::Field(seven)],
                action: Action::Delete
            }])
            .err(),
            Some(RuleError::UnsortedDescend { rule: 0, segment: 0 })
        );
        assert_eq!(
            RuleSet::over(&[Rule {
                path: &[Segment::AnyDepth { descend: &[one, one] }, Segment::Field(seven)],
                action: Action::Delete
            }])
            .err(),
            Some(RuleError::UnsortedDescend { rule: 0, segment: 0 })
        );
        // Two adjacent wildcards over comparable sets are one
        // wildcard respelled: refused at authoring, so the pair
        // cannot dodge the duplicate judgment below by respelling.
        assert_eq!(
            RuleSet::over(&[Rule {
                path: &[
                    Segment::AnyDepth { descend: &[one, two] },
                    Segment::AnyDepth { descend: &[one, two] },
                    Segment::Field(seven)
                ],
                action: Action::Delete
            }])
            .err(),
            Some(RuleError::AdjacentWildcards { rule: 0, segment: 1 })
        );
        // A subset pair is the same tautology (B ⊆ A folds into
        // A*): refused like the equal pair.
        assert_eq!(
            RuleSet::over(&[Rule {
                path: &[
                    Segment::AnyDepth { descend: &[one] },
                    Segment::AnyDepth { descend: &[one, two] },
                    Segment::Field(seven)
                ],
                action: Action::Delete
            }])
            .err(),
            Some(RuleError::AdjacentWildcards { rule: 0, segment: 1 })
        );
        // Incomparable sets compose for real and stay admitted.
        assert!(
            RuleSet::over(&[Rule {
                path: &[
                    Segment::AnyDepth { descend: &[one] },
                    Segment::AnyDepth { descend: &[two] },
                    Segment::Field(seven)
                ],
                action: Action::Delete
            }])
            .is_ok()
        );
        // Canonical spellings admit — and being canonical, two
        // set-equal wildcard paths are slice-equal and land in the
        // duplicate judgment.
        let wild_dup = [
            Rule {
                path: &[Segment::AnyDepth { descend: &[one, two] }, Segment::Field(seven)],
                action: Action::Delete,
            },
            Rule {
                path: &[Segment::AnyDepth { descend: &[one, two] }, Segment::Field(seven)],
                action: Action::Delete,
            },
        ];
        assert_eq!(
            RuleSet::over(&wild_dup).err(),
            Some(RuleError::DuplicatePath { first: 0, second: 1 })
        );
        let dup = [
            Rule { path: &[Segment::Field(one)], action: Action::Delete },
            Rule { path: &[Segment::Field(one)], action: Action::Delete },
        ];
        assert_eq!(
            RuleSet::over(&dup).err(),
            Some(RuleError::DuplicatePath { first: 0, second: 1 })
        );
    }

    #[test]
    fn normalize_rules_carry_no_replacement_judgment() {
        // Normalize has no value payload, so the replacement-size
        // judgment (`OversizeValue`) has nothing to apply to;
        // the path shape laws still hold.
        let rules = [Rule { path: &[Segment::Field(f(1))], action: Action::Normalize }];
        assert!(RuleSet::over(&rules).is_ok());
        let dup = [
            Rule { path: &[Segment::Field(f(1))], action: Action::Normalize },
            Rule { path: &[Segment::Field(f(1))], action: Action::Delete },
        ];
        assert_eq!(
            RuleSet::over(&dup).err(),
            Some(RuleError::DuplicatePath { first: 0, second: 1 })
        );
    }

    #[test]
    fn the_insert_free_door_refuses_insert_rules() {
        let tail = InsertRule { gap: Gap::TailOf, field: f(5), value: Value::Varint(1) };
        assert_eq!(
            RuleSet::over(&[
                Rule { path: &[Segment::Field(f(1))], action: Action::Delete },
                Rule { path: &[Segment::Field(f(2))], action: Action::Insert(&tail) },
            ])
            .err(),
            Some(RuleError::InsertRefused { rule: 1 })
        );
        // The insert door admits the same rules.
        assert!(
            InsertRuleSet::over(&[
                Rule { path: &[Segment::Field(f(1))], action: Action::Delete },
                Rule { path: &[Segment::Field(f(2))], action: Action::Insert(&tail) },
            ])
            .is_ok()
        );
    }

    #[test]
    fn the_insert_free_matcher_carries_no_gap_machinery() {
        // The type-level split's layout pin: the insert-free set
        // instantiates the unit gap store, so its matcher is
        // exactly one gap table lighter than the insert door's.
        use crate::path::{GapTable, Matcher};
        assert_eq!(
            core::mem::size_of::<Matcher<'_, RuleSet<'_>>>() + core::mem::size_of::<GapTable>(),
            core::mem::size_of::<Matcher<'_, InsertRuleSet<'_>>>()
        );
    }

    #[test]
    fn the_empty_anchor_path_is_lawful_for_insert_rules_alone() {
        let value = Value::Varint(1);
        let head = InsertRule { gap: Gap::HeadOf, field: f(5), value };
        let tail = InsertRule { gap: Gap::TailOf, field: f(5), value };
        assert!(
            InsertRuleSet::over(&[
                Rule { path: &[], action: Action::Insert(&head) },
                Rule { path: &[], action: Action::Insert(&tail) },
            ])
            .is_ok()
        );
        // Action rules keep the law untouched, at both doors.
        assert_eq!(
            InsertRuleSet::over(&[Rule { path: &[], action: Action::Delete }]).err(),
            Some(RuleError::EmptyPath { rule: 0 })
        );
        assert_eq!(
            RuleSet::over(&[Rule { path: &[], action: Action::Delete }]).err(),
            Some(RuleError::EmptyPath { rule: 0 })
        );
    }

    #[test]
    fn insert_rules_are_exempt_from_the_duplicate_path_judgment() {
        let one = [Segment::Field(f(7))];
        let a = InsertRule { gap: Gap::TailOf, field: f(5), value: Value::Varint(1) };
        let b = InsertRule { gap: Gap::TailOf, field: f(5), value: Value::Varint(2) };
        // Insert × insert on one path: lawful (same-gap inserts all
        // emit, in rule order — repeated fields are the use case);
        // identical rules included.
        assert!(
            InsertRuleSet::over(&[
                Rule { path: &one, action: Action::Insert(&a) },
                Rule { path: &one, action: Action::Insert(&b) },
                Rule { path: &one, action: Action::Insert(&a) },
            ])
            .is_ok()
        );
        // Insert × action on one path: lawful (the ownership law
        // governs their composition, not the conflict fault).
        assert!(
            InsertRuleSet::over(&[
                Rule { path: &one, action: Action::Insert(&a) },
                Rule { path: &one, action: Action::Delete },
            ])
            .is_ok()
        );
        // Action × action keeps today's law.
        assert_eq!(
            InsertRuleSet::over(&[
                Rule { path: &one, action: Action::Insert(&a) },
                Rule { path: &one, action: Action::Delete },
                Rule { path: &one, action: Action::Normalize },
            ])
            .err(),
            Some(RuleError::DuplicatePath { first: 1, second: 2 })
        );
    }

    // The giant class-top fixture follows the streaming twin's law: a
    // 32-bit wasm heap cannot host it, and under Miri it is byte-bulk
    // without provenance value. The judgment itself is
    // target-independent.
    #[cfg(all(not(target_family = "wasm"), not(miri)))]
    #[test]
    fn insert_values_face_the_len_class_judgment() {
        // One byte over the class, spelled as scatter — the class
        // top itself is the largest lawful allocation on 32-bit
        // targets, exactly as the replacement twin of this test
        // spells it.
        let big = alloc::vec![0u8; usize::try_from(PayloadLen::MAX.as_inner()).unwrap()];
        let parts: [&[u8]; 2] = [&big, &[0u8][..]];
        let scattered =
            InsertRule { gap: Gap::TailOf, field: f(5), value: Value::LenParts(&parts) };
        assert_eq!(
            InsertRuleSet::over(&[Rule {
                path: &[Segment::Field(f(1))],
                action: Action::Insert(&scattered),
            }])
            .err(),
            Some(RuleError::OversizeValue { rule: 0 })
        );
        // Exactly at the class top: admitted.
        let whole = InsertRule { gap: Gap::TailOf, field: f(5), value: Value::Len(&big) };
        assert!(
            InsertRuleSet::over(&[Rule {
                path: &[Segment::Field(f(1))],
                action: Action::Insert(&whole),
            }])
            .is_ok()
        );
    }

    #[test]
    fn duplicate_detection_reports_the_smallest_pair() {
        // 20 rules, two duplicated paths interleaved with fillers:
        // the direct scan must quote the lexicographically smallest
        // (first, second) pair — the verdict the retired sorted
        // scan pinned.
        let p1 = [Segment::Field(f(7))];
        let p2 = [Segment::Field(f(3))];
        let fillers: Vec<[Segment<'_>; 1]> = (100..116).map(|n| [Segment::Field(f(n))]).collect();
        let mut rules: Vec<Rule<'_>> =
            fillers.iter().map(|path| Rule { path, action: Action::Delete }).collect();
        rules.insert(2, Rule { path: &p1, action: Action::Delete });
        rules.insert(5, Rule { path: &p2, action: Action::Delete });
        rules.insert(9, Rule { path: &p1, action: Action::Delete });
        rules.push(Rule { path: &p2, action: Action::Delete });
        assert_eq!(
            RuleSet::over(&rules).err(),
            Some(RuleError::DuplicatePath { first: 2, second: 9 })
        );
    }
}
