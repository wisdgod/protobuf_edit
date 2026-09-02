//! Source-transfer plans for the batch rewriter: a third compiled
//! plan type whose jobs copy and move path-designated records and
//! payloads inside one document, beside the ordinary rule actions.
//!
//! A transfer designates occurrences of the job's own input — the
//! source paths select what moves, the anchor/target paths select
//! where it lands — and the emission is byte-exact: a copied or
//! moved record contributes exactly its source bytes (met tag
//! spelling, framing words at their met widths, the whole payload,
//! nested padding included); a payload transfer contributes exactly
//! the source LEN interior behind destination framing the job
//! authors minimally. Matching is over the original input only:
//! emitted transfers are output, never re-matched, and a source
//! designation always names the original bytes even where another
//! rule edits that record.
//!
//! Record and payload transfers are separate vocabularies because
//! their fidelity contracts differ: [`RecordTransferRule`] relocates
//! whole records verbatim into container gaps; [`PayloadCopyRule`]
//! and [`PayloadMoveRule`] detach a LEN interior and re-frame it at
//! the destination (a replaced target keeps its own tag; an
//! inserted or moved payload gets a crate-authored minimal tag and
//! prefix for the rule's field). A payload move suppresses the
//! entire source LEN record — removing only the interior would
//! leave a tag and prefix with no lawful meaning.
//!
//! Pairing is positional over walk order: [`CopyPairing::Zip`]
//! pairs the k-th source occurrence with the k-th destination
//! occurrence and requires equal counts;
//! [`CopyPairing::BroadcastOne`] requires exactly one source and
//! copies it to every destination. Moves have no broadcast
//! spelling, and one source occurrence feeds at most one move.
//! A wholly inapplicable rule (zero sources, zero destinations)
//! emits nothing and faults nothing — the [`TransferStats`] zero
//! count is the operator's signal, as for inserts.
//!
//! Ownership follows the host's law: a destination gap belongs to
//! its anchor's interior and emits iff that interior is walked and
//! emitted. A record owned by a delete/replace/normalize(LEN)
//! action, a moved record, and a replaced payload target keep
//! their interiors off the walk, so designations inside them never
//! fire. Each record occurrence admits at most one writer — an
//! action, a payload-replace target, or a move — and a second
//! claim is the [`TransferBreach::Contested`] refusal, judged
//! before any output byte exists. Copies are reads and never
//! contest.
//!
//! At one gap, ordinary inserts fire first (their landed order),
//! then record transfers, then payload copies, then payload moves,
//! each in rule-index order.
//!
//! Transfer jobs walk the document three times — designate (bind
//! source spans, count destinations, judge every transfer law),
//! measure, emit — where plain jobs walk twice; the plan between
//! the passes stores coordinates, never source bytes. The plain
//! [`RuleSet`](super::RuleSet) and [`InsertRuleSet`] doors keep
//! their two-pass engine and carry no transfer table, branch, or
//! state in any of their instantiations.

use alloc::vec::Vec;

use super::{Gap, InsertRuleSet, InsertStats, Rule, RuleError};
use crate::admission::Coord;
use crate::path::{self, Lane, Segment};
use crate::wire::FieldNumber;

/// How copy sources pair with their destination occurrences.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CopyPairing {
    /// The k-th source occurrence lands at the k-th destination
    /// occurrence, both in walk order; the counts must be equal.
    Zip,
    /// Exactly one source occurrence, copied to every destination
    /// occurrence (zero destinations emit nothing).
    BroadcastOne,
}

/// A whole-record transfer's motion: copy under a pairing, or a
/// zip-paired move (moves have no broadcast spelling — one source
/// occurrence cannot relocate to two places).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RecordTransfer {
    /// Sources stay put and their exact bytes also emit at the
    /// destinations.
    Copy(CopyPairing),
    /// The k-th source's exact bytes emit at the k-th destination
    /// and the source occurrence emits nowhere; its interior
    /// leaves the walk.
    MoveZip,
}

/// One whole-record transfer.
///
/// `source` selects the records whose exact bytes move; `anchor` +
/// `gap` select the destination container interiors (the empty
/// anchor path designates the root interior, as for insert rules).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RecordTransferRule<'r> {
    /// The records whose exact bytes transfer.
    pub source: &'r [Segment<'r>],
    /// The destination containers (empty = the root interior).
    pub anchor: &'r [Segment<'r>],
    /// Which interior side of each anchor occurrence receives.
    pub gap: Gap,
    /// Copy or move, with the pairing law.
    pub transfer: RecordTransfer,
}

/// A payload copy's destination: replace an existing LEN target's
/// interior, or author a new LEN record into a container gap.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PayloadCopyTarget<'r> {
    /// The target records' interiors are replaced: target tag
    /// verbatim, prefix re-authored minimally, interior byte-exact
    /// from the source. Targets must be LEN records.
    Replace {
        /// The LEN records whose payloads are replaced.
        target: &'r [Segment<'r>],
    },
    /// A new LEN record is authored into each anchor occurrence's
    /// gap: minimal tag for `field`, minimal prefix, interior
    /// byte-exact from the source.
    Insert {
        /// The destination containers (empty = the root interior).
        anchor: &'r [Segment<'r>],
        /// Which interior side of each anchor occurrence receives.
        gap: Gap,
        /// The authored record's field number.
        field: FieldNumber,
    },
}

/// One payload copy: `source` selects LEN records whose interiors
/// copy byte-exactly to the destination under the pairing law.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PayloadCopyRule<'r> {
    /// The LEN records whose interiors copy.
    pub source: &'r [Segment<'r>],
    /// Where the interiors land.
    pub target: PayloadCopyTarget<'r>,
    /// How sources pair with destinations.
    pub pairing: CopyPairing,
}

/// One payload move, zip-paired.
///
/// The k-th source LEN's interior is authored as a new record at
/// the k-th anchor occurrence's gap, and the entire source record
/// emits nowhere. Only the gap destination exists: replacing an
/// existing target while also suppressing the source would be a
/// compound command, not a relocation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PayloadMoveRule<'r> {
    /// The LEN records whose interiors move.
    pub source: &'r [Segment<'r>],
    /// The destination containers (empty = the root interior).
    pub anchor: &'r [Segment<'r>],
    /// Which interior side of each anchor occurrence receives.
    pub gap: Gap,
    /// The authored record's field number.
    pub field: FieldNumber,
}

// The authoring types are pure borrowed data, sized for static
// tables: 64-bit layouts pinned exactly, narrower pointer widths
// bounded by the same ceilings.
const _: () = {
    assert!(if cfg!(target_pointer_width = "64") {
        core::mem::size_of::<RecordTransferRule<'_>>() == 40
            && core::mem::size_of::<PayloadCopyRule<'_>>() == 48
            && core::mem::size_of::<PayloadMoveRule<'_>>() == 40
            && core::mem::size_of::<TransferRuleSet<'_>>() == 64
    } else {
        core::mem::size_of::<RecordTransferRule<'_>>() <= 40
            && core::mem::size_of::<PayloadCopyRule<'_>>() <= 48
            && core::mem::size_of::<PayloadMoveRule<'_>>() <= 40
            && core::mem::size_of::<TransferRuleSet<'_>>() <= 64
    });
};

/// Which transfer table an authoring or job refusal quotes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TransferTable {
    /// The whole-record transfer rules.
    Records,
    /// The payload copy rules.
    PayloadCopies,
    /// The payload move rules.
    PayloadMoves,
}

/// Which of a transfer rule's paths an authoring refusal quotes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PathRole {
    /// The rule's source path.
    Source,
    /// The rule's destination anchor path.
    Anchor,
    /// A payload copy's replace-target path.
    Target,
}

/// A path-shape breach inside a transfer rule, in segment
/// coordinates — the same laws the host's rule paths obey.
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PathBreach {
    /// No segments (lawful only for anchor paths, where it
    /// designates the root interior).
    Empty,
    /// The last segment is a wildcard: no selected field.
    WildcardTarget,
    /// A wildcard with an empty descend set is a degenerate ε.
    EmptyDescendSet {
        /// The offending segment's index.
        segment: u32,
    },
    /// A descend set spelled out of its canonical strictly
    /// ascending order.
    UnsortedDescend {
        /// The offending segment's index.
        segment: u32,
    },
    /// Two adjacent wildcards over comparable descend sets — a
    /// redundant spelling of the wider one.
    AdjacentWildcards {
        /// The second wildcard's segment index.
        segment: u32,
    },
}

impl core::fmt::Display for PathBreach {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::Empty => f.write_str("the path has no segments"),
            Self::WildcardTarget => f.write_str("the path ends on a wildcard"),
            Self::EmptyDescendSet { segment } => {
                write!(f, "segment {segment} is a wildcard with an empty descend set")
            }
            Self::UnsortedDescend { segment } => {
                write!(
                    f,
                    "segment {segment} spells its descend set out of order \
                     (the canonical spelling is strictly ascending)"
                )
            }
            Self::AdjacentWildcards { segment } => {
                write!(
                    f,
                    "segments {} and {segment} respell one wildcard",
                    segment.saturating_sub(1)
                )
            }
        }
    }
}

/// An authoring error, judged once at [`TransferRuleSet::over`].
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TransferRuleError {
    /// The ordinary rule table refused — the host's own authoring
    /// judgment, unchanged.
    Rules(RuleError),
    /// The transfer tables hold more paths than the matcher's
    /// state domain (65,535) admits, counted across all three.
    TooManyTransferPaths {
        /// The number of transfer paths offered.
        count: usize,
    },
    /// A transfer rule's path broke a shape law.
    Path {
        /// The offending rule's table.
        table: TransferTable,
        /// The offending rule's index in its table.
        rule: u32,
        /// Which of the rule's paths broke.
        role: PathRole,
        /// The broken law.
        breach: PathBreach,
    },
}

impl core::fmt::Display for TransferRuleError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::Rules(refusal) => write!(f, "{refusal}"),
            Self::TooManyTransferPaths { count } => {
                write!(f, "{count} transfer paths exceed the 65,535-path limit")
            }
            Self::Path { table, rule, role, breach } => {
                write!(f, "{table:?} rule {rule}'s {role:?} path: {breach}")
            }
        }
    }
}

impl core::error::Error for TransferRuleError {
    #[inline]
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Rules(refusal) => Some(refusal),
            Self::TooManyTransferPaths { .. } | Self::Path { .. } => None,
        }
    }
}

/// One writer claim on a record occurrence. Each occurrence admits
/// at most one writer; copies are reads and never claim.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Claim {
    /// An ordinary action rule targets the record.
    Action {
        /// The rule's index in the ordinary table.
        rule: u32,
    },
    /// A payload copy replaces the record's interior.
    ReplaceTarget {
        /// The rule's index in the payload-copy table.
        rule: u32,
    },
    /// A record transfer moves the record.
    RecordMove {
        /// The rule's index in the record-transfer table.
        rule: u32,
    },
    /// A payload move suppresses the record.
    PayloadMove {
        /// The rule's index in the payload-move table.
        rule: u32,
    },
}

/// A transfer-law refusal, judged in the designation pass — before
/// any output byte exists.
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TransferBreach {
    /// A payload rule's source occurrence is not a LEN record —
    /// only a LEN has a detachable interior.
    SourceKind {
        /// The rule's table.
        table: TransferTable,
        /// The rule's index in its table.
        rule: u32,
    },
    /// A payload copy's replace-target occurrence is not a LEN
    /// record.
    TargetKind {
        /// The rule's index in the payload-copy table.
        rule: u32,
    },
    /// A transfer anchor occurrence is a scalar record — anchors
    /// commit containerhood, exactly as insert anchors do.
    AnchorKind {
        /// The rule's table.
        table: TransferTable,
        /// The rule's index in its table.
        rule: u32,
    },
    /// A pairing equation failed: zip counts differ, or a
    /// broadcast rule's source count is not exactly one while
    /// destinations exist.
    Cardinality {
        /// The rule's table.
        table: TransferTable,
        /// The rule's index in its table.
        rule: u32,
        /// Source occurrences designated.
        sources: u32,
        /// Destination occurrences designated.
        destinations: u32,
    },
    /// Two writers claimed one record occurrence — two moves, a
    /// move beside an action, a replaced target beside its own
    /// deletion: the occurrence's fate would be indeterminate.
    Contested {
        /// The first claim, in population order.
        first: Claim,
        /// The second claim.
        second: Claim,
    },
}

impl core::fmt::Display for TransferBreach {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::SourceKind { table, rule } => {
                write!(f, "{table:?} rule {rule}'s source occurrence is not a LEN record")
            }
            Self::TargetKind { rule } => {
                write!(f, "payload-copy rule {rule}'s target occurrence is not a LEN record")
            }
            Self::AnchorKind { table, rule } => {
                write!(f, "{table:?} rule {rule}'s anchor occurrence is a scalar record")
            }
            Self::Cardinality { table, rule, sources, destinations } => {
                write!(
                    f,
                    "{table:?} rule {rule} designated {sources} sources for \
                     {destinations} destinations"
                )
            }
            Self::Contested { first, second } => {
                write!(f, "one record occurrence claimed twice: {first:?} and {second:?}")
            }
        }
    }
}

impl core::error::Error for TransferBreach {}

/// A compiled transfer plan: the ordinary rules (inserts admitted,
/// judged exactly as at the [`InsertRuleSet`] door) beside the
/// three transfer tables, all shapes judged once here.
///
/// The plain doors carry none of this: a [`RuleSet`](super::RuleSet)
/// or [`InsertRuleSet`] job compiles no transfer table, branch, or
/// state. This door's jobs run the transfer engine — three walks
/// instead of two — through `rewrite_transfers` and its siblings
/// in each dialect module.
#[must_use]
#[derive(Clone, Copy, Debug)]
pub struct TransferRuleSet<'r> {
    actions: InsertRuleSet<'r>,
    records: &'r [RecordTransferRule<'r>],
    payload_copies: &'r [PayloadCopyRule<'r>],
    payload_moves: &'r [PayloadMoveRule<'r>],
}

/// Judges one transfer path's shape, mapping the shared breach
/// vocabulary; `anchor` waives the empty-path law (the empty
/// anchor designates the root interior).
const fn judge_transfer_path(
    steps: &[Segment<'_>],
    table: TransferTable,
    rule: u32,
    role: PathRole,
    anchor: bool,
) -> Result<(), TransferRuleError> {
    if steps.is_empty() {
        if anchor {
            return Ok(());
        }
        return Err(TransferRuleError::Path { table, rule, role, breach: PathBreach::Empty });
    }
    if let Err(shape) = path::judge_path(steps) {
        let breach = match shape {
            path::ShapeBreach::EmptyPath => PathBreach::Empty,
            path::ShapeBreach::WildcardTarget => PathBreach::WildcardTarget,
            path::ShapeBreach::EmptyDescendSet { segment } => {
                PathBreach::EmptyDescendSet { segment }
            }
            path::ShapeBreach::UnsortedDescend { segment } => {
                PathBreach::UnsortedDescend { segment }
            }
            path::ShapeBreach::AdjacentWildcards { segment } => {
                PathBreach::AdjacentWildcards { segment }
            }
        };
        return Err(TransferRuleError::Path { table, rule, role, breach });
    }
    Ok(())
}

impl<'r> TransferRuleSet<'r> {
    /// Judges every table's static shape and seals the plan.
    ///
    /// The ordinary `rules` face the insert-admitting door's exact
    /// judgment (insert rules lawful, the empty anchor path lawful
    /// for them alone, action duplicates refused). Transfer paths
    /// face the shared shape laws — non-empty except destination
    /// anchors (where the empty path designates the root
    /// interior), field terminals, canonical descend sets — and
    /// the combined transfer-path count must fit the matcher's
    /// state domain. Occurrence-level laws (source kinds, pairing
    /// counts, contested writers) are document facts and are
    /// judged per job, in the designation pass.
    ///
    /// # Errors
    ///
    /// [`TransferRuleError::Rules`] wrapping the host's judgment of
    /// the ordinary table; [`TransferRuleError::Path`] for a
    /// transfer path breaking a shape law;
    /// [`TransferRuleError::TooManyTransferPaths`] past the state
    /// domain.
    ///
    /// # Examples
    ///
    /// ```
    /// use protobuf_edit::FieldNumber;
    /// use protobuf_edit::path::Segment;
    /// use protobuf_edit::rewrite::{
    ///     CopyPairing, Gap, PathBreach, PathRole, PayloadCopyRule, PayloadCopyTarget,
    ///     RecordTransfer, RecordTransferRule, TransferRuleError, TransferRuleSet, TransferTable,
    /// };
    ///
    /// let f1 = FieldNumber::new(1).unwrap();
    /// // The empty anchor path is the root interior — lawful.
    /// let append = RecordTransferRule {
    ///     source: &[Segment::Field(f1)],
    ///     anchor: &[],
    ///     gap: Gap::TailOf,
    ///     transfer: RecordTransfer::Copy(CopyPairing::Zip),
    /// };
    /// assert!(TransferRuleSet::over(&[], &[append], &[], &[]).is_ok());
    ///
    /// // An empty source path designates nothing — refused.
    /// let empty = PayloadCopyRule {
    ///     source: &[],
    ///     target: PayloadCopyTarget::Replace { target: &[Segment::Field(f1)] },
    ///     pairing: CopyPairing::Zip,
    /// };
    /// assert_eq!(
    ///     TransferRuleSet::over(&[], &[], &[empty], &[]).err(),
    ///     Some(TransferRuleError::Path {
    ///         table: TransferTable::PayloadCopies,
    ///         rule: 0,
    ///         role: PathRole::Source,
    ///         breach: PathBreach::Empty,
    ///     })
    /// );
    /// ```
    pub const fn over(
        rules: &'r [Rule<'r>],
        records: &'r [RecordTransferRule<'r>],
        payload_copies: &'r [PayloadCopyRule<'r>],
        payload_moves: &'r [PayloadMoveRule<'r>],
    ) -> Result<Self, TransferRuleError> {
        let actions = match InsertRuleSet::over(rules) {
            Ok(set) => set,
            Err(refusal) => return Err(TransferRuleError::Rules(refusal)),
        };
        // Two matcher-domain paths per rule (source + destination),
        // counted across the three tables.
        let total = (records.len() + payload_copies.len() + payload_moves.len()) * 2;
        #[allow(clippy::as_conversions, reason = "u16::MAX widens losslessly for the cap check")]
        if total > u16::MAX as usize {
            return Err(TransferRuleError::TooManyTransferPaths { count: total });
        }
        let mut index = 0;
        while index < records.len() {
            let rule = &records[index];
            let at = path::ix_u32(index);
            let table = TransferTable::Records;
            if let Err(refusal) =
                judge_transfer_path(rule.source, table, at, PathRole::Source, false)
            {
                return Err(refusal);
            }
            if let Err(refusal) =
                judge_transfer_path(rule.anchor, table, at, PathRole::Anchor, true)
            {
                return Err(refusal);
            }
            index += 1;
        }
        index = 0;
        while index < payload_copies.len() {
            let rule = &payload_copies[index];
            let at = path::ix_u32(index);
            let table = TransferTable::PayloadCopies;
            if let Err(refusal) =
                judge_transfer_path(rule.source, table, at, PathRole::Source, false)
            {
                return Err(refusal);
            }
            let destination = match rule.target {
                PayloadCopyTarget::Replace { target } => {
                    judge_transfer_path(target, table, at, PathRole::Target, false)
                }
                PayloadCopyTarget::Insert { anchor, .. } => {
                    judge_transfer_path(anchor, table, at, PathRole::Anchor, true)
                }
            };
            if let Err(refusal) = destination {
                return Err(refusal);
            }
            index += 1;
        }
        index = 0;
        while index < payload_moves.len() {
            let rule = &payload_moves[index];
            let at = path::ix_u32(index);
            let table = TransferTable::PayloadMoves;
            if let Err(refusal) =
                judge_transfer_path(rule.source, table, at, PathRole::Source, false)
            {
                return Err(refusal);
            }
            if let Err(refusal) =
                judge_transfer_path(rule.anchor, table, at, PathRole::Anchor, true)
            {
                return Err(refusal);
            }
            index += 1;
        }
        Ok(Self { actions, records, payload_copies, payload_moves })
    }

    /// The ordinary-rule door this plan embeds — the walks drive
    /// the host's action machinery through it, unchanged.
    pub(super) const fn actions(&self) -> InsertRuleSet<'r> {
        self.actions
    }
}

/// The transfer job receipt: the host's action tallies plus the
/// four transfer counts.
///
/// Zero transfer counts are the silently-inapplicable signal — a
/// source that never occurred, or destinations whose owning
/// interior was never emitted.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct TransferStats {
    pub(super) core: InsertStats,
    pub(super) records_copied: u32,
    pub(super) records_moved: u32,
    pub(super) payloads_copied: u32,
    pub(super) payloads_moved: u32,
}

impl TransferStats {
    /// Records deleted by ordinary rules (a deleted group counts
    /// once).
    #[inline]
    #[must_use]
    pub const fn deleted(self) -> u32 {
        self.core.deleted()
    }

    /// Records replaced by ordinary rules.
    #[inline]
    #[must_use]
    pub const fn replaced(self) -> u32 {
        self.core.replaced()
    }

    /// Records re-emitted at minimal width by ordinary rules.
    #[inline]
    #[must_use]
    pub const fn normalized(self) -> u32 {
        self.core.normalized()
    }

    /// Records inserted by ordinary insert rules.
    #[inline]
    #[must_use]
    pub const fn inserted(self) -> u32 {
        self.core.inserted()
    }

    /// LEN payloads descended into (committed as messages).
    #[inline]
    #[must_use]
    pub const fn descended(self) -> u32 {
        self.core.descended()
    }

    /// Whole records copied — one per emitting destination
    /// occurrence.
    #[inline]
    #[must_use]
    pub const fn records_copied(self) -> u32 {
        self.records_copied
    }

    /// Whole records moved — one per emitting destination
    /// occurrence.
    #[inline]
    #[must_use]
    pub const fn records_moved(self) -> u32 {
        self.records_moved
    }

    /// Payload interiors copied — replaced targets and authored
    /// insertions both count here.
    #[inline]
    #[must_use]
    pub const fn payloads_copied(self) -> u32 {
        self.payloads_copied
    }

    /// Payload interiors moved.
    #[inline]
    #[must_use]
    pub const fn payloads_moved(self) -> u32 {
        self.payloads_moved
    }

    /// Every judgment tally, the descend count excluded — the emit
    /// pass skips clean subtrees, so its descend count lawfully
    /// undershoots while every judgment must repeat.
    pub(super) const fn judgments(self) -> [u32; 8] {
        [
            self.core.deleted(),
            self.core.replaced(),
            self.core.normalized(),
            self.core.inserted(),
            self.records_copied,
            self.records_moved,
            self.payloads_copied,
            self.payloads_moved,
        ]
    }
}

// ─── the transfer-path matcher provider (engine-internal) ───

/// One transfer path's population, classified from its matcher id.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum TransferHit {
    /// A record-transfer rule's source terminal.
    RecordSource(u16),
    /// A record-transfer rule's anchor terminal.
    RecordAnchor(u16),
    /// A payload-copy rule's source terminal.
    CopySource(u16),
    /// A payload-copy rule's replace-target terminal.
    CopyTarget(u16),
    /// A payload-copy rule's insert-anchor terminal.
    CopyAnchor(u16),
    /// A payload-move rule's source terminal.
    MoveSource(u16),
    /// A payload-move rule's anchor terminal.
    MoveAnchor(u16),
}

/// The transfer paths as one matcher provider: sources first, then
/// destinations, tables in declaration order. Every terminal rides
/// the gap store's visit-all fold (one lane) — the classification
/// happens at the id, so the walk separates populations without a
/// second matcher scan. The target table stays empty: no transfer
/// path is an exclusive action terminal.
#[derive(Clone, Copy)]
pub(super) struct TransferPaths<'r> {
    records: &'r [RecordTransferRule<'r>],
    payload_copies: &'r [PayloadCopyRule<'r>],
    payload_moves: &'r [PayloadMoveRule<'r>],
}

impl<'r> TransferPaths<'r> {
    pub(super) const fn new(set: &TransferRuleSet<'r>) -> Self {
        Self {
            records: set.records,
            payload_copies: set.payload_copies,
            payload_moves: set.payload_moves,
        }
    }

    /// Classifies a matcher id into its population and rule index.
    pub(super) fn classify(&self, id: u16) -> TransferHit {
        let id = usize::from(id);
        let r = self.records.len();
        let c = self.payload_copies.len();
        let m = self.payload_moves.len();
        // Lossless: `over` admitted 2·(r + c + m) to u16.
        #[allow(clippy::as_conversions, reason = "over admitted the path count to u16")]
        match id {
            _ if id < r => TransferHit::RecordSource(id as u16),
            _ if id < 2 * r => TransferHit::RecordAnchor((id - r) as u16),
            _ if id < 2 * r + c => TransferHit::CopySource((id - 2 * r) as u16),
            _ if id < 2 * r + 2 * c => {
                let rule = (id - (2 * r + c)) as u16;
                match self.payload_copies[usize::from(rule)].target {
                    PayloadCopyTarget::Replace { .. } => TransferHit::CopyTarget(rule),
                    PayloadCopyTarget::Insert { .. } => TransferHit::CopyAnchor(rule),
                }
            }
            _ if id < 2 * r + 2 * c + m => TransferHit::MoveSource((id - (2 * r + 2 * c)) as u16),
            _ => {
                debug_assert!(id < 2 * (r + c + m), "ids are minted below count()");
                TransferHit::MoveAnchor((id - (2 * r + 2 * c + m)) as u16)
            }
        }
    }

    /// The destination gap side of an anchor hit (`None` for the
    /// replace-target population, which has no gap).
    pub(super) fn gap_side(&self, hit: TransferHit) -> Option<Gap> {
        match hit {
            TransferHit::RecordAnchor(rule) => Some(self.records[usize::from(rule)].gap),
            TransferHit::CopyAnchor(rule) => {
                match self.payload_copies[usize::from(rule)].target {
                    PayloadCopyTarget::Insert { gap, .. } => Some(gap),
                    // The classification minted `CopyAnchor` from the
                    // Insert form.
                    PayloadCopyTarget::Replace { .. } => unreachable!("anchor hits quote inserts"),
                }
            }
            TransferHit::MoveAnchor(rule) => Some(self.payload_moves[usize::from(rule)].gap),
            _ => None,
        }
    }

    /// Feeds every root-gap transfer rule of `gap`'s kind to
    /// `fire`, tables in population order, rule order within each —
    /// empty anchor paths live outside the NFA, exactly as the
    /// host's root insert rules do.
    pub(super) fn root_anchors(&self, gap: Gap, mut fire: impl FnMut(TransferHit)) {
        for (index, rule) in self.records.iter().enumerate() {
            if rule.anchor.is_empty() && rule.gap == gap {
                // Lossless: `over` admitted the table sizes to u16.
                #[allow(clippy::as_conversions, reason = "table sizes admitted to u16")]
                fire(TransferHit::RecordAnchor(index as u16));
            }
        }
        for (index, rule) in self.payload_copies.iter().enumerate() {
            if let PayloadCopyTarget::Insert { anchor, gap: side, .. } = rule.target
                && anchor.is_empty()
                && side == gap
            {
                #[allow(clippy::as_conversions, reason = "table sizes admitted to u16")]
                fire(TransferHit::CopyAnchor(index as u16));
            }
        }
        for (index, rule) in self.payload_moves.iter().enumerate() {
            if rule.anchor.is_empty() && rule.gap == gap {
                #[allow(clippy::as_conversions, reason = "table sizes admitted to u16")]
                fire(TransferHit::MoveAnchor(index as u16));
            }
        }
    }
}

impl<'r> path::Paths<'r> for TransferPaths<'r> {
    // Every terminal lands in the gap store (visit-all fold); the
    // conflict-folded target table stays empty.
    const LANED: bool = true;

    type Gaps = path::GapTable;

    #[inline]
    fn count(&self) -> u16 {
        // Lossless: `over` admitted the combined count to u16.
        #[allow(clippy::as_conversions, reason = "over admitted the path count to u16")]
        {
            (2 * (self.records.len() + self.payload_copies.len() + self.payload_moves.len())) as u16
        }
    }

    fn path(&self, id: u16) -> &'r [Segment<'r>] {
        match self.classify(id) {
            TransferHit::RecordSource(rule) => self.records[usize::from(rule)].source,
            TransferHit::RecordAnchor(rule) => self.records[usize::from(rule)].anchor,
            TransferHit::CopySource(rule) => self.payload_copies[usize::from(rule)].source,
            TransferHit::CopyTarget(rule) | TransferHit::CopyAnchor(rule) => {
                match self.payload_copies[usize::from(rule)].target {
                    PayloadCopyTarget::Replace { target } => target,
                    PayloadCopyTarget::Insert { anchor, .. } => anchor,
                }
            }
            TransferHit::MoveSource(rule) => self.payload_moves[usize::from(rule)].source,
            TransferHit::MoveAnchor(rule) => self.payload_moves[usize::from(rule)].anchor,
        }
    }

    #[inline]
    fn lane(&self, _id: u16) -> Lane {
        // One visit-all population; the walk classifies by id.
        Lane::Head
    }
}

// ─── the designation product (engine-internal) ───

/// One designated source occurrence's byte facts. For record
/// transfers the span is the whole record; for payload transfers
/// it is the LEN interior. Grouped record sources fill `to` at the
/// group's verified exit (the designation order is the enter
/// order).
#[derive(Clone, Copy, Debug)]
pub(super) struct SourceSpan {
    pub(super) from: Coord,
    pub(super) to: Coord,
}

/// The designation pass's product for one transfer job: per-rule
/// source spans in walk order, per-rule destination counts, the
/// move-suppressed record heads, and the resolved replace targets.
/// Coordinates only — no source byte is retained.
pub(super) struct TransferPlan {
    /// Source spans per record-transfer rule.
    pub(super) record_sources: Vec<Vec<SourceSpan>>,
    /// Destination occurrences per record-transfer rule.
    pub(super) record_gaps: Vec<u32>,
    /// Source payload spans per payload-copy rule.
    pub(super) copy_sources: Vec<Vec<SourceSpan>>,
    /// Destination occurrences per payload-copy rule (replace
    /// targets and insert anchors both count here).
    pub(super) copy_gaps: Vec<u32>,
    /// Source payload spans per payload-move rule, with the whole
    /// record's head for suppression.
    pub(super) move_sources: Vec<Vec<SourceSpan>>,
    /// Destination occurrences per payload-move rule.
    pub(super) move_gaps: Vec<u32>,
    /// Move-suppressed record heads, ascending (walk order).
    pub(super) moved: Vec<Coord>,
    /// Replace-target record heads with their resolved source
    /// interiors, ascending (walk order across all rules).
    pub(super) replaced: Vec<(Coord, SourceSpan)>,
}

impl TransferPlan {
    pub(super) fn new(set: &TransferRuleSet<'_>) -> Self {
        Self {
            record_sources: alloc::vec![Vec::new(); set.records.len()],
            record_gaps: alloc::vec![0; set.records.len()],
            copy_sources: alloc::vec![Vec::new(); set.payload_copies.len()],
            copy_gaps: alloc::vec![0; set.payload_copies.len()],
            move_sources: alloc::vec![Vec::new(); set.payload_moves.len()],
            move_gaps: alloc::vec![0; set.payload_moves.len()],
            moved: Vec::new(),
            replaced: Vec::new(),
        }
    }

    /// Judges the pairing equations and resolves every replace
    /// target against its paired source — the plan-level laws the
    /// per-occurrence pass could not close. The per-rule target
    /// heads arrive in walk order per rule; the merged table is
    /// sorted once so the apply passes consume it with one cursor.
    pub(super) fn resolve(
        &mut self,
        set: &TransferRuleSet<'_>,
        copy_targets: &[Vec<Coord>],
    ) -> Result<(), TransferBreach> {
        for (index, rule) in set.records.iter().enumerate() {
            let sources = path::ix_u32(self.record_sources[index].len());
            let destinations = self.record_gaps[index];
            let pairing = match rule.transfer {
                RecordTransfer::Copy(pairing) => pairing,
                RecordTransfer::MoveZip => CopyPairing::Zip,
            };
            judge_pairing(TransferTable::Records, index, pairing, sources, destinations)?;
        }
        for (index, rule) in set.payload_copies.iter().enumerate() {
            let sources = path::ix_u32(self.copy_sources[index].len());
            // Replace destinations are the target occurrences,
            // designated at their own record events; insert
            // destinations are the fired anchor gaps.
            let destinations = match rule.target {
                PayloadCopyTarget::Replace { .. } => path::ix_u32(copy_targets[index].len()),
                PayloadCopyTarget::Insert { .. } => self.copy_gaps[index],
            };
            judge_pairing(
                TransferTable::PayloadCopies,
                index,
                rule.pairing,
                sources,
                destinations,
            )?;
            if let PayloadCopyTarget::Replace { .. } = rule.target {
                for (ordinal, &head) in copy_targets[index].iter().enumerate() {
                    let span = match rule.pairing {
                        CopyPairing::Zip => self.copy_sources[index][ordinal],
                        CopyPairing::BroadcastOne => self.copy_sources[index][0],
                    };
                    self.replaced.push((head, span));
                }
            }
        }
        for (index, _) in set.payload_moves.iter().enumerate() {
            let sources = path::ix_u32(self.move_sources[index].len());
            let destinations = self.move_gaps[index];
            judge_pairing(
                TransferTable::PayloadMoves,
                index,
                CopyPairing::Zip,
                sources,
                destinations,
            )?;
        }
        // Replace targets of different rules interleave in the
        // document; one sort restores the walk order the apply
        // cursor consumes. The moved heads arrive in walk order
        // already (one designation event per occurrence).
        self.replaced.sort_unstable_by_key(|&(head, _)| head);
        debug_assert!(self.moved.is_sorted(), "record events ascend");
        Ok(())
    }
}

/// The pairing equations, one place: zip demands equal counts;
/// broadcast demands exactly one source wherever anything would
/// emit (a wholly inapplicable rule — zero and zero — is silent,
/// as inserts are).
const fn judge_pairing(
    table: TransferTable,
    rule: usize,
    pairing: CopyPairing,
    sources: u32,
    destinations: u32,
) -> Result<(), TransferBreach> {
    let lawful = match pairing {
        CopyPairing::Zip => sources == destinations,
        CopyPairing::BroadcastOne => sources == 1 || (sources == 0 && destinations == 0),
    };
    if lawful {
        return Ok(());
    }
    Err(TransferBreach::Cardinality { table, rule: path::ix_u32(rule), sources, destinations })
}

// ─── the pass drivers (engine-internal) ───

/// What the walk does with the current record, ruled by the pass
/// driver: proceed with the host's ordinary handling, suppress a
/// moved record, or replace a payload target's interior with its
/// paired source span.
#[derive(Clone, Copy, Debug)]
pub(super) enum Disposition {
    /// No transfer owns the record — the host handling proceeds.
    Ordinary,
    /// The record is a move source: it emits nowhere here, and its
    /// interior leaves the walk.
    Suppress,
    /// The record is a replace target: destination tag verbatim, a
    /// minimal prefix, the source interior byte-exact; its own
    /// interior leaves the walk. The designation pass carries a
    /// placeholder span (its sink discards every emission); the
    /// apply passes carry the paired source.
    Replaced(SourceSpan),
}

/// One firing destination's emission, resolved by the apply
/// driver (`None` from the designation driver, which only counts).
#[derive(Clone, Copy, Debug)]
pub(super) enum GapEmission {
    /// A whole record's exact bytes.
    Record {
        /// The source record span.
        span: SourceSpan,
        /// Move (the origin is suppressed) or copy.
        moved: bool,
    },
    /// An authored LEN record over a source interior.
    Payload {
        /// The authored record's field.
        field: FieldNumber,
        /// The source interior span.
        span: SourceSpan,
        /// Move or copy.
        moved: bool,
    },
}

/// One pass's transfer decisions. The designation pass collects
/// designations and judges every transfer law (its breach channel
/// is live); the apply passes consume the resolved plan (their
/// breach channel is uninhabited, so every judgment site is dead
/// in their instantiations — the fault-barrier discipline the
/// host's two passes already follow).
pub(super) trait Driver {
    /// The pass's transfer-law fault channel.
    type Breach;

    /// A scalar record completed, with its transfer hits and the
    /// owning action rule if any.
    fn scalar(
        &mut self,
        head: u32,
        end: u32,
        hits: &[TransferHit],
        owned: Option<u16>,
    ) -> Result<Disposition, Self::Breach>;

    /// A LEN record completed, with its transfer hits and the
    /// owning action rule if any.
    fn len(
        &mut self,
        head: u32,
        payload_start: u32,
        end: u32,
        hits: &[TransferHit],
        owned: Option<u16>,
    ) -> Result<Disposition, Self::Breach>;

    /// A group record opened (`end` is past the open tag), with
    /// its transfer hits and the owning action rule if any. Groups
    /// never carry a `Replaced` disposition — replace targets are
    /// LEN records by the kind law.
    #[cfg(feature = "transfer-rewrite-grouped")]
    fn group_enter(
        &mut self,
        head: u32,
        hits: &[TransferHit],
        owned: Option<u16>,
    ) -> Result<Disposition, Self::Breach>;

    /// A group record-source designation opens at `head`; the
    /// returned slot is handed back at the group's verified exit.
    /// Designation order is the enter order.
    #[cfg(feature = "transfer-rewrite-grouped")]
    fn group_source_begin(&mut self, hit: TransferHit, head: u32) -> u32;

    /// The matching exit of a group record-source designation:
    /// `end` is past the end tag, completing the span.
    #[cfg(feature = "transfer-rewrite-grouped")]
    fn group_source_end(&mut self, hit: TransferHit, slot: u32, end: u32);

    /// One destination occurrence fired for an anchor hit: the
    /// designation driver counts it, the apply drivers resolve the
    /// emission.
    fn gap_fired(&mut self, hit: TransferHit) -> Option<GapEmission>;
}

/// The placeholder span the designation pass returns where the
/// apply passes carry a resolved source — its sink discards every
/// emission, so the empty slice is never observable.
const UNRESOLVED: SourceSpan = SourceSpan { from: Coord::MIN, to: Coord::MIN };

/// The designation driver: binds source spans, counts destination
/// occurrences, and judges the kind, ownership, and contest laws
/// at each occurrence. Pairing closes after the walk, in
/// [`TransferPlan::resolve`].
pub(super) struct Scout<'r, 's> {
    set: &'s TransferRuleSet<'r>,
    plan: TransferPlan,
    /// Replace-target heads per payload-copy rule, walk order.
    copy_targets: Vec<Vec<Coord>>,
    /// Per-occurrence writer-claim scratch, cleared per record.
    claims: Vec<Claim>,
}

impl<'r, 's> Scout<'r, 's> {
    pub(super) fn new(set: &'s TransferRuleSet<'r>) -> Self {
        Self {
            set,
            plan: TransferPlan::new(set),
            copy_targets: alloc::vec![Vec::new(); set.payload_copies.len()],
            claims: Vec::new(),
        }
    }

    /// Judges the occurrence's writer claims: at most one of an
    /// action, a replace target, or a move.
    fn contest(&self) -> Result<(), TransferBreach> {
        if self.claims.len() >= 2 {
            return Err(TransferBreach::Contested {
                first: self.claims[0],
                second: self.claims[1],
            });
        }
        Ok(())
    }

    /// Surrenders the designations for the plan resolution.
    pub(super) fn finish(self) -> (TransferPlan, Vec<Vec<Coord>>) {
        (self.plan, self.copy_targets)
    }
}

impl From<core::convert::Infallible> for TransferBreach {
    #[inline]
    fn from(refusal: core::convert::Infallible) -> Self {
        match refusal {}
    }
}

impl Driver for Scout<'_, '_> {
    type Breach = TransferBreach;

    fn scalar(
        &mut self,
        head: u32,
        end: u32,
        hits: &[TransferHit],
        owned: Option<u16>,
    ) -> Result<Disposition, TransferBreach> {
        self.claims.clear();
        if let Some(rule) = owned {
            self.claims.push(Claim::Action { rule: u32::from(rule) });
        }
        let mut moved = false;
        // SAFETY (both mints below): the transfer walk hands record
        // offsets inside the admitted input (the traversal door
        // refused an oversize input), so every offset is in class.
        let head = unsafe { Coord::new_unchecked(head) };
        let end = unsafe { Coord::new_unchecked(end) };
        for &hit in hits {
            match hit {
                TransferHit::RecordSource(rule) => {
                    self.plan.record_sources[usize::from(rule)]
                        .push(SourceSpan { from: head, to: end });
                    if matches!(
                        self.set.records[usize::from(rule)].transfer,
                        RecordTransfer::MoveZip
                    ) {
                        self.claims.push(Claim::RecordMove { rule: u32::from(rule) });
                        moved = true;
                    }
                }
                TransferHit::CopySource(rule) => {
                    return Err(TransferBreach::SourceKind {
                        table: TransferTable::PayloadCopies,
                        rule: u32::from(rule),
                    });
                }
                TransferHit::MoveSource(rule) => {
                    return Err(TransferBreach::SourceKind {
                        table: TransferTable::PayloadMoves,
                        rule: u32::from(rule),
                    });
                }
                TransferHit::CopyTarget(rule) => {
                    return Err(TransferBreach::TargetKind { rule: u32::from(rule) });
                }
                TransferHit::RecordAnchor(rule) => {
                    return Err(TransferBreach::AnchorKind {
                        table: TransferTable::Records,
                        rule: u32::from(rule),
                    });
                }
                TransferHit::CopyAnchor(rule) => {
                    return Err(TransferBreach::AnchorKind {
                        table: TransferTable::PayloadCopies,
                        rule: u32::from(rule),
                    });
                }
                TransferHit::MoveAnchor(rule) => {
                    return Err(TransferBreach::AnchorKind {
                        table: TransferTable::PayloadMoves,
                        rule: u32::from(rule),
                    });
                }
            }
        }
        self.contest()?;
        if moved {
            self.plan.moved.push(head);
            return Ok(Disposition::Suppress);
        }
        Ok(Disposition::Ordinary)
    }

    fn len(
        &mut self,
        head: u32,
        payload_start: u32,
        end: u32,
        hits: &[TransferHit],
        owned: Option<u16>,
    ) -> Result<Disposition, TransferBreach> {
        self.claims.clear();
        if let Some(rule) = owned {
            self.claims.push(Claim::Action { rule: u32::from(rule) });
        }
        let mut moved = false;
        let mut replaced = false;
        // SAFETY (all three mints below): the transfer walk hands
        // record offsets inside the admitted input (the traversal
        // door refused an oversize input), so every offset is in
        // class.
        let head = unsafe { Coord::new_unchecked(head) };
        let payload_start = unsafe { Coord::new_unchecked(payload_start) };
        let end = unsafe { Coord::new_unchecked(end) };
        for &hit in hits {
            match hit {
                TransferHit::RecordSource(rule) => {
                    self.plan.record_sources[usize::from(rule)]
                        .push(SourceSpan { from: head, to: end });
                    if matches!(
                        self.set.records[usize::from(rule)].transfer,
                        RecordTransfer::MoveZip
                    ) {
                        self.claims.push(Claim::RecordMove { rule: u32::from(rule) });
                        moved = true;
                    }
                }
                TransferHit::CopySource(rule) => {
                    self.plan.copy_sources[usize::from(rule)]
                        .push(SourceSpan { from: payload_start, to: end });
                }
                TransferHit::MoveSource(rule) => {
                    self.plan.move_sources[usize::from(rule)]
                        .push(SourceSpan { from: payload_start, to: end });
                    self.claims.push(Claim::PayloadMove { rule: u32::from(rule) });
                    moved = true;
                }
                TransferHit::CopyTarget(rule) => {
                    self.copy_targets[usize::from(rule)].push(head);
                    self.claims.push(Claim::ReplaceTarget { rule: u32::from(rule) });
                    replaced = true;
                }
                // Anchor hits commit containerhood; a LEN is a
                // container, so the descent question is the walk's
                // (gap firing happens at the descent events).
                TransferHit::RecordAnchor(_)
                | TransferHit::CopyAnchor(_)
                | TransferHit::MoveAnchor(_) => {}
            }
        }
        self.contest()?;
        if moved {
            self.plan.moved.push(head);
            return Ok(Disposition::Suppress);
        }
        if replaced {
            return Ok(Disposition::Replaced(UNRESOLVED));
        }
        Ok(Disposition::Ordinary)
    }

    #[cfg(feature = "transfer-rewrite-grouped")]
    fn group_enter(
        &mut self,
        head: u32,
        hits: &[TransferHit],
        owned: Option<u16>,
    ) -> Result<Disposition, TransferBreach> {
        self.claims.clear();
        if let Some(rule) = owned {
            self.claims.push(Claim::Action { rule: u32::from(rule) });
        }
        let mut moved = false;
        for &hit in hits {
            match hit {
                // The span completes at the verified exit through
                // `group_source_begin`/`group_source_end`; only the
                // move claim is judged here.
                TransferHit::RecordSource(rule) => {
                    if matches!(
                        self.set.records[usize::from(rule)].transfer,
                        RecordTransfer::MoveZip
                    ) {
                        self.claims.push(Claim::RecordMove { rule: u32::from(rule) });
                        moved = true;
                    }
                }
                TransferHit::CopySource(rule) => {
                    return Err(TransferBreach::SourceKind {
                        table: TransferTable::PayloadCopies,
                        rule: u32::from(rule),
                    });
                }
                TransferHit::MoveSource(rule) => {
                    return Err(TransferBreach::SourceKind {
                        table: TransferTable::PayloadMoves,
                        rule: u32::from(rule),
                    });
                }
                TransferHit::CopyTarget(rule) => {
                    return Err(TransferBreach::TargetKind { rule: u32::from(rule) });
                }
                // A group is a container by syntax: anchors are
                // lawful, and their gaps fire at the group's own
                // events.
                TransferHit::RecordAnchor(_)
                | TransferHit::CopyAnchor(_)
                | TransferHit::MoveAnchor(_) => {}
            }
        }
        self.contest()?;
        if moved {
            // SAFETY: the transfer walk hands record offsets inside
            // the admitted input, so the offset is in class.
            self.plan.moved.push(unsafe { Coord::new_unchecked(head) });
            return Ok(Disposition::Suppress);
        }
        Ok(Disposition::Ordinary)
    }

    #[cfg(feature = "transfer-rewrite-grouped")]
    fn group_source_begin(&mut self, hit: TransferHit, head: u32) -> u32 {
        let TransferHit::RecordSource(rule) = hit else {
            unreachable!("group captures quote record sources");
        };
        let sources = &mut self.plan.record_sources[usize::from(rule)];
        // SAFETY: the transfer walk hands record offsets inside the
        // admitted input, so the offset is in class; the provisional
        // end is the class floor, resolved at the verified exit.
        sources.push(SourceSpan { from: unsafe { Coord::new_unchecked(head) }, to: Coord::MIN });
        path::ix_u32(sources.len() - 1)
    }

    #[cfg(feature = "transfer-rewrite-grouped")]
    fn group_source_end(&mut self, hit: TransferHit, slot: u32, end: u32) {
        let TransferHit::RecordSource(rule) = hit else {
            unreachable!("group captures quote record sources");
        };
        // SAFETY: the transfer walk hands the verified exit offset
        // inside the admitted input, so the offset is in class.
        self.plan.record_sources[usize::from(rule)][crate::admission::usize_of(slot)].to =
            unsafe { Coord::new_unchecked(end) };
    }

    fn gap_fired(&mut self, hit: TransferHit) -> Option<GapEmission> {
        match hit {
            TransferHit::RecordAnchor(rule) => self.plan.record_gaps[usize::from(rule)] += 1,
            TransferHit::CopyAnchor(rule) => self.plan.copy_gaps[usize::from(rule)] += 1,
            TransferHit::MoveAnchor(rule) => self.plan.move_gaps[usize::from(rule)] += 1,
            // Replace targets are designated at their own record
            // events; source populations never anchor a gap.
            TransferHit::CopyTarget(_)
            | TransferHit::RecordSource(_)
            | TransferHit::CopySource(_)
            | TransferHit::MoveSource(_) => {
                unreachable!("gaps fire for anchor hits")
            }
        }
        None
    }
}

/// The apply driver: both the measuring and the emitting pass
/// consume the one resolved plan through it — per-rule destination
/// cursors and the two suppression/replacement cursors, advanced
/// by the deterministic replay.
pub(super) struct Apply<'r, 's> {
    set: &'s TransferRuleSet<'r>,
    plan: &'s TransferPlan,
    record_fired: Vec<u32>,
    copy_fired: Vec<u32>,
    move_fired: Vec<u32>,
    moved_at: usize,
    replaced_at: usize,
}

impl<'r, 's> Apply<'r, 's> {
    pub(super) fn new(set: &'s TransferRuleSet<'r>, plan: &'s TransferPlan) -> Self {
        Self {
            set,
            plan,
            record_fired: alloc::vec![0; set.records.len()],
            copy_fired: alloc::vec![0; set.payload_copies.len()],
            move_fired: alloc::vec![0; set.payload_moves.len()],
            moved_at: 0,
            replaced_at: 0,
        }
    }

    /// Rewinds every cursor for the next replay over the same plan.
    pub(super) fn rewind(&mut self) {
        self.record_fired.fill(0);
        self.copy_fired.fill(0);
        self.move_fired.fill(0);
        self.moved_at = 0;
        self.replaced_at = 0;
    }

    /// The one record-event judgment: a move-suppressed head, a
    /// replaced target head, or ordinary. Record events arrive in
    /// ascending head order, so both tables consume with cursors.
    fn record_event(&mut self, head: u32) -> Disposition {
        if self.moved_at < self.plan.moved.len()
            && self.plan.moved[self.moved_at].as_inner() == head
        {
            self.moved_at += 1;
            return Disposition::Suppress;
        }
        if self.replaced_at < self.plan.replaced.len()
            && self.plan.replaced[self.replaced_at].0.as_inner() == head
        {
            let span = self.plan.replaced[self.replaced_at].1;
            self.replaced_at += 1;
            return Disposition::Replaced(span);
        }
        Disposition::Ordinary
    }
}

impl Driver for Apply<'_, '_> {
    type Breach = core::convert::Infallible;

    fn scalar(
        &mut self,
        head: u32,
        _end: u32,
        _hits: &[TransferHit],
        _owned: Option<u16>,
    ) -> Result<Disposition, Self::Breach> {
        Ok(self.record_event(head))
    }

    fn len(
        &mut self,
        head: u32,
        _payload_start: u32,
        _end: u32,
        _hits: &[TransferHit],
        _owned: Option<u16>,
    ) -> Result<Disposition, Self::Breach> {
        Ok(self.record_event(head))
    }

    #[cfg(feature = "transfer-rewrite-grouped")]
    fn group_enter(
        &mut self,
        head: u32,
        _hits: &[TransferHit],
        _owned: Option<u16>,
    ) -> Result<Disposition, Self::Breach> {
        Ok(self.record_event(head))
    }

    #[cfg(feature = "transfer-rewrite-grouped")]
    fn group_source_begin(&mut self, _hit: TransferHit, _head: u32) -> u32 {
        0
    }

    #[cfg(feature = "transfer-rewrite-grouped")]
    fn group_source_end(&mut self, _hit: TransferHit, _slot: u32, _end: u32) {}

    fn gap_fired(&mut self, hit: TransferHit) -> Option<GapEmission> {
        Some(match hit {
            TransferHit::RecordAnchor(rule) => {
                let index = usize::from(rule);
                let k = self.record_fired[index];
                self.record_fired[index] += 1;
                let (source, moved) = match self.set.records[index].transfer {
                    RecordTransfer::Copy(CopyPairing::Zip) => (k, false),
                    RecordTransfer::Copy(CopyPairing::BroadcastOne) => (0, false),
                    RecordTransfer::MoveZip => (k, true),
                };
                let span = self.plan.record_sources[index][crate::admission::usize_of(source)];
                GapEmission::Record { span, moved }
            }
            TransferHit::CopyAnchor(rule) => {
                let index = usize::from(rule);
                let k = self.copy_fired[index];
                self.copy_fired[index] += 1;
                let PayloadCopyTarget::Insert { field, .. } = self.set.payload_copies[index].target
                else {
                    // The classification minted `CopyAnchor` from
                    // the Insert form.
                    unreachable!("anchor hits quote inserts")
                };
                let source = match self.set.payload_copies[index].pairing {
                    CopyPairing::Zip => k,
                    CopyPairing::BroadcastOne => 0,
                };
                let span = self.plan.copy_sources[index][crate::admission::usize_of(source)];
                GapEmission::Payload { field, span, moved: false }
            }
            TransferHit::MoveAnchor(rule) => {
                let index = usize::from(rule);
                let k = self.move_fired[index];
                self.move_fired[index] += 1;
                let span = self.plan.move_sources[index][crate::admission::usize_of(k)];
                GapEmission::Payload {
                    field: self.set.payload_moves[index].field,
                    span,
                    moved: true,
                }
            }
            // Replace targets consume at their own record events;
            // source populations never anchor a gap.
            TransferHit::CopyTarget(_)
            | TransferHit::RecordSource(_)
            | TransferHit::CopySource(_)
            | TransferHit::MoveSource(_) => unreachable!("gaps fire for anchor hits"),
        })
    }
}

/// A transfer walk's two-channel refusal: the host sink's own
/// channel (the document faults, uninhabited past the fault
/// barrier) or a transfer-law breach with its position and promise
/// chain (uninhabited in the apply passes).
pub(super) enum Flow<R, B> {
    /// The host fault channel's product.
    Host(R),
    /// A transfer-law breach at a designated occurrence.
    Transfer {
        /// Whole-input byte coordinate.
        at: u32,
        /// Committed containers crossed to reach it.
        trail: alloc::boxed::Box<[crate::path::Crossing]>,
        /// The broken law.
        breach: B,
    },
}
