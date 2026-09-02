//! Rule-driven batch rewriting over a stable-replay source
//! (write · sequential-repeatable · static), per wire dialect —
//! the dialect-orthogonal shared layer.
//!
//! One job: a stable-replay source, a compiled rule set, two
//! walks, new output bytes. The first walk owns every judgment —
//! wire law, matching, growth accounting — and compiles a
//! source-anchored edit script with the settle ledger folded in;
//! the second walk is a splicing pump that parses nothing: it
//! copies kept extents view by view, seeks past dropped ones, and
//! emits staged words and rule payloads between — its fault
//! alphabet is the supply's own refusals and the length-shaped
//! tear, wire faults unspellable. Judgment never re-runs: the
//! matcher would descend untouched subtrees, re-reading what the
//! script lets the pump seek past.
//!
//! Rules are pure data: a path (root-anchored segments) paired
//! with an action. Paths commit — every LEN a pattern crosses is
//! committed to be a message, and a parse fault inside it is a
//! real fault (this library never guesses messageness). Wildcards
//! carry an explicit descend set, the caller's transcription of
//! "which fields are messages".
//!
//! Output acceptance: replacement payloads, every word a
//! `Normalize` touches, and re-framed prefixes are emitted
//! minimally; everything else — tags, kept records, crossed
//! framing whose interior length held — rides verbatim; the
//! output always re-ingests under `Tolerant`, and closes under
//! `CanonicalMinimal` exactly when every padded word either was
//! absent from the source or fell under a `Normalize` target.
//!
//! Allocation policy: every allocation is single-job working
//! memory — the walk's frame stack, the edit script, the staging
//! arena — grown under the global allocator's panic/abort
//! discipline, and a function of record structure and edit size,
//! never of source length. Every holding is the in-flight product
//! of one job, so an abort's loss ends with that job. Supply
//! refusals are structured faults; output publication follows the
//! face (the module doc of each dialect names the exact custody).
//!
//! Coordinates: write · sequential-repeatable · static · Standard (value-level) · commit-only.
//!
//! # Choosing a face
//!
//! - [`RuleSet::over`] judges the rules' static shape once;
//!   compile one set and run it across sources.
//! - Each dialect ships `rewrite` (fresh buffer), `rewrite_into`
//!   (append to yours; truncated back to its mark on any
//!   refusal), and `rewrite_sink` (borrowed views handed forward;
//!   a refusal names the exact handed prefix — a fallible source
//!   makes "every fault precedes the first handoff" impossible,
//!   so no zero-handoff promise exists here). All three return
//!   [`Stats`]; a zero count is the silently-inapplicable-rule
//!   signal. `_standard` twins take the acceptance
//!   [`Standard`](crate::Standard); the plain faces are exactly
//!   the tolerant instances.
//!
//! Authoring is data: a [`Rule`] is a path of
//! [`Segment`]s times an [`Action`].
//! [`Action::Delete`] removes the target; [`Action::Replace`]
//! re-emits its payload from a [`Value`] of wire words;
//! [`Action::Normalize`] re-emits the target's own words at
//! minimal width. Record insertion and scatter payloads are the
//! buffered rewriter's vocabulary alone; this cell's actions stop
//! at deletion, replacement, and normalization.
//!
//! Elsewhere: the same rule language over resident bytes →
//! `rewrite`; per-record verdicts with the payload delivered →
//! `replay_splice`; handle-addressed edits over a standing index
//! → `overhaul` (each behind its feature).

use crate::path::{self, Segment};
use crate::wire::PayloadLen;

/// What happens to a targeted record.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Action<'r> {
    /// The record vanishes (a targeted group vanishes whole,
    /// after its pairing is verified).
    Delete,
    /// The record's payload is replaced: tag bytes verbatim
    /// (field and kind unchanged), payload re-emitted canonically.
    /// The value's wire kind must equal the record's — a mismatch
    /// is the caller's schema error, faulted loudly.
    Replace(Value<'r>),
    /// The record re-emits at minimal width: tag, LEN length
    /// prefix, and varint value all minimal; fixed payloads have
    /// one width and a LEN payload's interior rides verbatim. A
    /// grouped target's two framing tags re-emit minimally around
    /// its interior, which stays subject to the walk and the
    /// other rules. Kind-free, so it never faults `KindMismatch`.
    Normalize,
}

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
    /// A LEN record's new payload. Borrowed for the whole job:
    /// rules are static data outliving both walks, so no answer
    /// copy exists.
    Len(&'r [u8]),
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

/// An authoring error, judged once at [`RuleSet::over`] —
/// distinct from document faults (different reader, different
/// fix).
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
    /// A descend set spelled out of canonical order (strictly
    /// ascending field numbers is the one admitted spelling).
    UnsortedDescend {
        /// The offending rule's index.
        rule: u32,
        /// The offending segment's index.
        segment: u32,
    },
    /// Two adjacent wildcards whose descend sets are comparable —
    /// a redundant spelling of the wider one.
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
    /// A rule's `Value::Len` payload is longer than the LEN
    /// class.
    OversizeValue {
        /// The offending rule's index.
        rule: u32,
    },
    /// More rules than the matcher's state domain (65,535)
    /// admits.
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

/// A compiled rule set: authoring judged once, jobs downstream
/// are judgment-free.
///
/// # Examples
///
/// ```
/// use protobuf_edit::FieldNumber;
/// use protobuf_edit::path::Segment;
/// use protobuf_edit::replay_rewrite::{Action, Rule, RuleError, RuleSet};
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
#[must_use]
#[derive(Clone, Copy, Debug)]
pub struct RuleSet<'r> {
    rules: &'r [Rule<'r>],
}

impl<'r> RuleSet<'r> {
    /// Judges the rules' static shape (paths, descend sets,
    /// duplicates, replacement sizes).
    ///
    /// # Errors
    ///
    /// [`RuleError::TooManyRules`] and [`RuleError::PathTooLong`]
    /// when either axis leaves the matcher's state domain;
    /// [`RuleError::EmptyPath`], [`RuleError::WildcardTarget`],
    /// and [`RuleError::EmptyDescendSet`] for degenerate paths;
    /// [`RuleError::UnsortedDescend`] for a descend set spelled
    /// out of its canonical order; [`RuleError::AdjacentWildcards`]
    /// for two wildcards in a row over comparable descend sets;
    /// [`RuleError::OversizeValue`] for a replaced payload
    /// outside the LEN class; [`RuleError::DuplicatePath`] when
    /// two rules would target every hit twice.
    #[inline]
    pub const fn over(rules: &'r [Rule<'r>]) -> Result<Self, RuleError> {
        if let Err(refusal) = judge(rules) {
            return Err(refusal);
        }
        Ok(Self { rules })
    }

    /// The action of a rule the matcher quoted. Crate-internal:
    /// its ids come from the matcher alone.
    #[inline]
    pub(crate) fn action(&self, rule: u16) -> Action<'r> {
        debug_assert!(usize::from(rule) < self.rules.len(), "hits quote admitted rules");
        // SAFETY: every quoted rule id is minted by the matcher's
        // flatten from states enumerated over this same admitted
        // slice, so it is below `rules.len()`.
        unsafe { self.rules.get_unchecked(usize::from(rule)) }.action
    }
}

/// The shared authoring judgment: the state domain caps, the path
/// shape laws, the value class, and the duplicate scan.
const fn judge(rules: &[Rule<'_>]) -> Result<(), RuleError> {
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
        if rule.path.is_empty() {
            return Err(RuleError::EmptyPath { rule: at });
        }
        if let Err(breach) = path::judge_path(rule.path) {
            return Err(shape_error(breach, at));
        }
        if let Action::Replace(Value::Len(bytes)) = rule.action
            && bytes.len() > crate::admission::usize_of(PayloadLen::MAX.as_inner())
        {
            return Err(RuleError::OversizeValue { rule: at });
        }
        index += 1;
    }
    // The direct quadratic duplicate scan reports the smallest
    // (first, second) pair — admission-time cost, never per job,
    // and const-capable.
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

/// Maps a shared shape breach onto this module's error
/// vocabulary.
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

impl<'r> path::Paths<'r> for RuleSet<'r> {
    // No insert rules exist in this cell's admitted vocabulary:
    // the unit gap store keeps its matcher free of gap machinery.
    type Gaps = ();

    #[inline]
    fn count(&self) -> u16 {
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

/// The job receipt: what each action class touched.
///
/// The exposure face for silently-inapplicable rules (a scalar
/// where the route expected a container, a kind the pattern never
/// meets) — zero counts are the operator's signal.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct Stats {
    pub(crate) deleted: u32,
    pub(crate) replaced: u32,
    pub(crate) normalized: u32,
    pub(crate) descended: u32,
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

    /// Containers descended into (committed by a crossing path).
    #[inline]
    #[must_use]
    pub const fn descended(self) -> u32 {
        self.descended
    }
}

#[cfg(feature = "replay-rewrite-grouped")]
pub mod grouped;
#[cfg(feature = "replay-rewrite-groupless")]
pub mod groupless;
