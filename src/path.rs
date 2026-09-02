//! The selection-path stratum: root-anchored path programs over
//! record fields, and the compiled matcher the static machines
//! share.
//!
//! Six machine families drive it, each behind its feature:
//! `select` reads what a program designates from a buffered
//! message and `route` from a chunked stream; `rewrite`,
//! `inplace`, and `convert` edit what rules designate in a
//! buffered one; `rewire` applies path-bound actions over a
//! stream.
//!
//! A path is a borrowed slice of [`Segment`]s: `Field` hops one
//! container level, `AnyDepth` crosses zero or more containers
//! restricted to its descend set — the caller's transcription of
//! "these fields are messages". Paths commit: every LEN a pattern
//! crosses is committed to be a message, and a parse fault inside
//! it is a real fault quoting the [`Crossing`] chain (this
//! library never guesses messageness). The shape laws — non-empty
//! paths, `Field` terminals, canonical descend sets, no redundant
//! respellings, no duplicate paths — are judged once at an
//! admission face ([`Program::over`] here, `RuleSet::over` on the
//! write side), and every job downstream runs judgment-free.
//!
//! [`Program::over`] is a `const fn`: a `static` program compiles
//! the whole judgment away, so a process-reused selection carries
//! zero per-request authoring cost (see its example). The
//! admission's duplicate scan is the direct quadratic one — a
//! per-set authoring cost with no per-job claimant.

#[cfg(any(
    feature = "select-grouped",
    feature = "select-groupless",
    feature = "route-grouped",
    feature = "route-groupless",
    feature = "rewrite-grouped",
    feature = "rewrite-groupless",
    feature = "inplace-grouped",
    feature = "inplace-groupless",
    feature = "convert-grouped",
    feature = "rewire-grouped",
    feature = "rewire-groupless",
    feature = "replay-rewrite-grouped",
    feature = "replay-rewrite-groupless",
    feature = "replay-convert-grouped"
))]
use alloc::vec::Vec;

use crate::wire::FieldNumber;

/// One path step.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Segment<'a> {
    /// One hop: records numbered `field` at this level.
    Field(FieldNumber),
    /// Zero or more container crossings, each restricted to the
    /// caller-declared route alphabet (the transcription of "these
    /// fields are messages"). Crossing a LEN in the set is a
    /// message commitment; a group in the set crosses by syntax.
    AnyDepth {
        /// Container fields this wildcard may descend into — a set,
        /// spelled in its one canonical form: strictly ascending
        /// field numbers (admission refuses permutations and
        /// repeats, so equal sets are equal slices).
        descend: &'a [FieldNumber],
    },
}

const _: () = {
    assert!(if cfg!(target_pointer_width = "64") {
        core::mem::size_of::<Segment<'_>>() == 16
    } else {
        // Narrower pointers are bounded by the same ceiling.
        core::mem::size_of::<Segment<'_>>() <= 16
    });
};

/// One element of a fault's promise chain: the container field
/// crossed, and where its record head sits in the whole input.
///
/// # Examples
///
/// ```
/// # #[cfg(feature = "rewrite-groupless")] {
/// use protobuf_edit::path::Segment;
/// use protobuf_edit::rewrite::groupless::rewrite;
/// use protobuf_edit::rewrite::{Action, Rule, RuleSet};
/// use protobuf_edit::{DepthLimit, FieldNumber};
///
/// // A rule routing through field 3 commits its payloads to be
/// // messages; unlawful wire inside is a real fault, and the
/// // trail names the crossings that reached it.
/// let route = [FieldNumber::new(3).unwrap()];
/// let rules = [Rule {
///     path: &[
///         Segment::AnyDepth { descend: &route },
///         Segment::Field(FieldNumber::new(1).unwrap()),
///     ],
///     action: Action::Delete,
/// }];
/// let set = RuleSet::over(&rules).unwrap();
///
/// // LEN f3 wrapping one byte that is no lawful record head.
/// let msg = [0x1A, 0x01, 0xFF];
/// let fault = rewrite(&msg, &set, DepthLimit::REFERENCE).unwrap_err();
/// assert_eq!(fault.at(), 2);
/// assert_eq!(fault.trail().len(), 1);
/// assert_eq!(fault.trail()[0].field().as_inner(), 3);
/// assert_eq!(fault.trail()[0].at(), 0);
/// # }
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Crossing {
    field: FieldNumber,
    at: u32,
}

impl Crossing {
    /// Builds the trail element — the walkers' fault-path mint.
    #[cfg(any(
        feature = "select-grouped",
        feature = "select-groupless",
        feature = "rewrite-grouped",
        feature = "rewrite-groupless",
        feature = "convert-grouped",
        feature = "splice-grouped",
        feature = "splice-groupless"
    ))]
    #[inline]
    pub(crate) const fn new(field: FieldNumber, at: u32) -> Self {
        Self { field, at }
    }

    /// The container's field number.
    #[inline]
    pub const fn field(self) -> FieldNumber {
        self.field
    }

    /// The container record head's whole-input offset.
    #[inline]
    #[must_use]
    pub const fn at(self) -> u32 {
        self.at
    }
}

/// One admitted path's ordinal inside its [`Program`], minted by
/// the admission: a delivered id always names a path the program
/// holds, in authoring order.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[repr(transparent)]
pub struct PathId(u16);

impl PathId {
    /// Mints the id for a matcher-delivered hit (the admission
    /// bounds the domain; the matcher mints inside it).
    #[cfg(any(
        feature = "select-grouped",
        feature = "select-groupless",
        feature = "route-grouped",
        feature = "route-groupless"
    ))]
    #[inline]
    pub(crate) const fn mint(id: u16) -> Self {
        Self(id)
    }

    /// The path's authoring index, widened for table indexing.
    #[inline]
    #[must_use]
    pub const fn index(self) -> u32 {
        #[allow(clippy::as_conversions, reason = "u16 widens losslessly to u32")]
        {
            self.0 as u32
        }
    }
}

/// A compiled selection program: authoring judged once at
/// [`over`](Self::over), jobs downstream are judgment-free.
///
/// The program borrows the caller's path slices — pure data,
/// `Copy`, and `const`-buildable (a `static` program pays its
/// judgment at compile time).
#[must_use]
#[derive(Clone, Copy, Debug)]
pub struct Program<'r> {
    paths: &'r [&'r [Segment<'r>]],
}

impl<'r> Program<'r> {
    /// The admitted path slices, verbatim — the write-fold action
    /// admissions read shapes from the authored program
    /// (`const`-capable, so a static action table pays its
    /// judgment at compile time too).
    #[cfg(any(feature = "rewire-grouped", feature = "rewire-groupless"))]
    pub(crate) const fn segments(&self) -> &'r [&'r [Segment<'r>]] {
        self.paths
    }

    /// Judges the paths' static shape (segments, descend sets,
    /// duplicates) and seals the program.
    ///
    /// # Errors
    ///
    /// [`ProgramError::TooManyPaths`] and
    /// [`ProgramError::PathTooLong`] when either axis leaves the
    /// matcher's state domain; [`ProgramError::EmptyPath`],
    /// [`ProgramError::WildcardTarget`], and
    /// [`ProgramError::EmptyDescendSet`] for degenerate paths;
    /// [`ProgramError::UnsortedDescend`] for a descend set spelled
    /// out of its canonical strictly-ascending order (repeats
    /// included); [`ProgramError::AdjacentWildcards`] for two
    /// wildcards in a row over comparable descend sets — equal, or
    /// one containing the other — a redundant spelling of the
    /// wider one; [`ProgramError::DuplicatePath`] when two paths
    /// spell one selection (aliased delivery is caller-side id
    /// dispatch, not a second path).
    ///
    /// # Examples
    ///
    /// The judgment is `const`-capable: a `static` program pays it
    /// at compile time, and compilation itself is the judge.
    ///
    /// ```
    /// use protobuf_edit::FieldNumber;
    /// use protobuf_edit::path::{Program, Segment};
    ///
    /// const F4: FieldNumber = FieldNumber::new(4).unwrap();
    /// const F7: FieldNumber = FieldNumber::new(7).unwrap();
    /// static ROUTE: [FieldNumber; 1] = [F4];
    /// static PATHS: [&[Segment<'static>]; 2] = [
    ///     &[Segment::Field(F7)],
    ///     &[Segment::AnyDepth { descend: &ROUTE }, Segment::Field(F7)],
    /// ];
    /// static PROGRAM: Program<'static> = match Program::over(&PATHS) {
    ///     Ok(program) => program,
    ///     Err(_) => panic!("the paths are lawful"),
    /// };
    /// ```
    ///
    /// Two paths spelling one selection are refused:
    ///
    /// ```
    /// use protobuf_edit::FieldNumber;
    /// use protobuf_edit::path::{Program, ProgramError, Segment};
    ///
    /// let field = FieldNumber::new(7).unwrap();
    /// let twice: [&[Segment<'_>]; 2] =
    ///     [&[Segment::Field(field)], &[Segment::Field(field)]];
    /// assert_eq!(
    ///     Program::over(&twice).err(),
    ///     Some(ProgramError::DuplicatePath { first: 0, second: 1 })
    /// );
    /// ```
    pub const fn over(paths: &'r [&'r [Segment<'r>]]) -> Result<Self, ProgramError> {
        // Admission for the matcher's (u16, u16) state domain: both
        // indices are minted below this cap, so the narrowing casts
        // at the mint sites are lossless by this proof.
        #[allow(clippy::as_conversions, reason = "u16::MAX widens losslessly for the cap check")]
        if paths.len() > u16::MAX as usize {
            return Err(ProgramError::TooManyPaths { count: paths.len() });
        }
        let mut index = 0;
        while index < paths.len() {
            let at = ix_u32(index);
            #[allow(
                clippy::as_conversions,
                reason = "u16::MAX widens losslessly for the cap check"
            )]
            if paths[index].len() > u16::MAX as usize {
                return Err(ProgramError::PathTooLong { path: at });
            }
            if let Err(breach) = judge_path(paths[index]) {
                return Err(shape_error(breach, at));
            }
            index += 1;
        }
        // The direct quadratic duplicate scan reports the smallest
        // (first, second) pair: outer index ascends, inner index
        // ascends past it. Admission-time cost, never per job.
        let mut first = 0;
        while first < paths.len() {
            let mut second = first + 1;
            while second < paths.len() {
                if paths_equal(paths[first], paths[second]) {
                    return Err(ProgramError::DuplicatePath {
                        first: ix_u32(first),
                        second: ix_u32(second),
                    });
                }
                second += 1;
            }
            first += 1;
        }
        Ok(Self { paths })
    }

    /// The number of admitted paths — the exclusive bound on every
    /// delivered [`PathId::index`], so consumer-side per-path
    /// tables size from it.
    #[inline]
    #[must_use]
    pub const fn len(&self) -> u32 {
        ix_u32(self.paths.len())
    }

    /// True when the program holds no paths — a lawful program
    /// that selects nothing (a job over it still walks and judges
    /// the top layer's wire).
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }
}

/// An authoring error, judged once at [`Program::over`] — distinct
/// from document faults (different reader, different fix).
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProgramError {
    /// More paths than the matcher's state domain (65,535) admits.
    TooManyPaths {
        /// The number of paths offered.
        count: usize,
    },
    /// A path with more segments than the matcher's state domain
    /// (65,535) admits.
    PathTooLong {
        /// The offending path's index.
        path: u32,
    },
    /// A path with no segments selects nothing.
    EmptyPath {
        /// The offending path's index.
        path: u32,
    },
    /// The last segment is a wildcard: no selected field.
    WildcardTarget {
        /// The offending path's index.
        path: u32,
    },
    /// A wildcard with an empty descend set is a degenerate ε.
    EmptyDescendSet {
        /// The offending path's index.
        path: u32,
        /// The offending segment's index.
        segment: u32,
    },
    /// A descend set spelled out of canonical order. The set's one
    /// admitted spelling is strictly ascending field numbers:
    /// membership is order-blind, so admitting permutations (or
    /// repeats) would let two spellings of one set slip past the
    /// duplicate judgment and collide at match time instead.
    UnsortedDescend {
        /// The offending path's index.
        path: u32,
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
        /// The offending path's index.
        path: u32,
        /// The second wildcard's segment index.
        segment: u32,
    },
    /// Two paths spelling one selection: one canonical spelling
    /// per program — aliased delivery is the caller's own id
    /// dispatch, not a second path.
    DuplicatePath {
        /// The first path's index.
        first: u32,
        /// The second path's index.
        second: u32,
    },
}

impl core::fmt::Display for ProgramError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::TooManyPaths { count } => {
                write!(f, "{count} paths exceed the 65,535-path limit")
            }
            Self::PathTooLong { path } => {
                write!(f, "path {path} exceeds the 65,535-segment limit")
            }
            Self::EmptyPath { path } => write!(f, "path {path} has no segments"),
            Self::WildcardTarget { path } => write!(f, "path {path} ends on a wildcard"),
            Self::EmptyDescendSet { path, segment } => {
                write!(f, "path {path} segment {segment} is a wildcard with an empty descend set")
            }
            Self::UnsortedDescend { path, segment } => {
                write!(
                    f,
                    "path {path} segment {segment} spells its descend set out of order \
                     (the canonical spelling is strictly ascending)"
                )
            }
            Self::AdjacentWildcards { path, segment } => {
                write!(
                    f,
                    "path {path} segments {} and {segment} respell one wildcard \
                     (adjacent wildcards over comparable descend sets collapse \
                      into the wider one)",
                    segment - 1
                )
            }
            Self::DuplicatePath { first, second } => {
                write!(f, "paths {first} and {second} spell one selection")
            }
        }
    }
}

impl core::error::Error for ProgramError {}

// ─── the shared shape core (each admission face maps it) ───

/// Widens a matcher-domain ordinal (admitted ≤ 65,535 by the path
/// admissions) into its report form.
#[allow(clippy::as_conversions, reason = "admitted matcher ordinal widens losslessly")]
pub(crate) const fn ix_u32(i: usize) -> u32 {
    i as u32
}

/// A path-shape refusal in segment coordinates; each admission
/// face attaches the offending path's index and maps it onto its
/// own error vocabulary.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum ShapeBreach {
    /// No segments.
    EmptyPath,
    /// The terminal segment is a wildcard.
    WildcardTarget,
    /// A wildcard's descend set is empty.
    EmptyDescendSet {
        /// The offending segment's index.
        segment: u32,
    },
    /// A descend set left its canonical strictly-ascending
    /// spelling.
    UnsortedDescend {
        /// The offending segment's index.
        segment: u32,
    },
    /// Two adjacent wildcards over comparable descend sets.
    AdjacentWildcards {
        /// The second wildcard's segment index.
        segment: u32,
    },
}

/// Maps a shape breach onto this stratum's error vocabulary.
const fn shape_error(breach: ShapeBreach, path: u32) -> ProgramError {
    match breach {
        ShapeBreach::EmptyPath => ProgramError::EmptyPath { path },
        ShapeBreach::WildcardTarget => ProgramError::WildcardTarget { path },
        ShapeBreach::EmptyDescendSet { segment } => ProgramError::EmptyDescendSet { path, segment },
        ShapeBreach::UnsortedDescend { segment } => ProgramError::UnsortedDescend { path, segment },
        ShapeBreach::AdjacentWildcards { segment } => {
            ProgramError::AdjacentWildcards { path, segment }
        }
    }
}

/// Judges one path's static shape — the laws every static machine
/// shares (write-specific laws stay with `RuleSet::over`). Hand-
/// rolled loops keep the judgment `const`-capable.
pub(crate) const fn judge_path(path: &[Segment<'_>]) -> Result<(), ShapeBreach> {
    if path.is_empty() {
        return Err(ShapeBreach::EmptyPath);
    }
    // One pass judges the per-segment wildcard laws: the terminal
    // segment must select a field, and every descend set must be
    // non-empty and spelled in its one canonical form — strictly
    // ascending (which also refuses repeats), so slice equality
    // coincides with set equality and the duplicate judgment
    // cannot be dodged by permutation.
    let terminal = path.len() - 1;
    let mut seg = 0;
    while seg < path.len() {
        if let Segment::AnyDepth { descend } = path[seg] {
            if seg == terminal {
                return Err(ShapeBreach::WildcardTarget);
            }
            if descend.is_empty() {
                return Err(ShapeBreach::EmptyDescendSet { segment: ix_u32(seg) });
            }
            let mut i = 1;
            while i < descend.len() {
                if descend[i - 1].as_inner() >= descend[i].as_inner() {
                    return Err(ShapeBreach::UnsortedDescend { segment: ix_u32(seg) });
                }
                i += 1;
            }
        }
        seg += 1;
    }
    // `B ⊆ A` makes `A*·B*` (either order) collapse to the wider
    // star: a redundant respelling. One canonical spelling per
    // path keeps the duplicate judgment honest; admission-time,
    // never per job.
    let mut seg = 1;
    while seg < path.len() {
        if let (Segment::AnyDepth { descend: a }, Segment::AnyDepth { descend: b }) =
            (path[seg - 1], path[seg])
            && (descend_subset(a, b) || descend_subset(b, a))
        {
            return Err(ShapeBreach::AdjacentWildcards { segment: ix_u32(seg) });
        }
        seg += 1;
    }
    Ok(())
}

/// True when every member of `inner` appears in `outer` (the sets
/// are tiny; the scan is the admission's own cost).
const fn descend_subset(inner: &[FieldNumber], outer: &[FieldNumber]) -> bool {
    let mut i = 0;
    while i < inner.len() {
        let mut found = false;
        let mut j = 0;
        while j < outer.len() {
            if inner[i].as_inner() == outer[j].as_inner() {
                found = true;
                break;
            }
            j += 1;
        }
        if !found {
            return false;
        }
        i += 1;
    }
    true
}

/// Structural path equality, `const`-capable (canonical descend
/// spellings make it coincide with selection equality).
pub(crate) const fn paths_equal(a: &[Segment<'_>], b: &[Segment<'_>]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        let equal = match (a[i], b[i]) {
            (Segment::Field(x), Segment::Field(y)) => x.as_inner() == y.as_inner(),
            (Segment::AnyDepth { descend: x }, Segment::AnyDepth { descend: y }) => {
                descend_equal(x, y)
            }
            _ => false,
        };
        if !equal {
            return false;
        }
        i += 1;
    }
    true
}

/// Element-wise descend-set equality (canonical spellings make it
/// set equality).
const fn descend_equal(a: &[FieldNumber], b: &[FieldNumber]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i].as_inner() != b[i].as_inner() {
            return false;
        }
        i += 1;
    }
    true
}

// ─── the compiled matcher (shared by the static machines) ───

/// A live NFA state: path index, segment index — both minted under
/// the path admissions (≤ 65,535 each).
#[cfg(any(
    feature = "select-grouped",
    feature = "select-groupless",
    feature = "route-grouped",
    feature = "route-groupless",
    feature = "rewrite-grouped",
    feature = "rewrite-groupless",
    feature = "inplace-grouped",
    feature = "inplace-groupless",
    feature = "convert-grouped",
    feature = "rewire-grouped",
    feature = "rewire-groupless",
    feature = "replay-rewrite-grouped",
    feature = "replay-rewrite-groupless",
    feature = "replay-convert-grouped"
))]
type State = (u16, u16);

/// What a record's field number means to the live paths, folded
/// for a writer: two actions on one record are indeterminate, so
/// the double target is quoted, not enumerated.
#[cfg(any(
    feature = "rewrite-grouped",
    feature = "rewrite-groupless",
    feature = "inplace-grouped",
    feature = "inplace-groupless",
    feature = "rewire-grouped",
    feature = "rewire-groupless",
    feature = "replay-rewrite-grouped",
    feature = "replay-rewrite-groupless"
))]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Hits {
    /// No path targets it.
    None,
    /// Exactly one path targets it.
    One(u16),
    /// Two paths target it: the determinism fault, both quoted.
    Conflict(u16, u16),
}

/// Which population a path's terminal serves: an action rule's
/// target (the conflict-folded table the write fold scans), or an
/// insert rule's gap side. Gap terminals compile into their own
/// per-layer table, so the target table — and the fold over it —
/// stays byte-for-byte what it was before insertion existed; only
/// `LANED` program forms can mint non-`Target` lanes at all.
#[cfg(any(
    feature = "select-grouped",
    feature = "select-groupless",
    feature = "route-grouped",
    feature = "route-groupless",
    feature = "rewrite-grouped",
    feature = "rewrite-groupless",
    feature = "inplace-grouped",
    feature = "inplace-groupless",
    feature = "convert-grouped",
    feature = "rewire-grouped",
    feature = "rewire-groupless",
    feature = "replay-rewrite-grouped",
    feature = "replay-rewrite-groupless",
    feature = "replay-convert-grouped"
))]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub(crate) enum Lane {
    /// An action rule's terminal: the conflict-folded population.
    Target,
    /// An insert rule at its container occurrences' interior head.
    #[cfg(any(feature = "rewrite-grouped", feature = "rewrite-groupless"))]
    Head,
    /// An insert rule at its container occurrences' interior tail.
    #[cfg(any(feature = "rewrite-grouped", feature = "rewrite-groupless"))]
    Tail,
}

/// The gap lanes present at one probed field, folded to a bitmask:
/// the walk re-scans (`visit_gaps`) only where a bit is set.
#[cfg(any(feature = "rewrite-grouped", feature = "rewrite-groupless"))]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct GapMask(u8);

#[cfg(any(feature = "rewrite-grouped", feature = "rewrite-groupless"))]
impl GapMask {
    const EMPTY: Self = Self(0);

    /// Folds one gap lane in (`Target` never reaches this: the gap
    /// table holds gap lanes alone).
    const fn add(&mut self, lane: Lane) {
        self.0 |= match lane {
            Lane::Target => 0,
            Lane::Head => 1,
            Lane::Tail => 2,
        };
    }

    /// No gap lane hit at all.
    pub(crate) const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Any `HeadOf` rule hit.
    pub(crate) const fn head(self) -> bool {
        self.0 & 1 != 0
    }

    /// Any `TailOf` rule hit.
    pub(crate) const fn tail(self) -> bool {
        self.0 & 2 != 0
    }
}

/// Per-provider storage for gap terminals (insert anchors),
/// chosen by [`Paths::Gaps`]: the unit store for programs that
/// cannot carry insert rules — zero bytes, zero code, so the read
/// machines and rewire pay literally nothing — and the real
/// per-layer table for rule sets. The store keeps its own layer
/// marks, so the shared matcher's `Marks` and level stack stay
/// exactly what they were before insertion existed.
#[cfg(any(
    feature = "select-grouped",
    feature = "select-groupless",
    feature = "route-grouped",
    feature = "route-groupless",
    feature = "rewrite-grouped",
    feature = "rewrite-groupless",
    feature = "inplace-grouped",
    feature = "inplace-groupless",
    feature = "convert-grouped",
    feature = "rewire-grouped",
    feature = "rewire-groupless",
    feature = "replay-rewrite-grouped",
    feature = "replay-rewrite-groupless",
    feature = "replay-convert-grouped"
))]
pub(crate) trait GapStore: Default {
    /// Records whether the provider holds any gap rule at all.
    fn set_any(&mut self, any: bool);
    /// Whether any gap rule exists (the walks' one per-job flag).
    #[cfg(any(feature = "rewrite-grouped", feature = "rewrite-groupless"))]
    fn any(&self) -> bool;
    /// One gap terminal lands in the current layer.
    fn push(&mut self, field: FieldNumber, path: u16, lane: Lane);
    /// A layer opens: snapshot the mark.
    fn enter(&mut self);
    /// A layer closes: truncate to the snapshot.
    fn exit(&mut self);
    /// The gap lanes hitting `field` in the current layer.
    #[cfg(any(feature = "rewrite-grouped", feature = "rewrite-groupless"))]
    fn probe(&self, field: FieldNumber) -> GapMask;
    /// Every rule of `lane`'s kind hitting `field` in the current
    /// layer, ascending, converging states collapsed.
    #[cfg(any(feature = "rewrite-grouped", feature = "rewrite-groupless"))]
    fn visit(&self, field: FieldNumber, lane: Lane, visit: impl FnMut(u16));
    /// The lowest-indexed gap rule hitting `field` in the current
    /// layer.
    #[cfg(any(feature = "rewrite-grouped", feature = "rewrite-groupless"))]
    fn first(&self, field: FieldNumber) -> Option<u16>;
}

/// The unit store: unlaned programs carry no gap machinery at all.
#[cfg(any(
    feature = "select-grouped",
    feature = "select-groupless",
    feature = "route-grouped",
    feature = "route-groupless",
    feature = "rewrite-grouped",
    feature = "rewrite-groupless",
    feature = "inplace-grouped",
    feature = "inplace-groupless",
    feature = "convert-grouped",
    feature = "rewire-grouped",
    feature = "rewire-groupless",
    feature = "replay-rewrite-grouped",
    feature = "replay-rewrite-groupless",
    feature = "replay-convert-grouped"
))]
impl GapStore for () {
    #[inline]
    fn set_any(&mut self, _any: bool) {}
    #[cfg(any(feature = "rewrite-grouped", feature = "rewrite-groupless"))]
    #[inline]
    fn any(&self) -> bool {
        false
    }
    #[inline]
    fn push(&mut self, _field: FieldNumber, _path: u16, _lane: Lane) {}
    #[inline]
    fn enter(&mut self) {}
    #[inline]
    fn exit(&mut self) {}
    #[cfg(any(feature = "rewrite-grouped", feature = "rewrite-groupless"))]
    #[inline]
    fn probe(&self, _field: FieldNumber) -> GapMask {
        GapMask::EMPTY
    }
    #[cfg(any(feature = "rewrite-grouped", feature = "rewrite-groupless"))]
    #[inline]
    fn visit(&self, _field: FieldNumber, _lane: Lane, _visit: impl FnMut(u16)) {}
    #[cfg(any(feature = "rewrite-grouped", feature = "rewrite-groupless"))]
    #[inline]
    fn first(&self, _field: FieldNumber) -> Option<u16> {
        None
    }
}

/// The real gap table: entries and layer marks, self-contained —
/// only providers that can carry insert rules instantiate it.
#[cfg(any(feature = "rewrite-grouped", feature = "rewrite-groupless"))]
#[derive(Default)]
pub(crate) struct GapTable {
    /// Gap terminals, all layers concatenated (the target table's
    /// own layer-order invariant, gap lanes alone).
    entries: Vec<(FieldNumber, u16, Lane)>,
    /// Suspended layer marks, innermost last.
    marks: Vec<usize>,
    /// The current layer's start mark.
    layer: usize,
    /// Whether any gap rule exists at all.
    any: bool,
}

#[cfg(any(feature = "rewrite-grouped", feature = "rewrite-groupless"))]
impl GapStore for GapTable {
    fn set_any(&mut self, any: bool) {
        self.any = any;
    }

    #[inline]
    fn any(&self) -> bool {
        self.any
    }

    fn push(&mut self, field: FieldNumber, path: u16, lane: Lane) {
        self.entries.push((field, path, lane));
    }

    fn enter(&mut self) {
        // Mark maintenance exists for gap-bearing sets alone: with
        // no gap rule the table is permanently empty and every
        // probe sits behind the same flag, so insert-free jobs pay
        // one predicted branch per descent here and nothing else.
        if self.any {
            self.marks.push(self.layer);
            self.layer = self.entries.len();
        }
    }

    fn exit(&mut self) {
        if self.any {
            self.entries.truncate(self.layer);
            debug_assert!(!self.marks.is_empty(), "descents and exits pair");
            // SAFETY: paired with `enter` — the matcher exits only
            // layers it entered.
            self.layer = unsafe { self.marks.pop().unwrap_unchecked() };
        }
    }

    fn probe(&self, field: FieldNumber) -> GapMask {
        let mut gaps = GapMask::EMPTY;
        // SAFETY: `layer` is a snapshot of `entries.len()` taken at
        // layer entry (zero at construction), and the table never
        // shrinks below a live snapshot — pushes only grow it, and
        // `exit` truncates to the innermost snapshot before
        // restoring the parent's.
        for &(f, _, lane) in unsafe { self.entries.get_unchecked(self.layer..) } {
            if f == field {
                gaps.add(lane);
            }
        }
        gaps
    }

    fn visit(&self, field: FieldNumber, lane: Lane, mut visit: impl FnMut(u16)) {
        let mut last: Option<u16> = None;
        // SAFETY: as `probe` — the range start is a live layer
        // snapshot.
        for &(f, id, l) in unsafe { self.entries.get_unchecked(self.layer..) } {
            if f == field && l == lane && last != Some(id) {
                last = Some(id);
                visit(id);
            }
        }
    }

    fn first(&self, field: FieldNumber) -> Option<u16> {
        // SAFETY: as `probe` — the range start is a live layer
        // snapshot.
        for &(f, id, _) in unsafe { self.entries.get_unchecked(self.layer..) } {
            if f == field {
                return Some(id);
            }
        }
        None
    }
}

/// One layer's start marks into the matcher's three flat tables.
#[cfg(any(
    feature = "select-grouped",
    feature = "select-groupless",
    feature = "route-grouped",
    feature = "route-groupless",
    feature = "rewrite-grouped",
    feature = "rewrite-groupless",
    feature = "inplace-grouped",
    feature = "inplace-groupless",
    feature = "convert-grouped",
    feature = "rewire-grouped",
    feature = "rewire-groupless",
    feature = "replay-rewrite-grouped",
    feature = "replay-rewrite-groupless",
    feature = "replay-convert-grouped"
))]
#[derive(Clone, Copy)]
struct Marks {
    targets: usize,
    stages: usize,
    wilds: usize,
}

/// Path lookup for the matcher, one implementation per admitted
/// program form (`rewrite`'s rule set stores paths inside rules,
/// [`Program`] stores bare slices — no common slice exists without
/// allocation, so the matcher monomorphizes over the lookup).
///
/// The admission contract every implementor carries: at most
/// 65,535 paths, at most 65,535 segments per path (the matcher's
/// `(u16, u16)` state domain), every terminal segment a `Field`,
/// every descend set non-empty and strictly ascending, and every
/// path non-empty — except that a `LANED` implementor may hold
/// empty paths (root-gap insert anchors), which live outside the
/// NFA: the flatten skips them, so no layer table ever holds
/// their entries. The matcher mints every id it passes to
/// [`path`](Self::path) from `0..count()`.
#[cfg(any(
    feature = "select-grouped",
    feature = "select-groupless",
    feature = "route-grouped",
    feature = "route-groupless",
    feature = "rewrite-grouped",
    feature = "rewrite-groupless",
    feature = "inplace-grouped",
    feature = "inplace-groupless",
    feature = "convert-grouped",
    feature = "rewire-grouped",
    feature = "rewire-groupless",
    feature = "replay-rewrite-grouped",
    feature = "replay-rewrite-groupless",
    feature = "replay-convert-grouped"
))]
pub(crate) trait Paths<'r> {
    /// Whether this program form can carry non-`Target` lanes at
    /// all. `false` (the default) folds every lane fetch away in
    /// the monomorphization — read programs and rewire actions pay
    /// nothing for the insert machinery.
    const LANED: bool = false;
    /// The gap-terminal store this program form warrants: the unit
    /// store (zero bytes, zero code) unless the implementor can
    /// carry insert rules.
    type Gaps: GapStore;
    /// How many paths the program holds (admitted ≤ 65,535).
    fn count(&self) -> u16;
    /// The path at `id` — called only with ids below
    /// [`count`](Self::count), the matcher's own mint range.
    fn path(&self, id: u16) -> &'r [Segment<'r>];
    /// The lane of the path's terminal entries (`Target` unless
    /// the implementor carries insert rules).
    #[inline]
    fn lane(&self, _id: u16) -> Lane {
        Lane::Target
    }
}

#[cfg(any(
    feature = "select-grouped",
    feature = "select-groupless",
    feature = "route-grouped",
    feature = "route-groupless",
    feature = "rewrite-grouped",
    feature = "rewrite-groupless",
    feature = "inplace-grouped",
    feature = "inplace-groupless",
    feature = "convert-grouped",
    feature = "rewire-grouped",
    feature = "rewire-groupless",
    feature = "replay-convert-grouped"
))]
impl<'r> Paths<'r> for Program<'r> {
    // Programs carry no insert rules: the unit store keeps every
    // program-backed matcher free of gap machinery.
    type Gaps = ();

    #[inline]
    fn count(&self) -> u16 {
        // Lossless: `over` admitted the count to u16.
        #[allow(clippy::as_conversions, reason = "over admitted the count to u16")]
        {
            self.paths.len() as u16
        }
    }

    #[inline]
    fn path(&self, id: u16) -> &'r [Segment<'r>] {
        debug_assert!(usize::from(id) < self.paths.len(), "ids are minted below count()");
        // SAFETY: the matcher mints every id below `count()` (the
        // trait contract), and `count()` is this slice's length.
        unsafe { self.paths.get_unchecked(usize::from(id)) }
    }
}

/// The path NFA, compiled layer by layer over a [`Paths`]
/// provider. Layer entry flattens the live states' ε-chains (each
/// a wildcard run ending at its first `Field` — admission pins
/// every terminal there) into three flat tables:
///
/// - `targets`: action terminals → the owning path, in layer order
///   — non-decreasing path ids with equal ids adjacent (the root
///   flatten enumerates ids ascending, `commit_descent` sorts the
///   staged states, and each state lands at most one entry), the
///   invariant every verdict fold leans on (insert anchors compile
///   into their own gap table, same order, write side only);
/// - `stages`: non-terminal fields → the child state past them;
/// - `wilds`: wildcard self-loops, their descend-set membership
///   judged per probe (the one field-dependent question a layer
///   cannot pre-answer).
///
/// The probe faces scan tables instead of walking path slices:
/// segment decoding and path indexing are paid once per layer, and
/// a layer changes only at container boundaries while records
/// arrive per field. The tables stack — a descent appends, an
/// ascent truncates — so the
/// parent is restored by moving three marks, reusing buffer
/// capacity across the walk. Dialect-orthogonal: it consumes field
/// numbers and container entry/exit, never wire kinds. The two
/// verdict folds split by intent: the write fold ([`Hits`]) quotes
/// double targets, the read fold (`visit_targets`) enumerates
/// every hit.
#[cfg(any(
    feature = "select-grouped",
    feature = "select-groupless",
    feature = "route-grouped",
    feature = "route-groupless",
    feature = "rewrite-grouped",
    feature = "rewrite-groupless",
    feature = "inplace-grouped",
    feature = "inplace-groupless",
    feature = "convert-grouped",
    feature = "rewire-grouped",
    feature = "rewire-groupless",
    feature = "replay-rewrite-grouped",
    feature = "replay-rewrite-groupless",
    feature = "replay-convert-grouped"
))]
pub(crate) struct Matcher<'r, P: Paths<'r>> {
    paths: P,
    /// Terminal entries of action rules, all layers concatenated —
    /// gap terminals live in the provider-chosen store, so this
    /// table (and the write fold over it) is untouched by
    /// insertion.
    targets: Vec<(FieldNumber, u16)>,
    /// Non-terminal `Field` entries, all layers concatenated.
    stages: Vec<(FieldNumber, State)>,
    /// Wildcard self-loops, all layers concatenated.
    wilds: Vec<(&'r [FieldNumber], State)>,
    /// Gap terminals (insert anchors): the unit store for unlaned
    /// programs, the real table for rule sets.
    gaps: P::Gaps,
    /// The current layer's start marks.
    layer: Marks,
    /// Suspended ancestor marks, innermost last.
    levels: Vec<Marks>,
    /// Child states staged by the last route probe, committed
    /// (sorted, deduplicated, flattened) by `commit_descent`.
    staged: Vec<State>,
}

/// Flattens one live state's ε-chain into the layer tables: every
/// wildcard on the run self-loops, and the chain's first `Field`
/// lands as a target (terminal) or a stage (interior).
#[cfg(any(
    feature = "select-grouped",
    feature = "select-groupless",
    feature = "route-grouped",
    feature = "route-groupless",
    feature = "rewrite-grouped",
    feature = "rewrite-groupless",
    feature = "inplace-grouped",
    feature = "inplace-groupless",
    feature = "convert-grouped",
    feature = "rewire-grouped",
    feature = "rewire-groupless",
    feature = "replay-rewrite-grouped",
    feature = "replay-rewrite-groupless",
    feature = "replay-convert-grouped"
))]
fn flatten<'r, P: Paths<'r>>(
    paths: &P,
    (path, seg): State,
    targets: &mut Vec<(FieldNumber, u16)>,
    stages: &mut Vec<(FieldNumber, State)>,
    wilds: &mut Vec<(&'r [FieldNumber], State)>,
    gaps: &mut P::Gaps,
) {
    // `path` and `seg` are minted below `count()` and the path's
    // length (the admission contract plus the mint sites below).
    let steps = paths.path(path);
    if P::LANED && steps.is_empty() {
        // A laned program may hold empty anchor paths (root-gap
        // insert rules): they live outside the NFA — the walks
        // fire them at the root's own events — so the layer
        // tables hold nothing for them. Unlaned programs admit no
        // empty path, and this branch folds away.
        return;
    }
    let mut i = usize::from(seg);
    loop {
        // SAFETY: `i` starts at a minted in-bounds segment index
        // and the loop returns at its chain's first `Field`, which
        // exists — admission pinned every path's terminal segment
        // to a `Field` — so `i` never passes the end.
        match unsafe { *steps.get_unchecked(i) } {
            Segment::Field(field) => {
                if i + 1 == steps.len() {
                    // Gap terminals compile into the provider's
                    // own store (laned providers alone can mint
                    // them), so the write fold's table stays what
                    // it was.
                    if P::LANED {
                        let lane = paths.lane(path);
                        if lane != Lane::Target {
                            gaps.push(field, path, lane);
                            return;
                        }
                    }
                    targets.push((field, path));
                } else {
                    // Lossless: admission capped path lengths.
                    #[allow(
                        clippy::as_conversions,
                        reason = "admission capped path lengths to u16"
                    )]
                    stages.push((field, (path, i as u16 + 1)));
                }
                return;
            }
            Segment::AnyDepth { descend } => {
                // Lossless: admission capped path lengths.
                #[allow(clippy::as_conversions, reason = "admission capped path lengths to u16")]
                wilds.push((descend, (path, i as u16)));
                i += 1;
            }
        }
    }
}

#[cfg(any(
    feature = "select-grouped",
    feature = "select-groupless",
    feature = "route-grouped",
    feature = "route-groupless",
    feature = "rewrite-grouped",
    feature = "rewrite-groupless",
    feature = "inplace-grouped",
    feature = "inplace-groupless",
    feature = "convert-grouped",
    feature = "rewire-grouped",
    feature = "rewire-groupless",
    feature = "replay-rewrite-grouped",
    feature = "replay-rewrite-groupless",
    feature = "replay-convert-grouped"
))]
impl<'r, P: Paths<'r>> Matcher<'r, P> {
    /// Compiles the root layer: every path live at its head.
    pub(crate) fn new(paths: P) -> Self {
        let (mut targets, mut stages, mut wilds) = (Vec::new(), Vec::new(), Vec::new());
        let mut gaps = P::Gaps::default();
        let mut gapped = false;
        for id in 0..paths.count() {
            flatten(&paths, (id, 0), &mut targets, &mut stages, &mut wilds, &mut gaps);
            if P::LANED && paths.lane(id) != Lane::Target {
                gapped = true;
            }
        }
        gaps.set_any(gapped);
        Self {
            paths,
            targets,
            stages,
            wilds,
            gaps,
            layer: Marks { targets: 0, stages: 0, wilds: 0 },
            levels: Vec::new(),
            staged: Vec::new(),
        }
    }

    /// Whether the program holds any insert rule at all — computed
    /// once at construction, the walks' one per-container-event
    /// test: a `false` here keeps every gap scan off the hot path,
    /// so insert-free jobs pay a flag read and nothing else.
    #[cfg(any(feature = "rewrite-grouped", feature = "rewrite-groupless"))]
    #[inline]
    pub(crate) fn gapped(&self) -> bool {
        self.gaps.any()
    }

    /// Judges `field` as a leaf under the write fold: the target
    /// verdict from the terminal table alone. Insert anchors never
    /// enter this table or this fold — their gap sides are
    /// [`probe_gaps`](Self::probe_gaps)' separate question over
    /// the gap table, asked only when [`gapped`](Self::gapped)
    /// says any exist. Staging is untouched — leaves never
    /// descend, so walkers pair
    /// [`commit_descent`](Self::commit_descent) only with the
    /// route probes.
    #[cfg(any(
        feature = "rewrite-grouped",
        feature = "rewrite-groupless",
        feature = "inplace-grouped",
        feature = "inplace-groupless",
        feature = "rewire-grouped",
        feature = "rewire-groupless",
        feature = "replay-rewrite-grouped",
        feature = "replay-rewrite-groupless"
    ))]
    #[inline]
    pub(crate) fn probe_target(&self, field: FieldNumber) -> Hits {
        let mut found: Option<u16> = None;
        // SAFETY: `layer.targets` is a snapshot of `targets.len()`
        // taken at layer entry (zero at construction), and the
        // table never shrinks below a live snapshot — pushes only
        // grow it, and `exit` truncates to the innermost snapshot
        // before restoring the parent's — so the range start is in
        // bounds.
        for &(f, path) in unsafe { self.targets.get_unchecked(self.layer.targets..) } {
            if f == field {
                match found {
                    None => found = Some(path),
                    // Two states of one path can share a terminal
                    // (converging wildcard runs): not a conflict.
                    Some(first) if first != path => return Hits::Conflict(first, path),
                    Some(_) => {}
                }
            }
        }
        found.map_or(Hits::None, Hits::One)
    }

    /// Judges `field` as a container head under the write fold:
    /// the target verdict, and whether any path continues into it
    /// (the staged child states, committed by
    /// [`commit_descent`](Self::commit_descent), are non-empty).
    #[cfg(any(
        feature = "rewrite-grouped",
        feature = "rewrite-groupless",
        feature = "inplace-grouped",
        feature = "inplace-groupless",
        feature = "rewire-grouped",
        feature = "rewire-groupless",
        feature = "replay-rewrite-grouped",
        feature = "replay-rewrite-groupless"
    ))]
    pub(crate) fn probe(&mut self, field: FieldNumber) -> (Hits, bool) {
        let hits = self.probe_target(field);
        if let Hits::Conflict(..) = hits {
            return (hits, false);
        }
        (hits, self.probe_routes(field))
    }

    /// The gap lanes hitting `field` in this layer, folded to a
    /// mask over the gap store — the insert-bearing sets' own
    /// scan, asked behind [`gapped`](Self::gapped) so insert-free
    /// jobs never run it.
    #[cfg(any(feature = "rewrite-grouped", feature = "rewrite-groupless"))]
    pub(crate) fn probe_gaps(&self, field: FieldNumber) -> GapMask {
        self.gaps.probe(field)
    }

    /// Feeds every insert rule of `lane`'s kind hitting `field` in
    /// this layer to `visit`, ascending, converging states
    /// collapsed — the gap enumeration behind a set mask bit
    /// (rule-index order is the layer-order invariant's table
    /// order).
    #[cfg(any(feature = "rewrite-grouped", feature = "rewrite-groupless"))]
    pub(crate) fn visit_gaps(&self, field: FieldNumber, lane: Lane, visit: impl FnMut(u16)) {
        self.gaps.visit(field, lane, visit);
    }

    /// The lowest-indexed interior-gap rule hitting `field` in
    /// this layer — the rule a scalar occurrence's `KindMismatch`
    /// quotes. `None` when no gap lane hit.
    #[cfg(any(feature = "rewrite-grouped", feature = "rewrite-groupless"))]
    pub(crate) fn first_interior_gap(&self, field: FieldNumber) -> Option<u16> {
        self.gaps.first(field)
    }

    /// Judges `field` as a target under the single-action fold:
    /// the first path targeting it in this layer (the lowest id —
    /// the layer-order invariant makes table order id order), or
    /// `None`. No conflict verdict exists here: this fold serves
    /// machines whose one action makes converging paths agree by
    /// construction, so any hit means that action, once.
    #[cfg(any(feature = "convert-grouped", feature = "replay-convert-grouped"))]
    #[inline]
    pub(crate) fn first_target(&self, field: FieldNumber) -> Option<u16> {
        // SAFETY: `layer.targets` is a snapshot of `targets.len()`
        // taken at layer entry (zero at construction), and the
        // table never shrinks below a live snapshot — pushes only
        // grow it, and `exit` truncates to the innermost snapshot
        // before restoring the parent's — so the range start is in
        // bounds.
        for &(f, path) in unsafe { self.targets.get_unchecked(self.layer.targets..) } {
            if f == field {
                return Some(path);
            }
        }
        None
    }

    /// Feeds every path id targeting `field` in this layer to
    /// `visit`, ascending, converging states collapsed — the read
    /// fold. It leans on the layer-order invariant (type doc):
    /// target entries carry non-decreasing ids with equal ids
    /// adjacent, so one register deduplicates and the delivery
    /// order is the authoring order.
    #[cfg(any(
        feature = "select-grouped",
        feature = "select-groupless",
        feature = "route-grouped",
        feature = "route-groupless"
    ))]
    #[inline]
    pub(crate) fn visit_targets(&self, field: FieldNumber, mut visit: impl FnMut(u16)) {
        let mut last: Option<u16> = None;
        // SAFETY: `layer.targets` is a snapshot of `targets.len()`
        // taken at layer entry (zero at construction), and the
        // table never shrinks below a live snapshot — pushes only
        // grow it, and `exit` truncates to the innermost snapshot
        // before restoring the parent's — so the range start is in
        // bounds.
        for &(f, id) in unsafe { self.targets.get_unchecked(self.layer.targets..) } {
            if f == field && last != Some(id) {
                last = Some(id);
                visit(id);
            }
        }
    }

    /// Stages the child states of every path continuing into
    /// `field` — the route question alone, shared by both folds;
    /// `true` when anything staged. A following
    /// [`commit_descent`](Self::commit_descent) compiles the
    /// staged layer.
    pub(crate) fn probe_routes(&mut self, field: FieldNumber) -> bool {
        self.staged.clear();
        // SAFETY: both marks are layer-entry snapshots of their
        // tables' lengths; see `probe_target`.
        for &(f, state) in unsafe { self.stages.get_unchecked(self.layer.stages..) } {
            if f == field {
                self.staged.push(state);
            }
        }
        for &(descend, state) in unsafe { self.wilds.get_unchecked(self.layer.wilds..) } {
            // A manual scan: descend sets are tiny, and this spells
            // exactly the compares wanted; how it weighs against
            // the iterator's `contains` machinery is a question for
            // the performance epoch's instruments, not settled here.
            let mut j = 0;
            while j < descend.len() {
                if descend[j] == field {
                    self.staged.push(state);
                    break;
                }
                j += 1;
            }
        }
        !self.staged.is_empty()
    }

    /// Enters the container the immediately preceding route probe
    /// judged: the staged states, deduplicated, compile into the
    /// child layer's tables.
    pub(crate) fn commit_descent(&mut self) {
        // Converging states arrive as duplicates; collapsing them
        // here bounds every layer by the reachable state set.
        self.staged.sort_unstable();
        self.staged.dedup();
        self.levels.push(self.layer);
        self.layer = Marks {
            targets: self.targets.len(),
            stages: self.stages.len(),
            wilds: self.wilds.len(),
        };
        self.gaps.enter();
        for &state in &self.staged {
            flatten(
                &self.paths,
                state,
                &mut self.targets,
                &mut self.stages,
                &mut self.wilds,
                &mut self.gaps,
            );
        }
    }

    /// Leaves a container: truncates the child layer's table
    /// entries and restores the parent's marks.
    pub(crate) fn exit(&mut self) {
        self.targets.truncate(self.layer.targets);
        self.stages.truncate(self.layer.stages);
        self.wilds.truncate(self.layer.wilds);
        self.gaps.exit();
        debug_assert!(!self.levels.is_empty(), "descents and exits pair");
        // SAFETY: paired with `commit_descent` — the walkers exit
        // only containers they entered, and the cursor verifies
        // group pairing before delivering an exit.
        self.layer = unsafe { self.levels.pop().unwrap_unchecked() };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(n: u32) -> FieldNumber {
        FieldNumber::new(n).unwrap()
    }

    #[test]
    fn state_domain_admission_caps_paths_and_segment_counts() {
        // One over the (u16, u16) matcher state domain on each axis.
        let long_path = alloc::vec![Segment::Field(f(1)); (u16::MAX as usize) + 1];
        let one: [&[Segment<'_>]; 1] = [&long_path];
        assert_eq!(Program::over(&one).err(), Some(ProgramError::PathTooLong { path: 0 }));
        let many = alloc::vec![&long_path[..1]; (u16::MAX as usize) + 1];
        assert_eq!(
            Program::over(&many).err(),
            Some(ProgramError::TooManyPaths { count: (u16::MAX as usize) + 1 })
        );
    }

    #[test]
    fn authoring_errors_are_judged_at_construction() {
        assert_eq!(Program::over(&[&[]]).err(), Some(ProgramError::EmptyPath { path: 0 }));
        assert_eq!(
            Program::over(&[&[Segment::AnyDepth { descend: &[] }]]).err(),
            Some(ProgramError::WildcardTarget { path: 0 })
        );
        let one = f(1);
        assert_eq!(
            Program::over(&[&[Segment::AnyDepth { descend: &[] }, Segment::Field(one)]]).err(),
            Some(ProgramError::EmptyDescendSet { path: 0, segment: 0 })
        );
        // The descend set has one canonical spelling: strictly
        // ascending. A permutation and a repeat are both refused at
        // authoring, so set-equal paths cannot dodge the duplicate
        // judgment below by respelling.
        let (two, seven) = (f(2), f(7));
        assert_eq!(
            Program::over(&[&[Segment::AnyDepth { descend: &[two, one] }, Segment::Field(seven)]])
                .err(),
            Some(ProgramError::UnsortedDescend { path: 0, segment: 0 })
        );
        assert_eq!(
            Program::over(&[&[Segment::AnyDepth { descend: &[one, one] }, Segment::Field(seven)]])
                .err(),
            Some(ProgramError::UnsortedDescend { path: 0, segment: 0 })
        );
        // Two adjacent wildcards over comparable sets are one
        // wildcard respelled: refused at authoring, so the pair
        // cannot dodge the duplicate judgment below by respelling.
        assert_eq!(
            Program::over(&[&[
                Segment::AnyDepth { descend: &[one, two] },
                Segment::AnyDepth { descend: &[one, two] },
                Segment::Field(seven)
            ]])
            .err(),
            Some(ProgramError::AdjacentWildcards { path: 0, segment: 1 })
        );
        // A subset pair is the same tautology (B ⊆ A folds into
        // A*): refused like the equal pair.
        assert_eq!(
            Program::over(&[&[
                Segment::AnyDepth { descend: &[one] },
                Segment::AnyDepth { descend: &[one, two] },
                Segment::Field(seven)
            ]])
            .err(),
            Some(ProgramError::AdjacentWildcards { path: 0, segment: 1 })
        );
        // Incomparable sets compose for real and stay admitted.
        assert!(
            Program::over(&[&[
                Segment::AnyDepth { descend: &[one] },
                Segment::AnyDepth { descend: &[two] },
                Segment::Field(seven)
            ]])
            .is_ok()
        );
        // Canonical spellings admit — and being canonical, two
        // set-equal wildcard paths are slice-equal and land in the
        // duplicate judgment.
        let wild: &[Segment<'_>] =
            &[Segment::AnyDepth { descend: &[one, two] }, Segment::Field(seven)];
        assert_eq!(
            Program::over(&[wild, wild]).err(),
            Some(ProgramError::DuplicatePath { first: 0, second: 1 })
        );
    }

    #[test]
    fn the_duplicate_scan_reports_the_smallest_pair() {
        // Two duplicated paths interleaved with fillers: the direct
        // quadratic scan must quote the lexicographically smallest
        // (first, second) pair — the verdict the retired sorted
        // scan pinned.
        let p1: &[Segment<'_>] = &[Segment::Field(f(7))];
        let p2: &[Segment<'_>] = &[Segment::Field(f(3))];
        let fillers: alloc::vec::Vec<[Segment<'_>; 1]> =
            (100..116).map(|n| [Segment::Field(f(n))]).collect();
        let mut paths: alloc::vec::Vec<&[Segment<'_>]> =
            fillers.iter().map(<[Segment<'_>; 1]>::as_slice).collect();
        paths.insert(2, p1);
        paths.insert(5, p2);
        paths.insert(9, p1);
        paths.push(p2);
        assert_eq!(
            Program::over(&paths).err(),
            Some(ProgramError::DuplicatePath { first: 2, second: 9 })
        );
    }

    #[cfg(any(feature = "rewrite-grouped", feature = "rewrite-groupless"))]
    #[test]
    fn the_matcher_walks_wildcards_with_self_loops_and_epsilon() {
        let route = [f(1)];
        let paths: [&[Segment<'_>]; 1] =
            [&[Segment::AnyDepth { descend: &route }, Segment::Field(f(2))]];
        let program = Program::over(&paths).unwrap();
        let mut m = Matcher::new(program);
        // Zero crossings: field 2 at top level is a target (ε), and
        // nothing routes into it.
        assert_eq!(
            {
                let (hits, routed) = m.probe(f(2));
                (hits, routed)
            },
            (Hits::One(0), false)
        );
        // Field 1 is in the descend alphabet, not a target.
        assert_eq!(
            {
                let (hits, routed) = m.probe(f(1));
                (hits, routed)
            },
            (Hits::None, true)
        );
        assert_eq!(
            {
                let (hits, routed) = m.probe(f(3));
                (hits, routed)
            },
            (Hits::None, false)
        );
        m.probe(f(1));
        m.commit_descent();
        assert_eq!(
            {
                let (hits, routed) = m.probe(f(2));
                (hits, routed)
            },
            (Hits::One(0), false)
        );
        m.probe(f(1));
        m.commit_descent();
        assert_eq!(
            {
                let (hits, routed) = m.probe(f(2));
                (hits, routed)
            },
            (Hits::One(0), false)
        );
        m.exit();
        m.exit();
        assert_eq!(
            {
                let (hits, routed) = m.probe(f(2));
                (hits, routed)
            },
            (Hits::One(0), false)
        );
    }

    #[cfg(any(feature = "rewrite-grouped", feature = "rewrite-groupless"))]
    #[test]
    fn converging_wildcard_states_deduplicate_per_layer() {
        // Two stacked wildcards over different alphabets sharing a
        // member (identical adjacent alphabets are refused at
        // authoring as one wildcard respelled): descending through
        // the shared member keeps both live, and from the second
        // level down the deeper state is staged by both parents —
        // the layer must stay a two-state fixed point, not compound.
        let outer = [f(1), f(2)];
        let inner = [f(1), f(3)];
        let paths: [&[Segment<'_>]; 1] = [&[
            Segment::AnyDepth { descend: &outer },
            Segment::AnyDepth { descend: &inner },
            Segment::Field(f(4)),
        ]];
        let program = Program::over(&paths).unwrap();
        let mut m = Matcher::new(program);
        for _ in 0..4 {
            assert_eq!(
                {
                    let (hits, routed) = m.probe(f(1));
                    (hits, routed)
                },
                (Hits::None, true)
            );
            m.commit_descent();
            // `commit_descent` leaves the deduplicated layer states
            // in `staged`; the reachable set here is two states.
            assert!(m.staged.len() <= 2, "converging states collapse");
            assert!(
                m.wilds.len() - m.layer.wilds <= 3 && m.targets.len() - m.layer.targets <= 2,
                "layer tables reach a fixed point"
            );
        }
        // Both live states ε-reach the same target: one path, no
        // self-conflict.
        assert_eq!(
            {
                let (hits, routed) = m.probe(f(4));
                (hits, routed)
            },
            (Hits::One(0), false)
        );
    }

    #[cfg(any(feature = "select-grouped", feature = "select-groupless"))]
    #[test]
    fn the_read_fold_enumerates_ascending_and_collapses_convergence() {
        // Two paths target f7 — the write fold's Conflict shape —
        // and the read fold enumerates both, ascending.
        let route = [f(1)];
        let paths: [&[Segment<'_>]; 2] = [
            &[Segment::Field(f(7))],
            &[Segment::AnyDepth { descend: &route }, Segment::Field(f(7))],
        ];
        let program = Program::over(&paths).unwrap();
        let m = Matcher::new(program);
        let mut ids = alloc::vec::Vec::new();
        m.visit_targets(f(7), |id| ids.push(id));
        assert_eq!(ids, [0, 1]);

        // Stacked wildcards sharing member f1 reach one terminal
        // through two live states after a few descents — the fold
        // still delivers the path once.
        let outer = [f(1), f(2)];
        let inner = [f(1), f(3)];
        let paths: [&[Segment<'_>]; 1] = [&[
            Segment::AnyDepth { descend: &outer },
            Segment::AnyDepth { descend: &inner },
            Segment::Field(f(4)),
        ]];
        let program = Program::over(&paths).unwrap();
        let mut m = Matcher::new(program);
        for _ in 0..3 {
            assert!(m.probe_routes(f(1)));
            m.commit_descent();
        }
        let mut ids = alloc::vec::Vec::new();
        m.visit_targets(f(4), |id| ids.push(id));
        assert_eq!(ids, [0], "converging states collapse to one delivery");
    }

    #[cfg(any(feature = "rewrite-grouped", feature = "rewrite-groupless"))]
    #[test]
    fn double_targets_are_conflicts_under_the_write_fold() {
        let route = [f(1)];
        let paths: [&[Segment<'_>]; 2] = [
            &[Segment::Field(f(7))],
            &[Segment::AnyDepth { descend: &route }, Segment::Field(f(7))],
        ];
        let program = Program::over(&paths).unwrap();
        let mut m = Matcher::new(program);
        assert_eq!(m.probe(f(7)).0, Hits::Conflict(0, 1));
    }

    #[cfg(any(feature = "rewrite-grouped", feature = "rewrite-groupless"))]
    #[test]
    fn program_and_rule_set_agree_on_every_shared_shape_verdict() {
        use crate::rewrite::{Action, Rule, RuleError, RuleSet};

        // A seeded generator over the shape space: lawful paths and
        // every breach class, judged by both admission faces — the
        // verdicts must agree modulo vocabulary.
        struct Rng(u64);
        impl Rng {
            const fn next(&mut self) -> u64 {
                let mut x = self.0;
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                self.0 = x;
                x
            }
        }

        // Descend-set arena: canonical, permuted, repeated, empty.
        let sets: [&[FieldNumber]; 6] =
            [&[], &[f(1)], &[f(1), f(2)], &[f(2), f(1)], &[f(1), f(1)], &[f(2), f(3)]];

        let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
        let mut judged_err = 0;
        let mut judged_ok = 0;
        for _ in 0..512 {
            // Build one or two paths of up to four segments each.
            let mut arena: alloc::vec::Vec<alloc::vec::Vec<Segment<'_>>> = alloc::vec::Vec::new();
            for _ in 0..=(rng.next() % 2) {
                let len = rng.next() % 4;
                let mut path = alloc::vec::Vec::new();
                for _ in 0..len {
                    if rng.next().is_multiple_of(2) {
                        #[allow(
                            clippy::as_conversions,
                            reason = "seed residues stay inside the field domain"
                        )]
                        path.push(Segment::Field(f(1 + (rng.next() % 8) as u32)));
                    } else {
                        #[allow(
                            clippy::as_conversions,
                            reason = "seed residues index the tiny set arena"
                        )]
                        path.push(Segment::AnyDepth {
                            descend: sets[(rng.next() % sets.len() as u64) as usize],
                        });
                    }
                }
                arena.push(path);
            }
            let paths: alloc::vec::Vec<&[Segment<'_>]> =
                arena.iter().map(alloc::vec::Vec::as_slice).collect();
            let rules: alloc::vec::Vec<Rule<'_>> =
                paths.iter().map(|path| Rule { path, action: Action::Delete }).collect();

            let program = Program::over(&paths);
            let set = RuleSet::over(&rules);
            match (program, set) {
                (Ok(_), Ok(_)) => judged_ok += 1,
                (Err(p), Err(r)) => {
                    judged_err += 1;
                    let agree = matches!(
                        (p, r),
                        (
                            ProgramError::EmptyPath { path },
                            RuleError::EmptyPath { rule }
                        ) if path == rule
                    ) || matches!(
                        (p, r),
                        (
                            ProgramError::WildcardTarget { path },
                            RuleError::WildcardTarget { rule }
                        ) if path == rule
                    ) || matches!(
                        (p, r),
                        (
                            ProgramError::EmptyDescendSet { path, segment },
                            RuleError::EmptyDescendSet { rule, segment: s }
                        ) if path == rule && segment == s
                    ) || matches!(
                        (p, r),
                        (
                            ProgramError::UnsortedDescend { path, segment },
                            RuleError::UnsortedDescend { rule, segment: s }
                        ) if path == rule && segment == s
                    ) || matches!(
                        (p, r),
                        (
                            ProgramError::AdjacentWildcards { path, segment },
                            RuleError::AdjacentWildcards { rule, segment: s }
                        ) if path == rule && segment == s
                    ) || matches!(
                        (p, r),
                        (
                            ProgramError::DuplicatePath { first, second },
                            RuleError::DuplicatePath { first: a, second: b }
                        ) if first == a && second == b
                    );
                    assert!(agree, "verdicts diverged: {p:?} vs {r:?}");
                }
                (p, r) => panic!("one face admitted what the other refused: {p:?} vs {r:?}"),
            }
        }
        // The generator really generated both sides of the space.
        assert!(judged_ok >= 32, "only {judged_ok} lawful shapes seen");
        assert!(judged_err >= 32, "only {judged_err} breaches seen");
    }
}
