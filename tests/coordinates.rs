//! The coordinate census: the anti-hole decider over the scenario
//! space.
//!
//! Every scenario module file — the eight shared layers and their
//! dialect twins — must declare its position in the axis system as
//! one `Coordinates:` line in its module doc. This suite walks
//! `src/` itself, so a new scenario module that lands without a
//! coordinate line, or with coordinates a sibling already claims,
//! fails here before any prose can paper over the gap. The
//! adjudication table embedded below is the single source the
//! lines must match: moving a module's position means changing the
//! table and the module doc together, in one reviewed diff.
//!
//! Axes whose domain is empty at a point are omitted from its
//! line: read points have no revision axis (nothing to retract),
//! stream points have no backing axis (no addressable source is
//! retained — staging is a bounded carry, per module doc) with one
//! deliberate exception — the stream-ingest editors (stream_adopt,
//! stream_draft, stream_intake) and the stream collector (collect)
//! retain the copied source because that owned source is the finished
//! product's own backing (the sealed editor's, the sealed index's),
//! so their lines carry `owned`. Sequential-repeatable points omit
//! the backing axis with no exception: a replay machine retains
//! zero source bytes — walks lend views that die at the next pull,
//! and the standing products hold whole-source coordinates and
//! decoded words, never views into a source that is not resident.
//! And the value-side constructor sits outside the input axes (its
//! payload and output roles still carry axis facts; the role
//! account lives with the adjudication record, not in these
//! lines).
//!
//! Two capability rulings stand in this record beside the axes.
//! Their standing judge is the base-identity step in CI's cells
//! job (`.github/workflows/ci.yml`): every base cell expanded
//! feature-off, sliced to its emitted module region, held to
//! zero hits on the transfer vocabulary — the hand-listed
//! diagnostic terms plus the item names derived in the same run
//! from the cell's transfer sibling — with planted-input
//! self-checks proving both counters live on every run. The
//! priced-crossing step beside it holds the crossing feature to
//! exactly the transfer baseline plus its own machine, in both
//! directions. The magnitude controls below were each executed
//! once and recorded with their ruling in the commit record;
//! they are measurements, not judges that stand.
//!
//! - **Designation is producer-cell identity.** `record_ref` — and
//!   on the grouped dialect its private source-derived group-depth
//!   helper — plus the `crate::source` designation carrier belong
//!   to every offline read or edit cell's base identity; no
//!   `designate-*` feature exists. The mint is three small bodies
//!   per dialect and one carrier module, not a machine family.
//!   Executed control, in the commit record: the designation-cost
//!   expansion diff — a producer-only cell (`patch-<dialect>`, no
//!   default features) expanded and diffed against the
//!   pre-designation pin; the only lawful non-doc additions are
//!   the `record_ref` bodies (plus the grouped depth helper), with
//!   zero non-doc removals and zero transfer vocabulary in the
//!   emitted region.
//! - **Payload-backing policy is cell identity.** The copied,
//!   borrowed, and mixed siblings of one family share one lattice
//!   point and one feature; they owe no capability cells. Transfer
//!   is a capability — its own monotone feature and its own
//!   sibling machines; backing is identity — the same feature,
//!   sibling forms inside the cell. Neither ruling rests on a
//!   magnitude comparison. Executed control, in the commit record:
//!   the backing-identity A/B — the per-cell expansion diff of
//!   every base cell against its pre-mixed pin, in which every
//!   added emitted line is attributable to a Mix item, riding the
//!   layout pins that hold each mixed form byte-equal in size to
//!   its base twin.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

/// The marker every declaration line starts with, verbatim.
const MARKER: &str = "//! Coordinates: ";

/// Files of the unconditional strata plus scenario-internal
/// submodules: no coordinate line is expected or allowed. Test
/// submodules (`tests.rs`) are exempted by name in [`is_exempt`].
const EXEMPT: &[&str] = &[
    "lib.rs",
    "_macro.rs",
    "admission.rs",
    "pump.rs",
    "replay_pump.rs",
    "replay_script.rs",
    "replay_revise.rs",
    "cursor.rs",
    "cursor/grouped.rs",
    "cursor/groupless.rs",
    "editor.rs",
    "editor/grouped.rs",
    "editor/groupless.rs",
    "revise.rs",
    "revise/grouped.rs",
    "revise/groupless.rs",
    "fixed.rs",
    "scalar.rs",
    "source.rs",
    "source/grouped.rs",
    "source/groupless.rs",
    "replay_source.rs",
    "wire.rs",
    "wire/grouped.rs",
    "wire/groupless.rs",
    "varint.rs",
    "varint/slice.rs",
    "varint/carry.rs",
    "path.rs",
    "traverse/packed.rs",
    "splice/back.rs",
    // The transfer capability's scenario-internal emission
    // submodules: sibling machines inside their base cells' lattice
    // points, so no coordinate line of their own.
    "patch/grouped/transfer.rs",
    "patch/groupless/transfer.rs",
    "adopt/grouped/transfer.rs",
    "adopt/groupless/transfer.rs",
    "amend/grouped/transfer.rs",
    "amend/groupless/transfer.rs",
    "draft/grouped/transfer.rs",
    "draft/groupless/transfer.rs",
    "intake/grouped/transfer.rs",
    "intake/groupless/transfer.rs",
    "markup/grouped/transfer.rs",
    "markup/groupless/transfer.rs",
    "review/grouped/transfer.rs",
    "review/groupless/transfer.rs",
    "stream_adopt/grouped/transfer.rs",
    "stream_adopt/groupless/transfer.rs",
    "stream_draft/grouped/transfer.rs",
    "stream_draft/groupless/transfer.rs",
    "stream_intake/grouped/transfer.rs",
    "stream_intake/groupless/transfer.rs",
    "session/grouped/transfer.rs",
    "session/groupless/transfer.rs",
    "rewrite/transfer.rs",
    "rewrite/grouped/transfer.rs",
    "rewrite/groupless/transfer.rs",
    "splice/transfer.rs",
    "splice/grouped/transfer.rs",
    "splice/groupless/transfer.rs",
    // The stream-ingest cells' shared test corpus: cfg(test) only,
    // no scenario surface.
    "stream_corpus.rs",
];

/// The adjudicated occupancy: scenario module file → the point it
/// claims. Shared layers carry no dialect value; dialect files
/// carry theirs. Rows sit in the lattice's enumeration order —
/// derived from the coordinate lines themselves by test (f), so
/// this table cannot drift into birth order without going red.
const ADJUDICATED: &[(&str, &str)] = &[
    (
        "select.rs",
        "read · buffered · static · tolerant (type-level) · canonical (type-level) · borrowed",
    ),
    (
        "select/grouped.rs",
        "read · buffered · static · grouped · tolerant (type-level) · canonical (type-level) · \
         borrowed",
    ),
    (
        "select/groupless.rs",
        "read · buffered · static · groupless · tolerant (type-level) · canonical (type-level) · \
         borrowed",
    ),
    (
        "traverse.rs",
        "read · buffered · online · tolerant (type-level) · canonical (type-level) · borrowed",
    ),
    (
        "traverse/grouped.rs",
        "read · buffered · online · grouped · tolerant (type-level) · canonical (type-level) · \
         borrowed",
    ),
    (
        "traverse/groupless.rs",
        "read · buffered · online · groupless · tolerant (type-level) · canonical (type-level) · \
         borrowed",
    ),
    ("inspect.rs", "read · buffered · offline · Standard (value-level) · borrowed"),
    (
        "inspect/grouped.rs",
        "read · buffered · offline · grouped · Standard (value-level) · borrowed",
    ),
    (
        "inspect/groupless.rs",
        "read · buffered · offline · groupless · Standard (value-level) · borrowed",
    ),
    (
        "fixed_inspect.rs",
        "read · buffered · offline · Standard (value-level) · borrowed · fixed scratch",
    ),
    (
        "fixed_inspect/grouped.rs",
        "read · buffered · offline · grouped · Standard (value-level) · borrowed · fixed scratch",
    ),
    (
        "fixed_inspect/groupless.rs",
        "read · buffered · offline · groupless · Standard (value-level) · borrowed · \
         fixed scratch",
    ),
    ("retain.rs", "read · buffered · offline · Standard (value-level) · owned"),
    ("retain/grouped.rs", "read · buffered · offline · grouped · Standard (value-level) · owned"),
    (
        "retain/groupless.rs",
        "read · buffered · offline · groupless · Standard (value-level) · owned",
    ),
    ("route.rs", "read · stream · static · Standard (value-level)"),
    ("route/grouped.rs", "read · stream · static · grouped · Standard (value-level)"),
    ("route/groupless.rs", "read · stream · static · groupless · Standard (value-level)"),
    ("scan.rs", "read · stream · online · Standard (value-level)"),
    ("scan/grouped.rs", "read · stream · online · grouped · Standard (value-level)"),
    ("scan/groupless.rs", "read · stream · online · groupless · Standard (value-level)"),
    ("collect.rs", "read · stream · offline · Standard (value-level) · owned"),
    ("collect/grouped.rs", "read · stream · offline · grouped · Standard (value-level) · owned"),
    (
        "collect/groupless.rs",
        "read · stream · offline · groupless · Standard (value-level) · owned",
    ),
    ("survey.rs", "read · sequential-repeatable · offline · Standard (value-level)"),
    (
        "survey/grouped.rs",
        "read · sequential-repeatable · offline · grouped · Standard (value-level)",
    ),
    (
        "survey/groupless.rs",
        "read · sequential-repeatable · offline · groupless · Standard (value-level)",
    ),
    ("rewrite.rs", "write · buffered · static · Standard (value-level) · borrowed · commit-only"),
    (
        "rewrite/grouped.rs",
        "write · buffered · static · grouped · Standard (value-level) · borrowed · commit-only",
    ),
    (
        "rewrite/groupless.rs",
        "write · buffered · static · groupless · Standard (value-level) · borrowed · commit-only",
    ),
    ("inplace.rs", "write · buffered · static · Standard (value-level) · in-place · commit-only"),
    (
        "inplace/grouped.rs",
        "write · buffered · static · grouped · Standard (value-level) · in-place · commit-only",
    ),
    (
        "inplace/groupless.rs",
        "write · buffered · static · groupless · Standard (value-level) · in-place · commit-only",
    ),
    (
        "fixed_inplace.rs",
        "write · buffered · static · Standard (value-level) · in-place · commit-only · \
         fixed scratch",
    ),
    (
        "fixed_inplace/grouped.rs",
        "write · buffered · static · grouped · Standard (value-level) · in-place · commit-only · \
         fixed scratch",
    ),
    (
        "fixed_inplace/groupless.rs",
        "write · buffered · static · groupless · Standard (value-level) · in-place · \
         commit-only · fixed scratch",
    ),
    (
        "convert.rs",
        "write · buffered · static · crossing · Standard (value-level) · borrowed · commit-only",
    ),
    (
        "convert/grouped.rs",
        "write · buffered · static · groupless (input) · grouped (output) · \
         Standard (value-level) · borrowed · commit-only",
    ),
    (
        "convert/groupless.rs",
        "write · buffered · static · grouped (input) · groupless (output) · \
         Standard (value-level) · borrowed · commit-only",
    ),
    ("splice.rs", "write · buffered · online · Standard (value-level) · borrowed · commit-only"),
    (
        "splice/grouped.rs",
        "write · buffered · online · grouped · Standard (value-level) · borrowed · commit-only",
    ),
    (
        "splice/groupless.rs",
        "write · buffered · online · groupless · Standard (value-level) · borrowed · commit-only",
    ),
    ("patch.rs", "write · buffered · offline · tolerant (type-level) · borrowed · commit-only"),
    (
        "patch/grouped.rs",
        "write · buffered · offline · grouped · tolerant (type-level) · borrowed · commit-only",
    ),
    (
        "patch/groupless.rs",
        "write · buffered · offline · groupless · tolerant (type-level) · borrowed · commit-only",
    ),
    (
        "fixed_patch.rs",
        "write · buffered · offline · tolerant (type-level) · borrowed · commit-only · \
         fixed scratch",
    ),
    (
        "fixed_patch/grouped.rs",
        "write · buffered · offline · grouped · tolerant (type-level) · borrowed · commit-only · \
         fixed scratch",
    ),
    (
        "fixed_patch/groupless.rs",
        "write · buffered · offline · groupless · tolerant (type-level) · borrowed · \
         commit-only · fixed scratch",
    ),
    ("markup.rs", "write · buffered · offline · tolerant (type-level) · borrowed · revisable"),
    (
        "markup/grouped.rs",
        "write · buffered · offline · grouped · tolerant (type-level) · borrowed · revisable",
    ),
    (
        "markup/groupless.rs",
        "write · buffered · offline · groupless · tolerant (type-level) · borrowed · revisable",
    ),
    ("adopt.rs", "write · buffered · offline · tolerant (type-level) · owned · commit-only"),
    (
        "adopt/grouped.rs",
        "write · buffered · offline · grouped · tolerant (type-level) · owned · commit-only",
    ),
    (
        "adopt/groupless.rs",
        "write · buffered · offline · groupless · tolerant (type-level) · owned · commit-only",
    ),
    ("draft.rs", "write · buffered · offline · tolerant (type-level) · owned · revisable"),
    (
        "draft/grouped.rs",
        "write · buffered · offline · grouped · tolerant (type-level) · owned · revisable",
    ),
    (
        "draft/groupless.rs",
        "write · buffered · offline · groupless · tolerant (type-level) · owned · revisable",
    ),
    ("amend.rs", "write · buffered · offline · canonical (type-level) · borrowed · commit-only"),
    (
        "amend/grouped.rs",
        "write · buffered · offline · grouped · canonical (type-level) · borrowed · commit-only",
    ),
    (
        "amend/groupless.rs",
        "write · buffered · offline · groupless · canonical (type-level) · borrowed · commit-only",
    ),
    ("review.rs", "write · buffered · offline · canonical (type-level) · borrowed · revisable"),
    (
        "review/grouped.rs",
        "write · buffered · offline · grouped · canonical (type-level) · borrowed · revisable",
    ),
    (
        "review/groupless.rs",
        "write · buffered · offline · groupless · canonical (type-level) · borrowed · revisable",
    ),
    ("intake.rs", "write · buffered · offline · canonical (type-level) · owned · commit-only"),
    (
        "intake/grouped.rs",
        "write · buffered · offline · grouped · canonical (type-level) · owned · commit-only",
    ),
    (
        "intake/groupless.rs",
        "write · buffered · offline · groupless · canonical (type-level) · owned · commit-only",
    ),
    ("session.rs", "write · buffered · offline · canonical (type-level) · owned · revisable"),
    (
        "session/grouped.rs",
        "write · buffered · offline · grouped · canonical (type-level) · owned · revisable",
    ),
    (
        "session/groupless.rs",
        "write · buffered · offline · groupless · canonical (type-level) · owned · revisable",
    ),
    ("rewire.rs", "write · stream · static · Standard (value-level) · commit-only"),
    (
        "rewire/grouped.rs",
        "write · stream · static · grouped · Standard (value-level) · commit-only",
    ),
    (
        "rewire/groupless.rs",
        "write · stream · static · groupless · Standard (value-level) · commit-only",
    ),
    ("transcode.rs", "write · stream · online · Standard (value-level) · commit-only"),
    (
        "transcode/grouped.rs",
        "write · stream · online · grouped · Standard (value-level) · commit-only",
    ),
    (
        "transcode/groupless.rs",
        "write · stream · online · groupless · Standard (value-level) · commit-only",
    ),
    ("stream_adopt.rs", "write · stream · offline · tolerant (type-level) · owned · commit-only"),
    (
        "stream_adopt/grouped.rs",
        "write · stream · offline · grouped · tolerant (type-level) · owned · commit-only",
    ),
    (
        "stream_adopt/groupless.rs",
        "write · stream · offline · groupless · tolerant (type-level) · owned · commit-only",
    ),
    ("stream_draft.rs", "write · stream · offline · tolerant (type-level) · owned · revisable"),
    (
        "stream_draft/grouped.rs",
        "write · stream · offline · grouped · tolerant (type-level) · owned · revisable",
    ),
    (
        "stream_draft/groupless.rs",
        "write · stream · offline · groupless · tolerant (type-level) · owned · revisable",
    ),
    ("stream_intake.rs", "write · stream · offline · canonical (type-level) · owned · commit-only"),
    (
        "stream_intake/grouped.rs",
        "write · stream · offline · grouped · canonical (type-level) · owned · commit-only",
    ),
    (
        "stream_intake/groupless.rs",
        "write · stream · offline · groupless · canonical (type-level) · owned · commit-only",
    ),
    (
        "replay_rewrite.rs",
        "write · sequential-repeatable · static · Standard (value-level) · commit-only",
    ),
    (
        "replay_rewrite/grouped.rs",
        "write · sequential-repeatable · static · grouped · Standard (value-level) · commit-only",
    ),
    (
        "replay_rewrite/groupless.rs",
        "write · sequential-repeatable · static · groupless · Standard (value-level) · \
         commit-only",
    ),
    (
        "replay_convert.rs",
        "write · sequential-repeatable · static · crossing · Standard (value-level) · commit-only",
    ),
    (
        "replay_convert/grouped.rs",
        "write · sequential-repeatable · static · groupless (input) · grouped (output) · \
         Standard (value-level) · commit-only",
    ),
    (
        "replay_convert/groupless.rs",
        "write · sequential-repeatable · static · grouped (input) · groupless (output) · \
         Standard (value-level) · commit-only",
    ),
    (
        "replay_splice.rs",
        "write · sequential-repeatable · online · Standard (value-level) · commit-only",
    ),
    (
        "replay_splice/grouped.rs",
        "write · sequential-repeatable · online · grouped · Standard (value-level) · commit-only",
    ),
    (
        "replay_splice/groupless.rs",
        "write · sequential-repeatable · online · groupless · Standard (value-level) · \
         commit-only",
    ),
    (
        "overhaul.rs",
        "write · sequential-repeatable · offline · tolerant (type-level) · commit-only",
    ),
    (
        "overhaul/grouped.rs",
        "write · sequential-repeatable · offline · grouped · tolerant (type-level) · commit-only",
    ),
    (
        "overhaul/groupless.rs",
        "write · sequential-repeatable · offline · groupless · tolerant (type-level) · \
         commit-only",
    ),
    ("maintain.rs", "write · sequential-repeatable · offline · tolerant (type-level) · revisable"),
    (
        "maintain/grouped.rs",
        "write · sequential-repeatable · offline · grouped · tolerant (type-level) · revisable",
    ),
    (
        "maintain/groupless.rs",
        "write · sequential-repeatable · offline · groupless · tolerant (type-level) · \
         revisable",
    ),
    ("refit.rs", "write · sequential-repeatable · offline · canonical (type-level) · commit-only"),
    (
        "refit/grouped.rs",
        "write · sequential-repeatable · offline · grouped · canonical (type-level) · \
         commit-only",
    ),
    (
        "refit/groupless.rs",
        "write · sequential-repeatable · offline · groupless · canonical (type-level) · \
         commit-only",
    ),
    (
        "commission.rs",
        "write · sequential-repeatable · offline · canonical (type-level) · revisable",
    ),
    (
        "commission/grouped.rs",
        "write · sequential-repeatable · offline · grouped · canonical (type-level) · revisable",
    ),
    (
        "commission/groupless.rs",
        "write · sequential-repeatable · offline · groupless · canonical (type-level) · \
         revisable",
    ),
    ("construct.rs", "author (outside the input axes)"),
    ("construct/grouped.rs", "author (outside the input axes) · grouped"),
    ("construct/groupless.rs", "author (outside the input axes) · groupless"),
];

/// The axes in the crate root's declared sequence, each with its
/// poles in the axis account's recorded order. Test (b) draws the
/// lawful-value set from here; test (f) derives the enumeration
/// order from here — order is a projection of this table plus the
/// coordinate lines, never an independent choice.
const AXES: &[(&str, &[&str])] = &[
    ("intent", &["read", "write"]),
    // `sequential-repeatable` — the pole's definition: the input is
    // not addressable and not once-only, but can be walked from
    // byte zero as many times as asked, each walk yielding one
    // identical finite sequence (the file-shaped availability mode;
    // the supply contract is `replay_source`). Presence is the
    // availability mode of the input bytes, and the two landed
    // poles were the occupied projection, not a theorem — this pole
    // is appended third so every landed coordinate line and key
    // stays byte-identical.
    ("presence", &["buffered", "stream", "sequential-repeatable"]),
    ("designation", &["static", "online", "offline"]),
    // `crossing` names the converter pair whose output pole is the
    // input's opposite — the coordinate line's default projection
    // (the input-document role) under-determines that pair, so the
    // shared layer states the off-diagonal fact and the twins
    // resolve it with role-annotated entries (`X (input) ·
    // Y (output)`). It follows the fixed poles as the off-diagonal
    // case, exactly as `Standard` follows acceptance's fixed poles
    // as the statically unpinned one.
    ("dialect", &["grouped", "groupless", "crossing"]),
    // `Standard` names the runtime parameter carrying both
    // acceptance poles on one machine; it follows the fixed poles
    // as the statically unpinned case (no ordering comparison
    // among the occupied points reaches it).
    ("acceptance", &["tolerant", "canonical", "Standard"]),
    // `in-place` — the pole's definition: the source allocation is
    // the output; borrowed mutably for the job, edited atomically.
    // Added because the default input-role projection
    // under-determined the rewrite/inplace pair (both project
    // `write · buffered · static · Standard`): the output role's
    // backing is what separates them, and the pole carries it into
    // the line.
    ("backing", &["borrowed", "owned", "in-place"]),
    ("revision", &["commit-only", "revisable"]),
    // `scratch` — the pole's definition: working memory is
    // caller-supplied under a capacity contract (one slab carved at
    // the door, demand priced exactly, exhaustion a deterministic
    // refusal). Appended last so heap cells omit it lawfully (they
    // carry no caller-memory contract, so the axis's domain is
    // empty at their points), keeping every landed line
    // byte-identical while the key's omitted-axis zero sorts each
    // fixed twin immediately after its host. The alternative — a
    // second role-annotated entry on the backing axis — ties the
    // lattice key with the host (the key reads the first backing
    // entry), which test (f)'s strictly-ascending law refuses; the
    // executed probe is in the commit record.
    ("scratch", &["fixed scratch"]),
];

/// The one value outside every axis: the constructor's exterior
/// mark.
const EXTERIOR: &str = "author";

/// Every lawful level/scope annotation an entry may carry. The
/// role annotations (`input`, `output`) exist for the dialect
/// entries of the crossing pair alone, where the two projections
/// differ; every other entry's dialect projection is the input
/// role's, unannotated.
const ANNOTATIONS: &[&str] =
    &["fixed", "type-level", "value-level", "outside the input axes", "input", "output"];

/// Axis vocabulary retired by adjudication: the pre-axis-system
/// space description and its cell coordinates. Forbidden anywhere
/// in live text — the checks above pin only `Coordinates:` lines,
/// so without this ban a retired framework could keep speaking
/// through the surrounding prose (module doc first lines, the
/// crate root's module list, the README table).
const RETIRED_VOCABULARY: &[&str] = &[
    "· index",
    "· traversal",
    "access × presence",
    // The allocation partition speaks the loss-bound form; the
    // replayability wording it replaced must not resurface.
    "cannot be replayed",
    "a re-run rebuilds",
];

/// The byte roles a machine touches: the input document, payload
/// arguments passed into write/author faces, the machine's working
/// memory, and the output. The coordinate lines project each axis
/// onto the input-document role alone; this table carries the
/// other three projections. Its law — learned from two fired gaps
/// (the author payload copy and the save-side presence
/// hole): **no cell may be silent** — every cell states a value or
/// an `n/a:` with its reason. A new scenario module must fill its
/// seven rows before the census goes green, and changing a cell
/// means changing the adjudication record in the same diff.
const ROLES: [&str; 4] = ["input", "payload", "memory", "output"];

/// Shared layer × axis → the four role dispositions, axes in the
/// `AXES` order (the exterior `author` included). Owed debts are
/// named by their ledger number so the cell reads as a status, not
/// a promise.
const ROLE_CENSUS: &[(&str, &str, [&str; 4])] = &[
    // ── select ──
    (
        "select.rs",
        "intent",
        [
            "read",
            "n/a: read faces take no payloads",
            "n/a: machine-internal",
            "borrowed observations, no derived document",
        ],
    ),
    (
        "select.rs",
        "presence",
        [
            "buffered",
            "n/a: read faces take no payloads",
            "layer tables + walk stack, job-local",
            "views into the input",
        ],
    ),
    (
        "select.rs",
        "designation",
        [
            "static",
            "n/a: read faces take no payloads",
            "n/a: retention is the axis's own mechanism",
            "matches name source records (PathId + span)",
        ],
    ),
    (
        "select.rs",
        "dialect",
        [
            "per twin",
            "n/a: read faces take no payloads",
            "single-dialect vocabulary",
            "the input's dialect, observed",
        ],
    ),
    (
        "select.rs",
        "acceptance",
        [
            "tolerant or canonical — the entry type pins it (Matches / CanonicalMatches)",
            "n/a: read faces take no payloads",
            "n/a: staging judges nothing",
            "n/a: no bytes re-emitted",
        ],
    ),
    (
        "select.rs",
        "backing",
        ["borrowed", "n/a: read faces take no payloads", "machine-owned tables", "borrowed views"],
    ),
    (
        "select.rs",
        "revision",
        [
            "n/a: reads retract nothing",
            "n/a: read faces take no payloads",
            "n/a: no log",
            "n/a: nothing published",
        ],
    ),
    (
        "select.rs",
        "scratch",
        [
            "n/a: the axis governs working memory",
            "n/a: the axis governs working memory",
            "machine-owned working memory — no caller-memory contract, so the point does not \
             extend into this axis (its line omits it)",
            "n/a: the axis governs working memory",
        ],
    ),
    // ── traverse ──
    (
        "traverse.rs",
        "intent",
        [
            "read",
            "n/a: read faces take no payloads",
            "n/a: machine-internal",
            "borrowed entries, no derived document",
        ],
    ),
    (
        "traverse.rs",
        "presence",
        [
            "buffered",
            "n/a: read faces take no payloads",
            "cursor + group stack, job-local",
            "views into the input",
        ],
    ),
    (
        "traverse.rs",
        "designation",
        [
            "online",
            "n/a: read faces take no payloads",
            "n/a: retention is the axis's own mechanism",
            "entries carry offsets, not identities",
        ],
    ),
    (
        "traverse.rs",
        "dialect",
        [
            "per twin",
            "n/a: read faces take no payloads",
            "single-dialect vocabulary",
            "the input's dialect, observed",
        ],
    ),
    (
        "traverse.rs",
        "acceptance",
        [
            "tolerant or canonical — the entry type pins it (Cursor / CanonicalCursor)",
            "n/a: read faces take no payloads",
            "n/a: staging judges nothing",
            "n/a: no bytes re-emitted",
        ],
    ),
    (
        "traverse.rs",
        "backing",
        ["borrowed", "n/a: read faces take no payloads", "machine-owned stack", "borrowed views"],
    ),
    (
        "traverse.rs",
        "revision",
        [
            "n/a: reads retract nothing",
            "n/a: read faces take no payloads",
            "n/a: no log",
            "n/a: nothing published",
        ],
    ),
    (
        "traverse.rs",
        "scratch",
        [
            "n/a: the axis governs working memory",
            "n/a: the axis governs working memory",
            "machine-owned working memory — no caller-memory contract, so the point does not \
             extend into this axis (its line omits it)",
            "n/a: the axis governs working memory",
        ],
    ),
    // ── inspect ──
    (
        "inspect.rs",
        "intent",
        [
            "read",
            "n/a: advisor answers, not payloads",
            "n/a: machine-internal",
            "borrowed queries, no derived document",
        ],
    ),
    (
        "inspect.rs",
        "presence",
        [
            "buffered",
            "n/a: advisor answers, not payloads",
            "row arena, tree-lived",
            "views into the input",
        ],
    ),
    (
        "inspect.rs",
        "designation",
        [
            "offline",
            "n/a: advisor answers, not payloads",
            "n/a: retention is the axis's own mechanism",
            "handles + narrowest resolve both ways",
        ],
    ),
    (
        "inspect.rs",
        "dialect",
        [
            "per twin",
            "n/a: advisor answers, not payloads",
            "single-dialect vocabulary",
            "the input's dialect, observed",
        ],
    ),
    (
        "inspect.rs",
        "acceptance",
        [
            "Standard (value-level: parse_standard picks the engine once; parse = Tolerant)",
            "n/a: advisor answers, not payloads",
            "widths stored under both standards (span geometry needs them)",
            "n/a: no bytes re-emitted",
        ],
    ),
    (
        "inspect.rs",
        "backing",
        [
            "borrowed",
            "n/a: advisor answers, not payloads",
            "machine-owned rows (the detachable owned twin = retain)",
            "borrowed views",
        ],
    ),
    (
        "inspect.rs",
        "revision",
        [
            "n/a: reads retract nothing",
            "n/a: advisor answers, not payloads",
            "n/a: no log",
            "n/a: nothing published",
        ],
    ),
    (
        "inspect.rs",
        "scratch",
        [
            "n/a: the axis governs working memory",
            "n/a: the axis governs working memory",
            "machine-owned working memory — no caller-memory contract, so the point does not \
             extend into this axis (its line omits it)",
            "n/a: the axis governs working memory",
        ],
    ),
    // ── fixed_inspect ──
    (
        "fixed_inspect.rs",
        "intent",
        [
            "read",
            "n/a: advisor answers, not payloads",
            "n/a: machine-internal",
            "borrowed queries, no derived document",
        ],
    ),
    (
        "fixed_inspect.rs",
        "presence",
        [
            "buffered",
            "n/a: advisor answers, not payloads",
            "row arena over a caller-slab lane, tree-lived",
            "views into the input",
        ],
    ),
    (
        "fixed_inspect.rs",
        "designation",
        [
            "offline",
            "n/a: advisor answers, not payloads",
            "n/a: retention is the axis's own mechanism",
            "handles + narrowest resolve both ways",
        ],
    ),
    (
        "fixed_inspect.rs",
        "dialect",
        [
            "per twin",
            "n/a: advisor answers, not payloads",
            "single-dialect vocabulary",
            "the input's dialect, observed",
        ],
    ),
    (
        "fixed_inspect.rs",
        "acceptance",
        [
            "Standard (value-level: parse_standard picks the engine once; parse = Tolerant)",
            "n/a: advisor answers, not payloads",
            "widths stored under both standards (span geometry needs them)",
            "n/a: no bytes re-emitted",
        ],
    ),
    (
        "fixed_inspect.rs",
        "backing",
        [
            "borrowed",
            "n/a: advisor answers, not payloads",
            "caller-slab lanes under the capacity contract",
            "borrowed views",
        ],
    ),
    (
        "fixed_inspect.rs",
        "revision",
        [
            "n/a: reads retract nothing",
            "n/a: advisor answers, not payloads",
            "n/a: no log",
            "n/a: nothing published",
        ],
    ),
    (
        "fixed_inspect.rs",
        "scratch",
        [
            "n/a: the axis governs working memory, not the source",
            "n/a: advisor answers, not payloads",
            "fixed scratch: the row arena and the parse's frame and path stacks carved from \
             one caller slab — frame and path capacities derived from the plan's rows and the \
             depth bound, the row count plan-declared (peak demand: evaporated speculative \
             rows count); exhaustion refuses at the door before a machine exists (SlabShort) \
             or aborts with no product published (RowsExhausted), budget() reads per-lane \
             high-water",
            "n/a: output is not scratch — queries hand borrowed views out",
        ],
    ),
    // ── retain ──
    (
        "retain.rs",
        "intent",
        [
            "read",
            "n/a: advisor answers, not payloads",
            "n/a: machine-internal",
            "borrowed queries, no derived document",
        ],
    ),
    (
        "retain.rs",
        "presence",
        [
            "buffered",
            "n/a: advisor answers, not payloads",
            "row arena, product-lived",
            "views into the owned source",
        ],
    ),
    (
        "retain.rs",
        "designation",
        [
            "offline",
            "n/a: advisor answers, not payloads",
            "n/a: retention is the axis's own mechanism",
            "handles + narrowest resolve both ways",
        ],
    ),
    (
        "retain.rs",
        "dialect",
        [
            "per twin",
            "n/a: advisor answers, not payloads",
            "single-dialect vocabulary",
            "the input's dialect, observed",
        ],
    ),
    (
        "retain.rs",
        "acceptance",
        [
            "Standard (value-level: parse_standard picks the engine once; parse = Tolerant)",
            "n/a: advisor answers, not payloads",
            "widths stored under both standards (span geometry needs them)",
            "n/a: no bytes re-emitted",
        ],
    ),
    (
        "retain.rs",
        "backing",
        [
            "owned (the buffer moves in; refusal returns it intact)",
            "n/a: advisor answers, not payloads",
            "machine-owned rows over the owned source (Send + Sync product)",
            "borrowed views; into_bytes releases the source",
        ],
    ),
    (
        "retain.rs",
        "revision",
        [
            "n/a: reads retract nothing",
            "n/a: advisor answers, not payloads",
            "n/a: no log",
            "n/a: nothing published",
        ],
    ),
    (
        "retain.rs",
        "scratch",
        [
            "n/a: the axis governs working memory",
            "n/a: the axis governs working memory",
            "machine-owned working memory — no caller-memory contract, so the point does not \
             extend into this axis (its line omits it)",
            "n/a: the axis governs working memory",
        ],
    ),
    // ── route ──
    (
        "route.rs",
        "intent",
        [
            "read",
            "n/a: read faces take no payloads",
            "n/a: machine-internal",
            "PathId-tagged events, no derived document",
        ],
    ),
    (
        "route.rs",
        "presence",
        [
            "stream",
            "n/a: read faces take no payloads",
            "bounded carry + container/tap stacks",
            "events per feed; tap segments borrow the feed",
        ],
    ),
    (
        "route.rs",
        "designation",
        [
            "static",
            "n/a: read faces take no payloads",
            "n/a: retention is the axis's own mechanism",
            "events name source records (PathId + record offsets)",
        ],
    ),
    (
        "route.rs",
        "dialect",
        [
            "per twin",
            "n/a: read faces take no payloads",
            "single-dialect vocabulary",
            "the input's dialect, observed",
        ],
    ),
    (
        "route.rs",
        "acceptance",
        [
            "Standard (value-level)",
            "n/a: read faces take no payloads",
            "n/a: staging judges nothing",
            "n/a: no bytes re-emitted",
        ],
    ),
    (
        "route.rs",
        "backing",
        [
            "n/a: no retained source (bounded staging only)",
            "n/a: read faces take no payloads",
            "machine-owned carry + matcher tables",
            "segments live one feed",
        ],
    ),
    (
        "route.rs",
        "revision",
        [
            "n/a: reads retract nothing",
            "n/a: read faces take no payloads",
            "n/a: no log",
            "n/a: nothing published",
        ],
    ),
    (
        "route.rs",
        "scratch",
        [
            "n/a: the axis governs working memory",
            "n/a: the axis governs working memory",
            "machine-owned working memory — no caller-memory contract, so the point does not \
             extend into this axis (its line omits it)",
            "n/a: the axis governs working memory",
        ],
    ),
    // ── scan ──
    (
        "scan.rs",
        "intent",
        [
            "read",
            "n/a: read faces take no payloads",
            "n/a: machine-internal",
            "sink events, no derived document",
        ],
    ),
    (
        "scan.rs",
        "presence",
        [
            "stream",
            "n/a: read faces take no payloads",
            "bounded carry + container stack",
            "events per feed; fragments borrow the chunk",
        ],
    ),
    (
        "scan.rs",
        "designation",
        [
            "online",
            "n/a: read faces take no payloads",
            "n/a: retention is the axis's own mechanism",
            "events carry offsets, not identities",
        ],
    ),
    (
        "scan.rs",
        "dialect",
        [
            "per twin",
            "n/a: read faces take no payloads",
            "single-dialect vocabulary",
            "the input's dialect, observed",
        ],
    ),
    (
        "scan.rs",
        "acceptance",
        [
            "Standard (value-level)",
            "n/a: read faces take no payloads",
            "n/a: staging judges nothing",
            "n/a: no bytes re-emitted",
        ],
    ),
    (
        "scan.rs",
        "backing",
        [
            "n/a: no retained source (bounded staging only)",
            "n/a: read faces take no payloads",
            "machine-owned carry",
            "fragments live one feed",
        ],
    ),
    (
        "scan.rs",
        "revision",
        [
            "n/a: reads retract nothing",
            "n/a: read faces take no payloads",
            "n/a: no log",
            "n/a: nothing published",
        ],
    ),
    (
        "scan.rs",
        "scratch",
        [
            "n/a: the axis governs working memory",
            "n/a: the axis governs working memory",
            "machine-owned working memory — no caller-memory contract, so the point does not \
             extend into this axis (its line omits it)",
            "n/a: the axis governs working memory",
        ],
    ),
    // ── collect ──
    (
        "collect.rs",
        "intent",
        [
            "read",
            "n/a: advisor answers, not payloads",
            "n/a: machine-internal",
            "borrowed queries, no derived document",
        ],
    ),
    (
        "collect.rs",
        "presence",
        [
            "stream (feed phase; consumed at finish — the seal into the standing index)",
            "n/a: advisor answers, not payloads",
            "growing owned source as the word bank + row arena, collection-lived then \
             product-lived; carry and frames only during collection",
            "views into the finished product's own source",
        ],
    ),
    (
        "collect.rs",
        "designation",
        [
            "offline (the finished index; the feed phase itself answers no queries)",
            "n/a: advisor answers, not payloads",
            "n/a: retention is the axis's own mechanism",
            "handles + narrowest resolve both ways",
        ],
    ),
    (
        "collect.rs",
        "dialect",
        [
            "per twin",
            "n/a: advisor answers, not payloads",
            "single-dialect vocabulary",
            "the input's dialect, observed",
        ],
    ),
    (
        "collect.rs",
        "acceptance",
        [
            "Standard (value-level: the constructor takes it; each feed selects the engine)",
            "n/a: advisor answers, not payloads",
            "widths stored under both standards (span geometry needs them)",
            "n/a: no bytes re-emitted",
        ],
    ),
    (
        "collect.rs",
        "backing",
        [
            "owned — the stream-presence exception: the retained copy IS the offline \
             product's source (chunks absorb whole per successful feed; a feed refusal \
             returns the accumulated bytes; into_source releases them)",
            "n/a: advisor answers, not payloads",
            "machine-owned rows over the owned source (Send + Sync product)",
            "borrowed views; into_bytes releases the source",
        ],
    ),
    (
        "collect.rs",
        "revision",
        [
            "n/a: reads retract nothing",
            "n/a: advisor answers, not payloads",
            "n/a: no log",
            "n/a: nothing published",
        ],
    ),
    (
        "collect.rs",
        "scratch",
        [
            "n/a: the axis governs working memory",
            "n/a: the axis governs working memory",
            "machine-owned working memory — no caller-memory contract, so the point does not \
             extend into this axis (its line omits it)",
            "n/a: the axis governs working memory",
        ],
    ),
    // ── survey ──
    (
        "survey.rs",
        "intent",
        [
            "read",
            "n/a: advisor answers, not payloads",
            "n/a: machine-internal",
            "row-resident answers and fetched copies, no derived document",
        ],
    ),
    (
        "survey.rs",
        "presence",
        [
            "sequential-repeatable (one index walk builds the rows; byte questions are later \
             fetch walks)",
            "n/a: advisor answers, not payloads",
            "source handle + row arena, product-lived; zero resident source bytes",
            "decoded words from the rows; payload bytes land in caller memory (read_payload, \
             payload_sink, fetch_payloads) — no face returns a view into the source",
        ],
    ),
    (
        "survey.rs",
        "designation",
        [
            "offline (the standing index; each single-handle fetch is one walk, and \
             fetch_payloads resolves k handles in one)",
            "n/a: advisor answers, not payloads",
            "n/a: retention is the axis's own mechanism",
            "handles + narrowest resolve both ways",
        ],
    ),
    (
        "survey.rs",
        "dialect",
        [
            "per twin",
            "n/a: advisor answers, not payloads",
            "single-dialect vocabulary",
            "the input's dialect, observed",
        ],
    ),
    (
        "survey.rs",
        "acceptance",
        [
            "Standard (value-level: open_standard picks the engine once; open = Tolerant)",
            "n/a: advisor answers, not payloads",
            "row geometry and decoded words stored under both standards",
            "n/a: no bytes re-emitted",
        ],
    ),
    (
        "survey.rs",
        "backing",
        [
            "no addressable source is retained — the supply is walked, never held, so the \
             point does not extend into this axis (its line omits it)",
            "n/a: advisor answers, not payloads",
            "machine-owned rows (topology, u64 spans, decoded scalar words) over the source \
             handle",
            "decoded words by value; fetched bytes are copies into caller memory",
        ],
    ),
    (
        "survey.rs",
        "revision",
        [
            "n/a: reads retract nothing",
            "n/a: advisor answers, not payloads",
            "n/a: no log",
            "n/a: nothing published",
        ],
    ),
    (
        "survey.rs",
        "scratch",
        [
            "n/a: the axis governs working memory",
            "n/a: the axis governs working memory",
            "machine-owned working memory — no caller-memory contract, so the point does not \
             extend into this axis (its line omits it)",
            "n/a: the axis governs working memory",
        ],
    ),
    // ── rewrite ──
    (
        "rewrite.rs",
        "intent",
        [
            "write",
            "replacement and insert values consumed at emit",
            "n/a: machine-internal",
            "the derived document",
        ],
    ),
    (
        "rewrite.rs",
        "presence",
        [
            "buffered",
            "whole slices or borrowed scatter (Value::LenParts, gathered at emit)",
            "matcher layers + slot ledger, job-local",
            "buffered Vec or caller sink (rewrite_sink; Err hands it nothing)",
        ],
    ),
    (
        "rewrite.rs",
        "designation",
        [
            "static",
            "n/a: values carry no occurrences",
            "n/a: retention is the axis's own mechanism",
            "n/a: outputs carry no record identities (rules match patterns, not records)",
        ],
    ),
    (
        "rewrite.rs",
        "dialect",
        [
            "per twin",
            "opaque interiors by declaration",
            "single-dialect vocabulary",
            "the input's dialect (cross-dialect conversion = the convert cells)",
        ],
    ),
    (
        "rewrite.rs",
        "acceptance",
        [
            "Standard (value-level: the _standard faces pick the walk once; plain = Tolerant)",
            "opaque by declaration; typed values author minimal",
            "n/a: staging judges nothing",
            "Tolerant always; CanonicalMinimal when every padded word was absent or normalized",
        ],
    ),
    (
        "rewrite.rs",
        "backing",
        [
            "borrowed",
            "borrowed rule payloads (single copy at emit)",
            "machine-owned tables",
            "owned Vec (same-allocation editing = the inplace cells)",
        ],
    ),
    (
        "rewrite.rs",
        "revision",
        [
            "n/a: input immutable",
            "n/a: rules are caller-owned plans",
            "n/a: no log (commit-only)",
            "n/a: publication is not revision",
        ],
    ),
    (
        "rewrite.rs",
        "scratch",
        [
            "n/a: the axis governs working memory",
            "n/a: the axis governs working memory",
            "machine-owned working memory — no caller-memory contract, so the point does not \
             extend into this axis (its line omits it)",
            "n/a: the axis governs working memory",
        ],
    ),
    // ── inplace ──
    (
        "inplace.rs",
        "intent",
        [
            "write",
            "replacement values and payloads consumed at the write loop",
            "n/a: machine-internal",
            "the caller's own buffer, edited in place",
        ],
    ),
    (
        "inplace.rs",
        "presence",
        [
            "buffered",
            "whole slices, borrowed for the job",
            "matcher layers + write list, job-local",
            "n/a: no output object — the input allocation is the product",
        ],
    ),
    (
        "inplace.rs",
        "designation",
        [
            "static",
            "n/a: values carry no occurrences",
            "n/a: retention is the axis's own mechanism",
            "n/a: outputs carry no record identities (rules match patterns; Stats counts)",
        ],
    ),
    (
        "inplace.rs",
        "dialect",
        [
            "per twin",
            "opaque payload bytes by declaration",
            "single-dialect vocabulary",
            "the input's dialect, in place",
        ],
    ),
    (
        "inplace.rs",
        "acceptance",
        [
            "Standard (value-level: the _standard faces pick the walk once; plain = Tolerant)",
            "payloads opaque by declaration; authored words lawful under the declared standard \
             (Tolerant may pad to the slot)",
            "n/a: staging judges nothing",
            "re-ingests under the declared standard (canonical closure exactly when declared)",
        ],
    ),
    (
        "inplace.rs",
        "backing",
        [
            "in-place: borrowed mutably, the source allocation is the output",
            "borrowed rule payloads (single copy at the write loop)",
            "machine-owned tables + write list, job-local",
            "the input allocation itself — zero output allocation",
        ],
    ),
    (
        "inplace.rs",
        "revision",
        [
            "n/a: the buffer mutates only past the fault barrier (commit-only)",
            "n/a: rules are caller-owned plans",
            "n/a: no log (commit-only)",
            "n/a: publication is not revision",
        ],
    ),
    (
        "inplace.rs",
        "scratch",
        [
            "n/a: the axis governs working memory",
            "n/a: the axis governs working memory",
            "machine-owned working memory — no caller-memory contract, so the point does not \
             extend into this axis (its line omits it)",
            "n/a: the axis governs working memory",
        ],
    ),
    // ── fixed_inplace ──
    (
        "fixed_inplace.rs",
        "intent",
        [
            "write",
            "replacement values and payloads consumed at the write loop",
            "n/a: machine-internal",
            "the caller's own buffer, edited in place",
        ],
    ),
    (
        "fixed_inplace.rs",
        "presence",
        [
            "buffered",
            "whole slices, borrowed for the job",
            "matcher lanes + walk stack + write list, job-local, carved from the caller's slab",
            "n/a: no output object — the input allocation is the product",
        ],
    ),
    (
        "fixed_inplace.rs",
        "designation",
        [
            "static",
            "n/a: values carry no occurrences",
            "n/a: retention is the axis's own mechanism",
            "n/a: outputs carry no record identities (rules match patterns; Stats counts)",
        ],
    ),
    (
        "fixed_inplace.rs",
        "dialect",
        [
            "per twin",
            "opaque payload bytes by declaration",
            "single-dialect vocabulary",
            "the input's dialect, in place",
        ],
    ),
    (
        "fixed_inplace.rs",
        "acceptance",
        [
            "Standard (value-level: apply_standard picks the walk once; apply = Tolerant)",
            "payloads opaque by declaration; authored words lawful under the declared standard \
             (Tolerant may pad to the slot)",
            "n/a: staging judges nothing",
            "re-ingests under the declared standard (canonical closure exactly when declared)",
        ],
    ),
    (
        "fixed_inplace.rs",
        "backing",
        [
            "in-place: borrowed mutably, the source allocation is the output",
            "borrowed rule payloads (single copy at the write loop)",
            "caller-slab lanes, job-local (tables + stacks + write list)",
            "the input allocation itself — zero output allocation",
        ],
    ),
    (
        "fixed_inplace.rs",
        "revision",
        [
            "n/a: the buffer mutates only past the fault barrier (commit-only)",
            "n/a: rules are caller-owned plans",
            "n/a: no log (commit-only)",
            "n/a: publication is not revision",
        ],
    ),
    (
        "fixed_inplace.rs",
        "scratch",
        [
            "n/a: the axis governs working memory, not the source",
            "n/a: rule payloads ride borrowed; the write loop copies them straight into the \
             buffer",
            "fixed scratch: matcher lanes, walk stacks, and the write list carved from one \
             caller slab — capacities derived from the rule set and depth bound, the write \
             count plan-declared; exhaustion refuses before the fault barrier, apply_budget \
             reads per-lane high-water",
            "n/a: the buffer is the output (in-place), not scratch",
        ],
    ),
    // ── convert ──
    (
        "convert.rs",
        "intent",
        [
            "write",
            "n/a: conversion takes no payloads (framing re-authors, values ride verbatim)",
            "n/a: machine-internal",
            "the derived document",
        ],
    ),
    (
        "convert.rs",
        "presence",
        [
            "buffered",
            "n/a: conversion takes no payloads",
            "per-cell inter-pass ledger (groupless: converted-group bodies; grouped: every \
             crossed LEN, clean ones included, plus the program's matcher tables) + frame \
             stack, job-local",
            "buffered Vec or caller sink (convert_sink; Err hands it nothing)",
        ],
    ),
    (
        "convert.rs",
        "designation",
        [
            "static",
            "n/a: conversion takes no payloads",
            "n/a: retention is the axis's own mechanism",
            "n/a: outputs carry no record identities (grouped-output designates by compiled \
             Program; groupless-output converts the whole syntax-identified group population — \
             the degenerate static designation, authored by the cell itself)",
        ],
    ),
    (
        "convert.rs",
        "dialect",
        [
            "the output pole's opposite, per twin (grouped-output reads groupless, \
             groupless-output reads grouped)",
            "n/a: conversion takes no payloads",
            "both dialects' wire vocabularies: the input's cursor, the output's emission table",
            "the named output dialect, unconditionally — crossing is the cell's one job",
        ],
    ),
    (
        "convert.rs",
        "acceptance",
        [
            "Standard (value-level: new picks the walk engine once)",
            "n/a: conversion takes no payloads",
            "n/a: staging judges nothing",
            "Tolerant always; CanonicalMinimal exactly when every padded source word was \
             converted framing or (groupless-output) sat inside a converted group's \
             now-opaque body (each cell's module doc states its exact closure sentence)",
        ],
    ),
    (
        "convert.rs",
        "backing",
        [
            "borrowed",
            "n/a: conversion takes no payloads",
            "machine-owned ledger + stacks",
            "owned Vec",
        ],
    ),
    (
        "convert.rs",
        "revision",
        [
            "n/a: input immutable",
            "n/a: conversion takes no payloads",
            "n/a: no log (commit-only)",
            "n/a: publication is not revision",
        ],
    ),
    (
        "convert.rs",
        "scratch",
        [
            "n/a: the axis governs working memory",
            "n/a: the axis governs working memory",
            "machine-owned working memory — no caller-memory contract, so the point does not \
             extend into this axis (its line omits it)",
            "n/a: the axis governs working memory",
        ],
    ),
    // ── splice ──
    (
        "splice.rs",
        "intent",
        [
            "write",
            "answer slices consumed at the ask",
            "n/a: machine-internal",
            "the derived document",
        ],
    ),
    (
        "splice.rs",
        "presence",
        [
            "buffered",
            "whole slices, borrowed for one ask (replacements, inserts, commit tails)",
            "layer stack + settle state (met-width holes, or the sink face's overlay), job-local",
            "buffered Vec or caller sink (splice_sink; Err hands it nothing)",
        ],
    ),
    (
        "splice.rs",
        "designation",
        [
            "online",
            "n/a: answers carry no occurrences",
            "n/a: retention is the axis's own mechanism",
            "n/a: outputs carry no record identities (verdicts fire once, at delivery)",
        ],
    ),
    (
        "splice.rs",
        "dialect",
        [
            "per twin",
            "answer bytes are the caller's declaration, accounted never parsed",
            "single-dialect vocabulary",
            "the input's dialect (cross-dialect conversion = the convert cells)",
        ],
    ),
    (
        "splice.rs",
        "acceptance",
        [
            "Standard (value-level)",
            "answers are the caller's declaration; authored words minimal",
            "n/a: staging judges nothing",
            "the declared standard, modulo answered bytes",
        ],
    ),
    (
        "splice.rs",
        "backing",
        [
            "borrowed",
            "transient borrows, consumed before the next ask (commit tails staged once)",
            "machine-owned stacks; the sink face adds overlay + staging stores",
            "owned Vec (fresh or appended at a mark) or caller sink",
        ],
    ),
    (
        "splice.rs",
        "revision",
        [
            "n/a: input immutable",
            "n/a: answers emit or stage immediately",
            "n/a: no log (commit-only)",
            "Vec faces truncate to their mark on Err; the sink face hands nothing",
        ],
    ),
    (
        "splice.rs",
        "scratch",
        [
            "n/a: the axis governs working memory",
            "n/a: the axis governs working memory",
            "machine-owned working memory — no caller-memory contract, so the point does not \
             extend into this axis (its line omits it)",
            "n/a: the axis governs working memory",
        ],
    ),
    // ── patch ──
    (
        "patch.rs",
        "intent",
        ["write", "payloads staged for the save", "n/a: machine-internal", "the derived document"],
    ),
    (
        "patch.rs",
        "presence",
        [
            "buffered",
            "whole slices, borrowed scatter (parts), or staged frames (begin_*_payload)",
            "row arena + stores, patch-lived",
            "buffered Vec or caller sink (save_sink; Err hands it nothing)",
        ],
    ),
    (
        "patch.rs",
        "designation",
        [
            "offline",
            "opaque by declaration (authored re-edit = composition: reopen the payload bytes \
             as their own patch); designations name original source occurrences — local \
             transfers ride coordinates, imports land the exact record bytes",
            "n/a: retention is the axis's own mechanism",
            "handles + narrowest resolve both ways; save_spans maps them into the output",
        ],
    ),
    (
        "patch.rs",
        "dialect",
        [
            "per twin",
            "opaque interiors by declaration",
            "single-dialect vocabulary",
            "the input's dialect (cross-dialect conversion = the convert cells)",
        ],
    ),
    (
        "patch.rs",
        "acceptance",
        [
            "tolerant (type-level)",
            "opaque by declaration; authored words minimal",
            "width carriage: tolerant stores met widths",
            "save/save_into/save_sink guarantee Tolerant; \
             save_canonical/save_canonical_into/save_canonical_sink guarantee \
             CanonicalMinimal; non-materialized (unopened/faulted/refused) and authored \
             LEN interiors are opaque declarations",
        ],
    ),
    (
        "patch.rs",
        "backing",
        [
            "borrowed (the transfer-tenure owned twin = adopt)",
            "per machine type (A3 form): Patch mixed — borrowed default, whole or scatter + \
             _copy and staged-frame twins ('p role lifetime) — BorrowPatch borrowed-only (no \
             copied column), CopyPatch copy-only (no 'p)",
            "machine-owned rows + stores",
            "owned Vec",
        ],
    ),
    (
        "patch.rs",
        "revision",
        [
            "n/a: input immutable",
            "re-set swaps the slot; abandoned copies inert (commit-only trade)",
            "n/a: no log (commit-only)",
            "n/a: publication is not revision",
        ],
    ),
    (
        "patch.rs",
        "scratch",
        [
            "n/a: the axis governs working memory",
            "n/a: the axis governs working memory",
            "machine-owned working memory — no caller-memory contract, so the point does not \
             extend into this axis (its line omits it)",
            "n/a: the axis governs working memory",
        ],
    ),
    // ── fixed_patch ──
    (
        "fixed_patch.rs",
        "intent",
        ["write", "payloads staged for the save", "n/a: machine-internal", "the derived document"],
    ),
    (
        "fixed_patch.rs",
        "presence",
        [
            "buffered",
            "whole slices, borrowed scatter (parts), or staged frames (begin_*_payload)",
            "row arena + stores over caller-slab lanes, patch-lived",
            "caller slice (save_into) or caller sink (save_sink; Err hands it nothing)",
        ],
    ),
    (
        "fixed_patch.rs",
        "designation",
        [
            "offline",
            "opaque by declaration (authored re-edit = composition: reopen the payload bytes \
             as their own patch)",
            "n/a: retention is the axis's own mechanism",
            "handles + narrowest resolve both ways (no save-side span table: that face would \
             allocate its product)",
        ],
    ),
    (
        "fixed_patch.rs",
        "dialect",
        [
            "per twin",
            "opaque interiors by declaration",
            "single-dialect vocabulary",
            "the input's dialect (cross-dialect conversion = the convert cells)",
        ],
    ),
    (
        "fixed_patch.rs",
        "acceptance",
        [
            "tolerant (type-level)",
            "opaque by declaration; authored words minimal",
            "width carriage: tolerant stores met widths",
            "save_into/save_sink guarantee Tolerant; save_canonical_into/save_canonical_sink \
             guarantee CanonicalMinimal; non-materialized (unopened/faulted/refused) and \
             authored LEN interiors are opaque declarations",
        ],
    ),
    (
        "fixed_patch.rs",
        "backing",
        [
            "borrowed (no owned fixed twin exists: an owned tenure is a heap object)",
            "per machine type (A3 form): Patch mixed — borrowed default, whole or scatter + \
             _copy and staged-frame twins ('p role lifetime) — BorrowPatch borrowed-only (no \
             copied column), CopyPatch copy-only (no 'p)",
            "caller-slab lanes under the capacity contract",
            "caller slice or sink — no owned Vec face exists",
        ],
    ),
    (
        "fixed_patch.rs",
        "revision",
        [
            "n/a: input immutable",
            "re-set swaps the slot; abandoned copies inert (commit-only trade)",
            "n/a: no log (commit-only)",
            "n/a: publication is not revision",
        ],
    ),
    (
        "fixed_patch.rs",
        "scratch",
        [
            "n/a: the axis governs working memory, not the source",
            "staged _copy bytes land in the slab's byte pool (plan-priced, cumulative)",
            "fixed scratch: one caller slab carved once at the door — Plan::bytes prices it \
             exactly for any address, budget() reads per-role high-water, exhaustion is a \
             deterministic refusal naming the lane (ScratchRole)",
            "n/a: output is not scratch — save_into writes the caller's slice, sinks hand \
             borrowed pieces",
        ],
    ),
    // ── markup ──
    (
        "markup.rs",
        "intent",
        [
            "write",
            "payloads staged for revision and save",
            "n/a: machine-internal",
            "the derived document",
        ],
    ),
    (
        "markup.rs",
        "presence",
        [
            "buffered",
            "whole slices or fallible staged frames (one logged transition at close)",
            "row arena + store + log, markup-lived",
            "owned Vec (save; reopens through the borrow door), caller Vec (save_into; Err \
             leaves it untouched), or caller sink (save_sink; Err hands it nothing)",
        ],
    ),
    (
        "markup.rs",
        "designation",
        [
            "offline",
            "opaque by declaration (authored interiors descend); designations name original \
             source occurrences — local transfers ride coordinates, imports land the exact \
             record bytes",
            "n/a: retention is the axis's own mechanism",
            "handles are machine-local, not save-killed: saving takes &self and every handle stays valid in its machine; cross-save identity is save_spans + narrowest on the reopened bytes",
        ],
    ),
    (
        "markup.rs",
        "dialect",
        [
            "per twin",
            "opaque interiors by declaration",
            "single-dialect vocabulary",
            "the input's dialect (cross-dialect conversion = the convert cells)",
        ],
    ),
    (
        "markup.rs",
        "acceptance",
        [
            "tolerant (type-level)",
            "opaque by declaration; authored words minimal",
            "width carriage: rows store the framing widths the scan met (the group end tag \
             included)",
            "save/save_into/save_sink guarantee Tolerant; \
             save_canonical/save_canonical_into/save_canonical_sink guarantee \
             CanonicalMinimal; non-materialized (unopened/faulted/refused) and authored \
             LEN interiors are opaque declarations",
        ],
    ),
    (
        "markup.rs",
        "backing",
        [
            "borrowed (no tenure transfer: open borrows and copies zero bytes, a refusal never \
             touched the buffer, and source answers the borrow at its full lifetime)",
            "per machine type (A3 form): Markup copy-only — payloads staged at the command, \
             staged-frame doors, no payload lifetime — BorrowMarkup borrowed-only (one \
             immutable slot per install, append-only so undo coordinates keep their bytes, no \
             staged frames, 'p beside the source borrow; saves copy each live payload once) — \
             MixMarkup mixed (borrowed default + _copy and staged-frame twins, one tagged \
             immutable slot per install either way, 'p beside the source borrow)",
            "machine-owned columns beside the borrowed source",
            "owned Vec",
        ],
    ),
    (
        "markup.rs",
        "revision",
        [
            "n/a: input immutable (the caller's slice, never taken)",
            "payload coordinates are historical: one immutable slot per install, and revert \
             restores the coordinate — never bytes copied into the log",
            "revisable: the transition log (revert_all restores the padded source byte-exactly)",
            "n/a: publication is not revision",
        ],
    ),
    (
        "markup.rs",
        "scratch",
        [
            "n/a: the axis governs working memory",
            "n/a: the axis governs working memory",
            "machine-owned working memory — no caller-memory contract, so the point does not \
             extend into this axis (its line omits it)",
            "n/a: the axis governs working memory",
        ],
    ),
    // ── adopt ──
    (
        "adopt.rs",
        "intent",
        ["write", "payloads staged for the save", "n/a: machine-internal", "the derived document"],
    ),
    (
        "adopt.rs",
        "presence",
        [
            "buffered",
            "whole slices, borrowed scatter (parts), or staged frames (begin_*_payload)",
            "row arena + stores, adopt-lived",
            "buffered Vec or caller sink (save_sink; Err hands it nothing)",
        ],
    ),
    (
        "adopt.rs",
        "designation",
        [
            "offline",
            "opaque by declaration (authored re-edit = composition: reopen the payload bytes \
             as their own adopt); designations name original source occurrences — local \
             transfers ride coordinates, imports land the exact record bytes",
            "n/a: retention is the axis's own mechanism",
            "handles + narrowest resolve both ways; save_spans maps them into the output",
        ],
    ),
    (
        "adopt.rs",
        "dialect",
        [
            "per twin",
            "opaque interiors by declaration",
            "single-dialect vocabulary",
            "the input's dialect (cross-dialect conversion = the convert cells)",
        ],
    ),
    (
        "adopt.rs",
        "acceptance",
        [
            "tolerant (type-level)",
            "opaque by declaration; authored words minimal",
            "width carriage: tolerant stores met widths",
            "save/save_into/save_sink guarantee Tolerant; \
             save_canonical/save_canonical_into/save_canonical_sink guarantee \
             CanonicalMinimal; non-materialized (unopened/faulted/refused) and authored \
             LEN interiors are opaque declarations",
        ],
    ),
    (
        "adopt.rs",
        "backing",
        [
            "owned (transfer tenure: the buffer moves in; refusal returns it; into_source releases it)",
            "per machine type (A3 form): Adopt mixed — borrowed default, whole or scatter + \
             _copy and staged-frame twins ('p role lifetime) — BorrowAdopt borrowed-only (no \
             copied column), CopyAdopt copy-only (no lifetimes at all)",
            "machine-owned rows + stores over the owned source",
            "owned Vec",
        ],
    ),
    (
        "adopt.rs",
        "revision",
        [
            "n/a: input immutable (released whole by into_source)",
            "re-set swaps the slot; abandoned copies inert (commit-only trade)",
            "n/a: no log (commit-only)",
            "n/a: publication is not revision",
        ],
    ),
    (
        "adopt.rs",
        "scratch",
        [
            "n/a: the axis governs working memory",
            "n/a: the axis governs working memory",
            "machine-owned working memory — no caller-memory contract, so the point does not \
             extend into this axis (its line omits it)",
            "n/a: the axis governs working memory",
        ],
    ),
    // ── draft ──
    (
        "draft.rs",
        "intent",
        [
            "write",
            "payloads staged for revision and save",
            "n/a: machine-internal",
            "the derived document",
        ],
    ),
    (
        "draft.rs",
        "presence",
        [
            "buffered",
            "whole slices or fallible staged frames (one logged transition at close)",
            "row arena + store + log, draft-lived",
            "owned Vec (save; reopens through the move door), caller Vec (save_into; Err \
             leaves it untouched), or caller sink (save_sink; Err hands it nothing)",
        ],
    ),
    (
        "draft.rs",
        "designation",
        [
            "offline",
            "opaque by declaration (authored interiors descend); designations name original \
             source occurrences — local transfers ride coordinates, imports land the exact \
             record bytes",
            "n/a: retention is the axis's own mechanism",
            "handles are machine-local, not save-killed: saving takes &self and every handle stays valid in its machine; cross-save identity is save_spans + narrowest on the reopened bytes",
        ],
    ),
    (
        "draft.rs",
        "dialect",
        [
            "per twin",
            "opaque interiors by declaration",
            "single-dialect vocabulary",
            "the input's dialect (cross-dialect conversion = the convert cells)",
        ],
    ),
    (
        "draft.rs",
        "acceptance",
        [
            "tolerant (type-level)",
            "opaque by declaration; authored words minimal",
            "width carriage: rows store the framing widths the scan met (the group end tag \
             included)",
            "save/save_into/save_sink guarantee Tolerant; \
             save_canonical/save_canonical_into/save_canonical_sink guarantee \
             CanonicalMinimal; non-materialized (unopened/faulted/refused) and authored \
             LEN interiors are opaque declarations",
        ],
    ),
    (
        "draft.rs",
        "backing",
        [
            "owned (transfer tenure: the buffer moves in; refusal returns it; into_source \
             releases it)",
            "per machine type (A3 form): Draft copy-only — payloads staged at the command, \
             staged-frame doors, no payload lifetime — BorrowDraft borrowed-only (one \
             immutable slot per install, append-only so undo coordinates keep their bytes, no \
             staged frames, 'p on the machine; saves copy each live payload once) — MixDraft \
             mixed (borrowed default + _copy and staged-frame twins, one tagged immutable \
             slot per install either way, 'p on the machine)",
            "machine-owned columns",
            "owned Vec",
        ],
    ),
    (
        "draft.rs",
        "revision",
        [
            "n/a: input immutable (released whole by into_source)",
            "payload coordinates are historical: one immutable slot per install, and revert \
             restores the coordinate — never bytes copied into the log",
            "revisable: the transition log (revert_all restores the padded source byte-exactly)",
            "n/a: publication is not revision",
        ],
    ),
    (
        "draft.rs",
        "scratch",
        [
            "n/a: the axis governs working memory",
            "n/a: the axis governs working memory",
            "machine-owned working memory — no caller-memory contract, so the point does not \
             extend into this axis (its line omits it)",
            "n/a: the axis governs working memory",
        ],
    ),
    // ── amend ──
    (
        "amend.rs",
        "intent",
        ["write", "payloads staged for the save", "n/a: machine-internal", "the derived document"],
    ),
    (
        "amend.rs",
        "presence",
        [
            "buffered",
            "whole slices, borrowed scatter (parts), or staged frames (begin_*_payload)",
            "row arena + stores, amend-lived",
            "buffered Vec or caller sink (save_sink; Err hands it nothing)",
        ],
    ),
    (
        "amend.rs",
        "designation",
        [
            "offline",
            "opaque by declaration (authored re-edit = composition: reopen the payload bytes \
             as their own amend); designations name original source occurrences — local \
             transfers ride coordinates, imports land the exact record bytes",
            "n/a: retention is the axis's own mechanism",
            "handles + narrowest resolve both ways; save_spans maps them into the output",
        ],
    ),
    (
        "amend.rs",
        "dialect",
        [
            "per twin",
            "opaque interiors by declaration",
            "single-dialect vocabulary",
            "the input's dialect (cross-dialect conversion = the convert cells)",
        ],
    ),
    (
        "amend.rs",
        "acceptance",
        [
            "canonical (type-level)",
            "opaque by declaration; authored words minimal",
            "width erasure: canonical admission stores none",
            "CanonicalMinimal; authored payload interiors ride as declared",
        ],
    ),
    (
        "amend.rs",
        "backing",
        [
            "borrowed (the transfer-tenure owned twin = intake)",
            "per machine type (A3 form): Amend mixed — borrowed default, whole or scatter + \
             _copy and staged-frame twins ('p role lifetime) — BorrowAmend borrowed-only (no \
             copied column), CopyAmend copy-only (no 'p)",
            "machine-owned rows + stores",
            "owned Vec",
        ],
    ),
    (
        "amend.rs",
        "revision",
        [
            "n/a: input immutable",
            "re-set swaps the slot; abandoned copies inert (commit-only trade)",
            "n/a: no log (commit-only)",
            "n/a: publication is not revision",
        ],
    ),
    (
        "amend.rs",
        "scratch",
        [
            "n/a: the axis governs working memory",
            "n/a: the axis governs working memory",
            "machine-owned working memory — no caller-memory contract, so the point does not \
             extend into this axis (its line omits it)",
            "n/a: the axis governs working memory",
        ],
    ),
    // ── review ──
    (
        "review.rs",
        "intent",
        [
            "write",
            "payloads staged for revision and save",
            "n/a: machine-internal",
            "the derived document",
        ],
    ),
    (
        "review.rs",
        "presence",
        [
            "buffered",
            "whole slices or fallible staged frames (one logged transition at close)",
            "row arena + store + log, review-lived",
            "owned Vec (save; reopens through the borrow door), caller Vec (save_into; Err \
             leaves it untouched), or caller sink (save_sink; Err hands it nothing)",
        ],
    ),
    (
        "review.rs",
        "designation",
        [
            "offline",
            "opaque by declaration (authored interiors descend); designations name original \
             source occurrences — local transfers ride coordinates, imports land the exact \
             record bytes",
            "n/a: retention is the axis's own mechanism",
            "handles are machine-local, not save-killed: saving takes &self and every handle stays valid in its machine; cross-save identity is save_spans + narrowest on the reopened bytes",
        ],
    ),
    (
        "review.rs",
        "dialect",
        [
            "per twin",
            "opaque interiors by declaration",
            "single-dialect vocabulary",
            "the input's dialect (cross-dialect conversion = the convert cells)",
        ],
    ),
    (
        "review.rs",
        "acceptance",
        [
            "canonical (type-level)",
            "opaque by declaration; authored words minimal",
            "width erasure: canonical admission stores none",
            "CanonicalMinimal; authored payload interiors ride as declared",
        ],
    ),
    (
        "review.rs",
        "backing",
        [
            "borrowed (no tenure transfer: open borrows and copies zero bytes, a refusal never \
             touched the buffer, and source answers the borrow at its full lifetime)",
            "per machine type (A3 form): Review copy-only — payloads staged at the command, \
             staged-frame doors, no payload lifetime — BorrowReview borrowed-only (one \
             immutable slot per install, append-only so undo coordinates keep their bytes, no \
             staged frames, 'p beside the source borrow; saves copy each live payload once) — \
             MixReview mixed (borrowed default + _copy and staged-frame twins, one tagged \
             immutable slot per install either way, 'p beside the source borrow)",
            "machine-owned columns beside the borrowed source",
            "owned Vec",
        ],
    ),
    (
        "review.rs",
        "revision",
        [
            "n/a: input immutable (the caller's slice, never taken)",
            "payload coordinates are historical: one immutable slot per install, and revert \
             restores the coordinate — never bytes copied into the log",
            "revisable: the transition log (revert_all restores the source byte-exactly)",
            "n/a: publication is not revision",
        ],
    ),
    (
        "review.rs",
        "scratch",
        [
            "n/a: the axis governs working memory",
            "n/a: the axis governs working memory",
            "machine-owned working memory — no caller-memory contract, so the point does not \
             extend into this axis (its line omits it)",
            "n/a: the axis governs working memory",
        ],
    ),
    // ── intake ──
    (
        "intake.rs",
        "intent",
        ["write", "payloads staged for the save", "n/a: machine-internal", "the derived document"],
    ),
    (
        "intake.rs",
        "presence",
        [
            "buffered",
            "whole slices, borrowed scatter (parts), or staged frames (begin_*_payload)",
            "row arena + stores, intake-lived",
            "buffered Vec or caller sink (save_sink; Err hands it nothing)",
        ],
    ),
    (
        "intake.rs",
        "designation",
        [
            "offline",
            "opaque by declaration (authored re-edit = composition: reopen the payload bytes \
             as their own intake); designations name original source occurrences — local \
             transfers ride coordinates, imports land the exact record bytes",
            "n/a: retention is the axis's own mechanism",
            "handles + narrowest resolve both ways; save_spans maps them into the output",
        ],
    ),
    (
        "intake.rs",
        "dialect",
        [
            "per twin",
            "opaque interiors by declaration",
            "single-dialect vocabulary",
            "the input's dialect (cross-dialect conversion = the convert cells)",
        ],
    ),
    (
        "intake.rs",
        "acceptance",
        [
            "canonical (type-level)",
            "opaque by declaration; authored words minimal",
            "width erasure: canonical admission stores none",
            "CanonicalMinimal; authored payload interiors ride as declared",
        ],
    ),
    (
        "intake.rs",
        "backing",
        [
            "owned (transfer tenure: the buffer moves in; refusal returns it; into_source releases it)",
            "per machine type (A3 form): Intake mixed — borrowed default, whole or scatter + \
             _copy and staged-frame twins ('p role lifetime) — BorrowIntake borrowed-only (no \
             copied column), CopyIntake copy-only (no lifetimes at all)",
            "machine-owned rows + stores over the owned source",
            "owned Vec",
        ],
    ),
    (
        "intake.rs",
        "revision",
        [
            "n/a: input immutable (released whole by into_source)",
            "re-set swaps the slot; abandoned copies inert (commit-only trade)",
            "n/a: no log (commit-only)",
            "n/a: publication is not revision",
        ],
    ),
    (
        "intake.rs",
        "scratch",
        [
            "n/a: the axis governs working memory",
            "n/a: the axis governs working memory",
            "machine-owned working memory — no caller-memory contract, so the point does not \
             extend into this axis (its line omits it)",
            "n/a: the axis governs working memory",
        ],
    ),
    // ── session ──
    (
        "session.rs",
        "intent",
        [
            "write",
            "payloads staged for revision and save",
            "n/a: machine-internal",
            "the derived document",
        ],
    ),
    (
        "session.rs",
        "presence",
        [
            "buffered",
            "whole slices or fallible staged frames (one logged transition at close)",
            "row arena + store + log, session-lived",
            "sealed DocBytes, portable Vec (save_into; Err leaves it untouched), or caller sink (save_sink; Err hands it nothing)",
        ],
    ),
    (
        "session.rs",
        "designation",
        [
            "offline",
            "opaque by declaration (authored interiors descend); designations name original \
             source occurrences — local transfers ride coordinates, imports land the exact \
             record bytes",
            "n/a: retention is the axis's own mechanism",
            "handles are machine-local, not save-killed: saving takes &self and every handle stays valid in its machine; cross-save identity is save_spans + narrowest on the reopened bytes",
        ],
    ),
    (
        "session.rs",
        "dialect",
        [
            "per twin",
            "opaque interiors by declaration",
            "single-dialect vocabulary",
            "the input's dialect (cross-dialect conversion = the convert cells)",
        ],
    ),
    (
        "session.rs",
        "acceptance",
        [
            "canonical (type-level)",
            "opaque by declaration; authored words minimal",
            "width erasure: canonical admission stores none",
            "CanonicalMinimal; authored payload interiors ride as declared",
        ],
    ),
    (
        "session.rs",
        "backing",
        [
            "owned",
            "per machine type (A3 form): Session copy-only — payloads staged at the command, \
             staged-frame doors, no payload lifetime — BorrowSession borrowed-only (one \
             immutable slot per install, append-only so undo coordinates keep their bytes, no \
             staged frames, 'p on the machine; saves copy each live payload once) — \
             MixSession mixed (borrowed default + _copy and staged-frame twins, one tagged \
             immutable slot per install either way, 'p on the machine; no priced door)",
            "machine-owned columns",
            "owned-local DocBytes; save_into gives the Send product (portability = composition; no concurrency axis exists)",
        ],
    ),
    (
        "session.rs",
        "revision",
        [
            "n/a: input immutable",
            "payload coordinates are historical: one immutable slot per install, and revert \
             restores the coordinate — never bytes copied into the log",
            "revisable: the transition log",
            "n/a: publication is not revision",
        ],
    ),
    (
        "session.rs",
        "scratch",
        [
            "n/a: the axis governs working memory",
            "n/a: the axis governs working memory",
            "machine-owned working memory — no caller-memory contract, so the point does not \
             extend into this axis (its line omits it)",
            "n/a: the axis governs working memory",
        ],
    ),
    // ── rewire ──
    (
        "rewire.rs",
        "intent",
        [
            "write",
            "bound action values consumed at emit",
            "n/a: machine-internal",
            "the derived document",
        ],
    ),
    (
        "rewire.rs",
        "presence",
        [
            "stream",
            "whole slices bound at construction (actions live with the program)",
            "bounded carry + staged head + matcher layers",
            "stream callback, incremental",
        ],
    ),
    (
        "rewire.rs",
        "designation",
        [
            "static",
            "n/a: bound values carry no occurrences; host-source transfer is relation-empty \
             (no stream content is retained) — external records inject as composition",
            "n/a: retention is the axis's own mechanism",
            "n/a: outputs carry no record identities (actions match paths, not records)",
        ],
    ),
    (
        "rewire.rs",
        "dialect",
        [
            "per twin",
            "opaque interiors by declaration",
            "single-dialect vocabulary",
            "the input's dialect (cross-dialect conversion = the convert cells)",
        ],
    ),
    (
        "rewire.rs",
        "acceptance",
        [
            "Standard (value-level)",
            "opaque by declaration; bound values author minimal",
            "n/a: staging judges nothing",
            "the declared standard, modulo bound bytes",
        ],
    ),
    (
        "rewire.rs",
        "backing",
        [
            "n/a: no retained source (bounded staging only)",
            "borrowed action payloads, emitted at the match",
            "machine-owned carry + tables",
            "caller custody at the sink",
        ],
    ),
    (
        "rewire.rs",
        "revision",
        [
            "n/a: input immutable",
            "n/a: actions are caller-owned bindings",
            "n/a: no log (commit-only)",
            "emitted prefix carries no promise after a fault",
        ],
    ),
    (
        "rewire.rs",
        "scratch",
        [
            "n/a: the axis governs working memory",
            "n/a: the axis governs working memory",
            "machine-owned working memory — no caller-memory contract, so the point does not \
             extend into this axis (its line omits it)",
            "n/a: the axis governs working memory",
        ],
    ),
    // ── transcode ──
    (
        "transcode.rs",
        "intent",
        [
            "write",
            "injected bytes consumed at emit",
            "n/a: machine-internal",
            "the derived document",
        ],
    ),
    (
        "transcode.rs",
        "presence",
        [
            "stream",
            "whole slices per injection or exact-length pulled chunks (the source verbs)",
            "bounded carry + staged tag + stack",
            "stream callback, incremental",
        ],
    ),
    (
        "transcode.rs",
        "designation",
        [
            "online",
            "n/a: injections carry no occurrences; host-source transfer is relation-empty \
             (no stream content is retained) — external records inject as composition",
            "n/a: retention is the axis's own mechanism",
            "n/a: outputs carry no record identities",
        ],
    ),
    (
        "transcode.rs",
        "dialect",
        [
            "per twin",
            "injections are the caller's declaration",
            "single-dialect vocabulary",
            "the input's dialect (cross-dialect conversion = the convert cells)",
        ],
    ),
    (
        "transcode.rs",
        "acceptance",
        [
            "Standard (value-level)",
            "injections are the caller's declaration",
            "n/a: staging judges nothing",
            "the declared standard, modulo injected bytes",
        ],
    ),
    (
        "transcode.rs",
        "backing",
        [
            "n/a: no retained source (bounded staging only)",
            "transient borrows, emitted at the decision point",
            "machine-owned carry",
            "caller custody at the sink",
        ],
    ),
    (
        "transcode.rs",
        "revision",
        [
            "n/a: input immutable",
            "n/a: injections emit immediately",
            "n/a: no log (commit-only)",
            "emitted prefix carries no promise after a fault",
        ],
    ),
    (
        "transcode.rs",
        "scratch",
        [
            "n/a: the axis governs working memory",
            "n/a: the axis governs working memory",
            "machine-owned working memory — no caller-memory contract, so the point does not \
             extend into this axis (its line omits it)",
            "n/a: the axis governs working memory",
        ],
    ),
    // ── stream_adopt ──
    (
        "stream_adopt.rs",
        "intent",
        ["write", "payloads staged for the save", "n/a: machine-internal", "the derived document"],
    ),
    (
        "stream_adopt.rs",
        "presence",
        [
            "stream (feed phase; consumed at finish — the crossing into the buffered editor)",
            "whole slices, borrowed scatter (parts), or staged frames (begin_*_payload), all \
             after the seal",
            "reserved final backing as the varint byte bank + row arena, ingest-lived then \
             adopt-lived",
            "the finished adopt's saves: buffered Vec or caller sink (save_sink; Err hands \
             it nothing)",
        ],
    ),
    (
        "stream_adopt.rs",
        "designation",
        [
            "offline (the finished editor; the feed phase itself answers no queries)",
            "opaque by declaration (authored re-edit = composition: reopen the payload bytes \
             as their own adopt); designations name original source occurrences — local \
             transfers ride coordinates, imports land the exact record bytes",
            "n/a: retention is the axis's own mechanism",
            "handles + narrowest resolve both ways; save_spans maps them into the output",
        ],
    ),
    (
        "stream_adopt.rs",
        "dialect",
        [
            "per twin",
            "opaque interiors by declaration",
            "single-dialect vocabulary",
            "the input's dialect (cross-dialect conversion = the convert cells)",
        ],
    ),
    (
        "stream_adopt.rs",
        "acceptance",
        [
            "tolerant (type-level); every feed admitted against the finished editor's cap \
             before a byte is read",
            "opaque by declaration; authored words minimal",
            "width carriage: tolerant stores met widths",
            "save/save_into/save_sink guarantee Tolerant; \
             save_canonical/save_canonical_into/save_canonical_sink guarantee \
             CanonicalMinimal; non-materialized (unopened/faulted/refused) and authored \
             LEN interiors are opaque declarations",
        ],
    ),
    (
        "stream_adopt.rs",
        "backing",
        [
            "owned — the stream-presence exception: the retained copy IS the offline product \
             (a failure returns it with exact chunk custody; into_source releases it)",
            "per machine type (A3 form): Adopt mixed — borrowed default, whole or scatter + \
             _copy and staged-frame twins ('p role lifetime) — BorrowAdopt borrowed-only (no \
             copied column), CopyAdopt copy-only (no lifetimes at all); each sealed by its \
             own finish door",
            "machine-owned rows + stores over the owned source",
            "owned Vec",
        ],
    ),
    (
        "stream_adopt.rs",
        "revision",
        [
            "n/a: input immutable once fed (released whole by into_source)",
            "re-set swaps the slot; abandoned copies inert (commit-only trade)",
            "n/a: no log (commit-only)",
            "n/a: publication is not revision",
        ],
    ),
    (
        "stream_adopt.rs",
        "scratch",
        [
            "n/a: the axis governs working memory",
            "n/a: the axis governs working memory",
            "machine-owned working memory — no caller-memory contract, so the point does not \
             extend into this axis (its line omits it)",
            "n/a: the axis governs working memory",
        ],
    ),
    // ── stream_draft ──
    (
        "stream_draft.rs",
        "intent",
        [
            "write",
            "payloads staged for revision and save",
            "n/a: machine-internal",
            "the derived document",
        ],
    ),
    (
        "stream_draft.rs",
        "presence",
        [
            "stream (feed phase; consumed at finish — the crossing into the buffered editor)",
            "whole slices or fallible staged frames (one logged transition at close), all \
             after the seal",
            "reserved final backing as the varint byte bank + row arena + layers + root run, \
             ingest-lived then draft-lived",
            "the finished draft's saves: owned Vec (save), caller Vec (save_into; Err leaves \
             it untouched), or caller sink (save_sink; Err hands it nothing)",
        ],
    ),
    (
        "stream_draft.rs",
        "designation",
        [
            "offline (the finished editor; the feed phase itself answers no queries)",
            "opaque by declaration (authored interiors descend); designations name original \
             source occurrences — local transfers ride coordinates, imports land the exact \
             record bytes",
            "n/a: retention is the axis's own mechanism",
            "handles are machine-local, not save-killed: saving takes &self and every handle stays valid in its machine; cross-save identity is save_spans + narrowest on the reopened bytes",
        ],
    ),
    (
        "stream_draft.rs",
        "dialect",
        [
            "per twin",
            "opaque interiors by declaration",
            "single-dialect vocabulary",
            "the input's dialect (cross-dialect conversion = the convert cells)",
        ],
    ),
    (
        "stream_draft.rs",
        "acceptance",
        [
            "tolerant (type-level); every feed admitted against the finished editor's cap \
             before a byte is read",
            "opaque by declaration; authored words minimal",
            "width carriage: rows store the framing widths the feed met (the group end tag \
             included)",
            "save/save_into/save_sink guarantee Tolerant; \
             save_canonical/save_canonical_into/save_canonical_sink guarantee \
             CanonicalMinimal; non-materialized (unopened/faulted/refused) and authored \
             LEN interiors are opaque declarations",
        ],
    ),
    (
        "stream_draft.rs",
        "backing",
        [
            "owned — the stream-presence exception: the retained copy IS the offline product \
             (a failure returns it with exact chunk custody; into_source releases it); every \
             growth edge fallible",
            "per machine type (A3 form): Draft copy-only — payloads staged at the command, \
             staged-frame doors, no payload lifetime — BorrowDraft borrowed-only (one \
             immutable slot per install, append-only so undo coordinates keep their bytes, no \
             staged frames, 'p on the machine; saves copy each live payload once); each \
             sealed by its own finish door",
            "machine-owned columns",
            "owned Vec",
        ],
    ),
    (
        "stream_draft.rs",
        "revision",
        [
            "n/a: input immutable once fed (released whole by into_source)",
            "staged payloads retract with their commands",
            "revisable: the transition log (revert_all restores the fed bytes byte-exactly, \
             padding included)",
            "n/a: publication is not revision",
        ],
    ),
    (
        "stream_draft.rs",
        "scratch",
        [
            "n/a: the axis governs working memory",
            "n/a: the axis governs working memory",
            "machine-owned working memory — no caller-memory contract, so the point does not \
             extend into this axis (its line omits it)",
            "n/a: the axis governs working memory",
        ],
    ),
    // ── stream_intake ──
    (
        "stream_intake.rs",
        "intent",
        ["write", "payloads staged for the save", "n/a: machine-internal", "the derived document"],
    ),
    (
        "stream_intake.rs",
        "presence",
        [
            "stream (feed phase; consumed at finish — the crossing into the buffered editor)",
            "whole slices, borrowed scatter (parts), or staged frames (begin_*_payload), all \
             after the seal",
            "reserved final backing as the varint byte bank + row arena, ingest-lived then \
             intake-lived",
            "the finished intake's saves: buffered Vec or caller sink (save_sink; Err hands \
             it nothing)",
        ],
    ),
    (
        "stream_intake.rs",
        "designation",
        [
            "offline (the finished editor; the feed phase itself answers no queries)",
            "opaque by declaration (authored re-edit = composition: reopen the payload bytes \
             as their own intake); designations name original source occurrences — local \
             transfers ride coordinates, imports land the exact record bytes",
            "n/a: retention is the axis's own mechanism",
            "handles + narrowest resolve both ways; save_spans maps them into the output",
        ],
    ),
    (
        "stream_intake.rs",
        "dialect",
        [
            "per twin",
            "opaque interiors by declaration",
            "single-dialect vocabulary",
            "the input's dialect (cross-dialect conversion = the convert cells)",
        ],
    ),
    (
        "stream_intake.rs",
        "acceptance",
        [
            "canonical (type-level); every feed admitted against the finished editor's cap \
             before a byte is read, every framing word and varint value judged minimal the \
             moment its last byte arrives",
            "opaque by declaration; authored words minimal",
            "width erasure: canonical admission stores none",
            "CanonicalMinimal; authored payload interiors ride as declared",
        ],
    ),
    (
        "stream_intake.rs",
        "backing",
        [
            "owned — the stream-presence exception: the retained copy IS the offline product \
             (a failure returns it with exact chunk custody; into_source releases it)",
            "per machine type (A3 form): Intake mixed — borrowed default, whole or scatter + \
             _copy and staged-frame twins ('p role lifetime) — BorrowIntake borrowed-only (no \
             copied column), CopyIntake copy-only (no lifetimes at all); each sealed by its \
             own finish door",
            "machine-owned rows + stores over the owned source",
            "owned Vec",
        ],
    ),
    (
        "stream_intake.rs",
        "revision",
        [
            "n/a: input immutable once fed (released whole by into_source)",
            "re-set swaps the slot; abandoned copies inert (commit-only trade)",
            "n/a: no log (commit-only)",
            "n/a: publication is not revision",
        ],
    ),
    (
        "stream_intake.rs",
        "scratch",
        [
            "n/a: the axis governs working memory",
            "n/a: the axis governs working memory",
            "machine-owned working memory — no caller-memory contract, so the point does not \
             extend into this axis (its line omits it)",
            "n/a: the axis governs working memory",
        ],
    ),
    // ── replay_rewrite ──
    (
        "replay_rewrite.rs",
        "intent",
        [
            "write",
            "replacement values consumed at emit",
            "n/a: machine-internal",
            "the derived document",
        ],
    ),
    (
        "replay_rewrite.rs",
        "presence",
        [
            "sequential-repeatable (two walks: pass 1 owns every judgment and compiles the \
             edit script, pass 2 is a splicing pump that parses nothing)",
            "whole slices, borrowed for the job",
            "frame stack + edit script + staging arena, job-local — a function of record \
             structure and edit size, never of source length",
            "buffered Vec or caller sink (rewrite_sink; a refusal names the exact handed \
             prefix)",
        ],
    ),
    (
        "replay_rewrite.rs",
        "designation",
        [
            "static",
            "n/a: values carry no occurrences",
            "n/a: retention is the axis's own mechanism",
            "n/a: outputs carry no record identities (rules match patterns, not records)",
        ],
    ),
    (
        "replay_rewrite.rs",
        "dialect",
        [
            "per twin",
            "opaque interiors by declaration",
            "single-dialect vocabulary",
            "the input's dialect (the dialect-crossing machine at this presence is \
             replay_convert)",
        ],
    ),
    (
        "replay_rewrite.rs",
        "acceptance",
        [
            "Standard (value-level: the _standard faces pick the walks once; plain = Tolerant)",
            "opaque by declaration; typed values author minimal",
            "n/a: staging judges nothing",
            "Tolerant always; CanonicalMinimal when every padded word was absent or normalized",
        ],
    ),
    (
        "replay_rewrite.rs",
        "backing",
        [
            "no addressable source is retained — the supply is walked, never held, so the \
             point does not extend into this axis (its line omits it)",
            "borrowed rule payloads (single copy at emit)",
            "machine-owned script + staging arena",
            "owned Vec (fresh or appended at a mark) or caller sink",
        ],
    ),
    (
        "replay_rewrite.rs",
        "revision",
        [
            "n/a: the source value is never written",
            "n/a: rules are caller-owned plans",
            "n/a: no log (commit-only)",
            "the fresh-Vec face returns no product on Err, the append face truncates to its \
             mark, the sink face reports its exact handed prefix with no validity promise",
        ],
    ),
    (
        "replay_rewrite.rs",
        "scratch",
        [
            "n/a: the axis governs working memory",
            "n/a: the axis governs working memory",
            "machine-owned working memory — no caller-memory contract, so the point does not \
             extend into this axis (its line omits it)",
            "n/a: the axis governs working memory",
        ],
    ),
    // ── replay_convert ──
    (
        "replay_convert.rs",
        "intent",
        [
            "write",
            "n/a: conversion takes no payloads (framing re-authors, records ride verbatim)",
            "n/a: machine-internal",
            "the derived document",
        ],
    ),
    (
        "replay_convert.rs",
        "presence",
        [
            "sequential-repeatable (the sink faces are two walks: pass 1 owns every judgment \
             and compiles the edit script with its prefix slots, pass 2 is a splicing pump \
             that parses nothing)",
            "n/a: conversion takes no payloads",
            "frame stack + edit script with prefix slots (grouped-output adds the program's \
             matcher tables), job-local — a function of record structure, never of source \
             length",
            "buffered Vec or caller sink (convert_sink; a refusal names the exact handed \
             prefix)",
        ],
    ),
    (
        "replay_convert.rs",
        "designation",
        [
            "static",
            "n/a: conversion takes no payloads",
            "n/a: retention is the axis's own mechanism",
            "n/a: outputs carry no record identities (grouped-output designates by compiled \
             Program under the three-way law; groupless-output converts the whole \
             syntax-identified group population — the degenerate static designation, \
             authored by the cell itself)",
        ],
    ),
    (
        "replay_convert.rs",
        "dialect",
        [
            "the output pole's opposite, per twin (grouped-output walks groupless, \
             groupless-output walks grouped)",
            "n/a: conversion takes no payloads",
            "both dialects' wire vocabularies: the input's classification table, the \
             output's emission table",
            "the named output dialect, unconditionally — crossing is the cell's one job",
        ],
    ),
    (
        "replay_convert.rs",
        "acceptance",
        [
            "Standard (value-level: the doors pick the walks once)",
            "n/a: conversion takes no payloads",
            "n/a: staging judges nothing",
            "Tolerant always; CanonicalMinimal exactly when every padded source word was \
             converted framing, a re-settled prefix, or (groupless-output) sat inside a \
             converted group's now-opaque body (each cell's module doc states its exact \
             closure sentence)",
        ],
    ),
    (
        "replay_convert.rs",
        "backing",
        [
            "no addressable source is retained — the supply is walked, never held, so the \
             point does not extend into this axis (its line omits it)",
            "n/a: conversion takes no payloads",
            "machine-owned script + stacks",
            "owned Vec (fresh or appended at a mark) or caller sink",
        ],
    ),
    (
        "replay_convert.rs",
        "revision",
        [
            "n/a: the source value is never written",
            "n/a: conversion takes no payloads",
            "n/a: no log (commit-only)",
            "the fresh-Vec face returns no product on Err, the append face truncates to its \
             mark, the sink face reports its exact handed prefix with no validity promise",
        ],
    ),
    (
        "replay_convert.rs",
        "scratch",
        [
            "n/a: the axis governs working memory",
            "n/a: the axis governs working memory",
            "machine-owned working memory — no caller-memory contract, so the point does not \
             extend into this axis (its line omits it)",
            "n/a: the axis governs working memory",
        ],
    ),
    // ── replay_splice ──
    (
        "replay_splice.rs",
        "intent",
        [
            "write",
            "answer slices staged by copy at the ask",
            "n/a: machine-internal",
            "the derived document",
        ],
    ),
    (
        "replay_splice.rs",
        "presence",
        [
            "sequential-repeatable (two walks: one ask walk stages every answer, one splicing \
             walk parses nothing — the rule is absent from the emitter, so a second ask is \
             unspellable)",
            "whole slices, borrowed for one ask and staged by copy (the machine owes the rule \
             nothing after the call returns)",
            "layer stack + edit script + staged answers, job-local — O(answered bytes), never \
             O(source)",
            "buffered Vec or caller sink (splice_sink; a refusal names the exact handed \
             prefix)",
        ],
    ),
    (
        "replay_splice.rs",
        "designation",
        [
            "online",
            "n/a: answers carry no occurrences",
            "n/a: retention is the axis's own mechanism",
            "n/a: outputs carry no record identities (verdicts fire once, at delivery)",
        ],
    ),
    (
        "replay_splice.rs",
        "dialect",
        [
            "per twin",
            "answer bytes are the caller's declaration, accounted never parsed",
            "single-dialect vocabulary",
            "the input's dialect, observed",
        ],
    ),
    (
        "replay_splice.rs",
        "acceptance",
        [
            "Standard (value-level)",
            "answers are the caller's declaration; authored words minimal",
            "n/a: staging judges nothing",
            "the declared standard, modulo answered bytes",
        ],
    ),
    (
        "replay_splice.rs",
        "backing",
        [
            "no addressable source is retained — the supply is walked, never held, so the \
             point does not extend into this axis (its line omits it); LEN payloads are never \
             made contiguous — the two typed phases (head declaration, close verdict) replace \
             the buffered payload-in-hand privilege",
            "transient borrows, staged by copy at the ask",
            "machine-owned stacks + script + staged answers",
            "owned Vec (fresh or appended at a mark) or caller sink",
        ],
    ),
    (
        "replay_splice.rs",
        "revision",
        [
            "n/a: the source value is never written",
            "n/a: answers stage immediately, and a committed LEN cannot late-downgrade to \
             opaque",
            "n/a: no log (commit-only)",
            "the fresh-Vec face returns no product on Err, the append face truncates to its \
             mark, the sink face reports its exact handed prefix with no validity promise",
        ],
    ),
    (
        "replay_splice.rs",
        "scratch",
        [
            "n/a: the axis governs working memory",
            "n/a: the axis governs working memory",
            "machine-owned working memory — no caller-memory contract, so the point does not \
             extend into this axis (its line omits it)",
            "n/a: the axis governs working memory",
        ],
    ),
    // ── overhaul ──
    (
        "overhaul.rs",
        "intent",
        ["write", "payloads staged for the save", "n/a: machine-internal", "the derived document"],
    ),
    (
        "overhaul.rs",
        "presence",
        [
            "sequential-repeatable (one index walk at open; descend, materialize, and fetch \
             are later walks; one splicing save walk — untouched extents ride pass 2 \
             verbatim, byte for byte)",
            "whole slices, retained or staged in machine-owned stores",
            "row arena + authored stores, editor-lived; zero resident source bytes",
            "buffered Vec or caller sink (save_sink; a refusal names the exact handed prefix)",
        ],
    ),
    (
        "overhaul.rs",
        "designation",
        [
            "offline",
            "opaque by declaration (authored re-edit = composition: reopen the payload bytes \
             as their own job)",
            "n/a: retention is the axis's own mechanism",
            "handles + narrowest resolve both ways",
        ],
    ),
    (
        "overhaul.rs",
        "dialect",
        [
            "per twin",
            "opaque interiors by declaration",
            "single-dialect vocabulary",
            "the input's dialect, observed",
        ],
    ),
    (
        "overhaul.rs",
        "acceptance",
        [
            "tolerant (type-level: padded framing admits at open and rides saves verbatim)",
            "opaque by declaration; authored words minimal",
            "width carriage rides the u64 span geometry the rows already store",
            "saves guarantee Tolerant; non-materialized (unopened/faulted/refused) and \
             authored LEN interiors are opaque declarations",
        ],
    ),
    (
        "overhaul.rs",
        "backing",
        [
            "no addressable source is retained — the supply is walked, never held, so the \
             point does not extend into this axis (its line omits it); the one-shot editing \
             over resident bytes is the patch (borrowed) and adopt (owned) cells",
            "three machine forms: mixed Overhaul — borrowed default, whole installs + _copy \
             twins ('p role lifetime) — BorrowOverhaul borrowed-only (no copied column), \
             CopyOverhaul copy-only (no 'p); whole-slice installs only, no staged frames",
            "machine-owned rows + authored stores (re-setting leaves old bytes inert — the \
             commit-only trade)",
            "owned Vec (restored on any refusal) or caller sink",
        ],
    ),
    (
        "overhaul.rs",
        "revision",
        [
            "n/a: the source value is never written",
            "re-set swaps the slot; abandoned copies inert (commit-only trade)",
            "n/a: no log (commit-only)",
            "the owned-product faces restore their buffer on any Err; the sink face reports \
             its exact handed prefix with no validity promise",
        ],
    ),
    (
        "overhaul.rs",
        "scratch",
        [
            "n/a: the axis governs working memory",
            "n/a: the axis governs working memory",
            "machine-owned working memory — no caller-memory contract, so the point does not \
             extend into this axis (its line omits it)",
            "n/a: the axis governs working memory",
        ],
    ),
    // ── maintain ──
    (
        "maintain.rs",
        "intent",
        ["write", "payloads staged for the save", "n/a: machine-internal", "the derived document"],
    ),
    (
        "maintain.rs",
        "presence",
        [
            "sequential-repeatable (one index walk at open; descend, materialize, and fetch \
             are later walks — authored payloads answer resident, walk-free; one splicing \
             save walk — untouched extents ride pass 2 verbatim, byte for byte)",
            "whole slices, retained or staged in machine-owned stores; staged frames copy \
             chunks in",
            "row arena + layers + revision log + authored stores, editor-lived; zero \
             resident source bytes",
            "buffered Vec or caller sink (save_sink; a refusal names the exact handed \
             prefix)",
        ],
    ),
    (
        "maintain.rs",
        "designation",
        [
            "offline",
            "opaque by declaration (authored re-edit = composition: reopen the payload bytes \
             as their own job)",
            "n/a: retention is the axis's own mechanism",
            "handles + narrowest resolve both ways",
        ],
    ),
    (
        "maintain.rs",
        "dialect",
        [
            "per twin",
            "opaque interiors by declaration",
            "single-dialect vocabulary",
            "the input's dialect, observed",
        ],
    ),
    (
        "maintain.rs",
        "acceptance",
        [
            "tolerant (type-level: padded framing admits at open and rides saves verbatim)",
            "opaque by declaration; authored words minimal",
            "met framing widths stored on the rows as input facts beside the banked words",
            "saves guarantee Tolerant; the save_canonical family additionally guarantees \
             CanonicalMinimal over the materialized commitment closure — non-materialized \
             (unopened/faulted) and authored LEN interiors are opaque declarations",
        ],
    ),
    (
        "maintain.rs",
        "backing",
        [
            "no addressable source is retained — the supply is walked, never held, so the \
             point does not extend into this axis (its line omits it); the revisable editing \
             over resident bytes is the markup (borrowed) and draft (owned) cells",
            "three machine forms: copy-only Maintain, borrowed BorrowMaintain ('p role \
             lifetime), mixed MixMaintain (per-install backing with _copy twins and staged \
             frames)",
            "machine-owned rows + append-only stores (slots are never overwritten or \
             truncated — the slot story revert depends on)",
            "owned Vec (restored on any refusal) or caller sink",
        ],
    ),
    (
        "maintain.rs",
        "revision",
        [
            "n/a: the source value is never written",
            "every install appends one immutable slot; a revert's restored coordinate still \
             names the exact bytes its command installed",
            "12-byte log entries with the packed fresh mark; revert restores the scanned \
             reading with zero walks (banked words + stored met widths re-speak it); \
             re-descending a re-sealed source container costs one fresh walk",
            "the owned-product faces restore their buffer on any Err; the sink faces report \
             their exact handed prefix with no validity promise",
        ],
    ),
    (
        "maintain.rs",
        "scratch",
        [
            "n/a: the axis governs working memory",
            "n/a: the axis governs working memory",
            "machine-owned working memory — no caller-memory contract, so the point does not \
             extend into this axis (its line omits it)",
            "n/a: the axis governs working memory",
        ],
    ),
    // ── refit ──
    (
        "refit.rs",
        "intent",
        ["write", "payloads staged for the save", "n/a: machine-internal", "the derived document"],
    ),
    (
        "refit.rs",
        "presence",
        [
            "sequential-repeatable (one index walk at open; descend, materialize, and fetch \
             are later walks; one splicing save walk — untouched extents ride pass 2 \
             verbatim, byte for byte)",
            "whole slices, borrowed scatter (parts), or staged frames (begin_*_payload), \
             retained or staged in machine-owned stores",
            "row arena + authored stores, editor-lived; zero resident source bytes",
            "buffered Vec or caller sink (save_sink; a refusal names the exact handed prefix)",
        ],
    ),
    (
        "refit.rs",
        "designation",
        [
            "offline",
            "opaque by declaration (authored re-edit = composition: reopen the payload bytes \
             as their own job)",
            "n/a: retention is the axis's own mechanism",
            "handles + narrowest resolve both ways",
        ],
    ),
    (
        "refit.rs",
        "dialect",
        [
            "per twin",
            "opaque interiors by declaration",
            "single-dialect vocabulary",
            "the input's dialect, observed",
        ],
    ),
    (
        "refit.rs",
        "acceptance",
        [
            "canonical (type-level: padded framing refuses — whole at the door, parked \
             resident inside a payload — through the shared opaque NonMinimal carrier)",
            "opaque by declaration; authored words minimal",
            "width erasure: canonical admission stores none — every window derives from the \
             record's own facts",
            "CanonicalMinimal outright (untouched extents riding verbatim are already \
             minimal); non-materialized (unopened/faulted) and authored LEN interiors are \
             opaque declarations",
        ],
    ),
    (
        "refit.rs",
        "backing",
        [
            "no addressable source is retained — the supply is walked, never held, so the \
             point does not extend into this axis (its line omits it); the canonical \
             one-shot editing over resident bytes is the amend (borrowed) and intake (owned) \
             cells",
            "three machine forms (the amend triple over S): mixed Refit — borrowed default, \
             whole or scatter + _copy and staged-frame twins ('p role lifetime) — \
             BorrowRefit borrowed-only (no copied column), CopyRefit copy-only (no 'p)",
            "machine-owned rows + authored stores (re-setting leaves old bytes inert — the \
             commit-only trade)",
            "owned Vec (restored on any refusal) or caller sink",
        ],
    ),
    (
        "refit.rs",
        "revision",
        [
            "n/a: the source value is never written",
            "re-set swaps the slot; abandoned copies inert (commit-only trade)",
            "n/a: no log (commit-only)",
            "the owned-product faces restore their buffer on any Err; the sink face reports \
             its exact handed prefix with no validity promise",
        ],
    ),
    (
        "refit.rs",
        "scratch",
        [
            "n/a: the axis governs working memory",
            "n/a: the axis governs working memory",
            "machine-owned working memory — no caller-memory contract, so the point does not \
             extend into this axis (its line omits it)",
            "n/a: the axis governs working memory",
        ],
    ),
    // ── commission ──
    (
        "commission.rs",
        "intent",
        ["write", "payloads staged for the save", "n/a: machine-internal", "the derived document"],
    ),
    (
        "commission.rs",
        "presence",
        [
            "sequential-repeatable (one index walk at open; descend, materialize, and fetch \
             are later walks — authored payloads answer resident, walk-free; one splicing \
             save walk — untouched extents ride pass 2 verbatim, byte for byte)",
            "whole slices, retained or staged in machine-owned stores; staged frames copy \
             chunks in",
            "row arena + layers + revision log + authored stores, editor-lived; zero \
             resident source bytes",
            "buffered Vec or caller sink (save_sink; a refusal names the exact handed \
             prefix)",
        ],
    ),
    (
        "commission.rs",
        "designation",
        [
            "offline",
            "opaque by declaration (authored re-edit = composition: reopen the payload bytes \
             as their own job)",
            "n/a: retention is the axis's own mechanism",
            "handles + narrowest resolve both ways",
        ],
    ),
    (
        "commission.rs",
        "dialect",
        [
            "per twin",
            "opaque interiors by declaration",
            "single-dialect vocabulary",
            "the input's dialect, observed",
        ],
    ),
    (
        "commission.rs",
        "acceptance",
        [
            "canonical (type-level: padded framing refuses — whole at the door, parked \
             resident inside a payload — through the shared opaque NonMinimal carrier)",
            "opaque by declaration; authored words minimal",
            "width erasure: canonical admission stores none — the banked words re-speak \
             scanned readings without a met column",
            "saves guarantee CanonicalMinimal outright — no separate canonical family \
             exists, exactly as on the buffered review twin; non-materialized \
             (unopened/faulted) and authored LEN interiors are opaque declarations",
        ],
    ),
    (
        "commission.rs",
        "backing",
        [
            "no addressable source is retained — the supply is walked, never held, so the \
             point does not extend into this axis (its line omits it); the canonical \
             revisable editing over resident bytes is the review (borrowed) and session \
             (sealed-carrier) cells",
            "three machine forms (the review triple over S): copy-only Commission, borrowed \
             BorrowCommission ('p role lifetime), mixed MixCommission (per-install backing \
             with _copy twins and staged frames)",
            "machine-owned rows + append-only stores (slots are never overwritten or \
             truncated — the slot story revert depends on); every growth edge fallible, \
             booked per edge",
            "owned Vec (restored on any refusal) or caller sink",
        ],
    ),
    (
        "commission.rs",
        "revision",
        [
            "n/a: the source value is never written",
            "every install appends one immutable slot; a revert's restored coordinate still \
             names the exact bytes its command installed",
            "12-byte log entries with the packed fresh mark; revert restores the scanned \
             reading with zero walks (the banked words re-speak it — no met column exists \
             to consult); re-descending a re-sealed source container costs one fresh walk",
            "the owned-product faces restore their buffer on any Err; the sink faces report \
             their exact handed prefix with no validity promise",
        ],
    ),
    (
        "commission.rs",
        "scratch",
        [
            "n/a: the axis governs working memory",
            "n/a: the axis governs working memory",
            "machine-owned working memory — no caller-memory contract, so the point does not \
             extend into this axis (its line omits it)",
            "n/a: the axis governs working memory",
        ],
    ),
    // ── construct ──
    (
        "construct.rs",
        "intent",
        [
            "n/a: no input document",
            "payloads authored into the document",
            "n/a: machine-internal",
            "the authored document",
        ],
    ),
    (
        "construct.rs",
        "presence",
        [
            "n/a: no input document",
            "whole slices or chunked frames (bytes_frame)",
            "owned store + events (the mixed machine adds its borrow table), builder-lived",
            "buffered Vec or caller sink (finish_sink; Err hands it nothing)",
        ],
    ),
    (
        "construct.rs",
        "designation",
        [
            "n/a: no input document",
            "authored payloads carry no occurrences; designated records land byte-exact as \
             canonical roots (push_record)",
            "n/a: retention is the axis's own mechanism",
            "n/a: outputs carry no record identities",
        ],
    ),
    (
        "construct.rs",
        "dialect",
        [
            "n/a: no input document",
            "opaque interiors by declaration",
            "single-dialect vocabulary",
            "the authored dialect (builder twin)",
        ],
    ),
    (
        "construct.rs",
        "acceptance",
        [
            "n/a: no input document",
            "raw and payload interiors are the caller's declaration",
            "n/a: staging judges nothing",
            "CanonicalMinimal; declared interiors ride as supplied",
        ],
    ),
    (
        "construct.rs",
        "backing",
        [
            "n/a: no input document",
            "per machine type (A3 form): Builder mixed — borrowed default + _copy twins ('p \
             role lifetime) — CopyBuilder copy-only (no borrow table, no 'p)",
            "machine-owned stores",
            "owned Vec",
        ],
    ),
    (
        "construct.rs",
        "revision",
        [
            "n/a: no input document",
            "n/a: pushes commit (no retraction)",
            "n/a: no log (commit-only)",
            "n/a: publication is not revision",
        ],
    ),
    (
        "construct.rs",
        "scratch",
        [
            "n/a: the axis governs working memory",
            "n/a: the axis governs working memory",
            "machine-owned working memory — no caller-memory contract, so the point does not \
             extend into this axis (its line omits it)",
            "n/a: the axis governs working memory",
        ],
    ),
];

fn is_exempt(rel: &str) -> bool {
    EXEMPT.contains(&rel) || rel.ends_with("/tests.rs")
}

/// Which family of concrete machines a file belongs to; points may
/// collide only across families.
fn dialect_family(rel: &str) -> &'static str {
    if rel.ends_with("/grouped.rs") {
        "grouped"
    } else if rel.ends_with("/groupless.rs") {
        "groupless"
    } else {
        "shared"
    }
}

/// Walks `src/` and returns every Rust file as (path relative to
/// `src/`, contents), sorted by path.
fn src_files() -> Vec<(String, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    let mut stack = vec![root.clone()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).expect("src directory is readable") {
            let path = entry.expect("directory entry is readable").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                let rel = path
                    .strip_prefix(&root)
                    .expect("walked file lies under src")
                    .components()
                    .map(|part| part.as_os_str().to_str().expect("source paths are UTF-8"))
                    .collect::<Vec<_>>()
                    .join("/");
                let text = fs::read_to_string(&path).expect("source file is readable");
                files.push((rel, text));
            }
        }
    }
    // The census must have walked something real: an empty or
    // near-empty walk would pass every per-file assertion vacuously.
    assert!(
        files.len() >= ADJUDICATED.len() + EXEMPT.len(),
        "census walked only {} files under src/",
        files.len()
    );
    files.sort();
    files
}

/// The declaration lines found in one file.
fn coordinate_lines(text: &str) -> Vec<&str> {
    text.lines().filter(|line| line.starts_with(MARKER)).collect()
}

/// Splits a declaration line into (value, annotation) entries.
fn parse_entries(rel: &str, line: &str) -> Vec<(String, Option<String>)> {
    let body = line
        .strip_prefix(MARKER)
        .unwrap_or_else(|| panic!("{rel}: line lost its marker: {line:?}"));
    let body = body
        .strip_suffix('.')
        .unwrap_or_else(|| panic!("{rel}: coordinate line must end with a period: {line:?}"));
    body.split(" · ")
        .map(|entry| {
            entry.split_once(" (").map_or_else(
                || (entry.to_owned(), None),
                |(value, rest)| {
                    let annotation = rest
                        .strip_suffix(')')
                        .unwrap_or_else(|| panic!("{rel}: unclosed annotation in entry {entry:?}"));
                    (value.to_owned(), Some(annotation.to_owned()))
                },
            )
        })
        .collect()
}

/// (a) Every scenario module file carries exactly one declaration;
/// strata and internal submodules carry none.
#[test]
fn every_scenario_module_declares_coordinates_exactly_once() {
    for (rel, text) in src_files() {
        let found = coordinate_lines(&text).len();
        if is_exempt(&rel) {
            assert_eq!(found, 0, "{rel}: stratum/internal file must not declare coordinates");
        } else {
            assert_eq!(found, 1, "{rel}: scenario module file must declare coordinates once");
        }
    }
}

/// (b) Every declared entry uses a lawful axis value and, when
/// annotated, a lawful annotation.
#[test]
fn coordinate_values_are_lawful_axis_values() {
    let mut entries_seen = 0_usize;
    for (rel, text) in src_files() {
        for line in coordinate_lines(&text) {
            for (value, annotation) in parse_entries(&rel, line) {
                assert!(
                    value == EXTERIOR
                        || AXES.iter().any(|(_, poles)| poles.contains(&value.as_str())),
                    "{rel}: {value:?} is not a lawful axis value"
                );
                if let Some(annotation) = annotation {
                    assert!(
                        ANNOTATIONS.contains(&annotation.as_str()),
                        "{rel}: {annotation:?} is not a lawful annotation"
                    );
                }
                entries_seen += 1;
            }
        }
    }
    assert!(entries_seen > 0, "census judged no coordinate entries");
}

/// (c) No two machines of one dialect family claim the same point.
#[test]
fn no_two_same_dialect_modules_share_coordinates() {
    let mut claims: BTreeMap<(&'static str, String), Vec<String>> = BTreeMap::new();
    for (rel, text) in src_files() {
        for line in coordinate_lines(&text) {
            let family = dialect_family(&rel);
            claims.entry((family, line.to_owned())).or_default().push(rel.clone());
        }
    }
    assert!(!claims.is_empty(), "census found no coordinate claims");
    for ((family, line), claimants) in claims {
        assert_eq!(
            claimants.len(),
            1,
            "one {family} point claimed twice ({line:?}) by {claimants:?}"
        );
    }
}

/// (d) The declarations equal the adjudication table, both ways: no
/// undeclared scenario file, no unclaimed table row, no drifted
/// coordinates.
#[test]
fn coordinates_match_the_adjudication_table() {
    let table: BTreeMap<&str, &str> = ADJUDICATED.iter().copied().collect();
    assert_eq!(table.len(), ADJUDICATED.len(), "adjudication table repeats a file");

    let mut declared: BTreeMap<String, String> = BTreeMap::new();
    for (rel, text) in src_files() {
        if let Some(line) = coordinate_lines(&text).first() {
            let body = line
                .strip_prefix(MARKER)
                .and_then(|rest| rest.strip_suffix('.'))
                .unwrap_or_else(|| panic!("{rel}: malformed coordinate line {line:?}"));
            declared.insert(rel.clone(), body.to_owned());
        } else {
            assert!(
                !table.contains_key(rel.as_str()),
                "{rel}: adjudicated module lost its coordinate line"
            );
        }
    }

    for (rel, body) in &declared {
        let expected = table
            .get(rel.as_str())
            .unwrap_or_else(|| panic!("{rel}: declares coordinates but is not adjudicated"));
        assert_eq!(body, expected, "{rel}: coordinates drifted from the adjudication table");
    }
    assert_eq!(
        declared.len(),
        table.len(),
        "declared modules and the adjudication table must cover each other exactly"
    );
}

/// The lattice sort key of one declaration: per axis in the
/// declared sequence, the 1-based pole index, with 0 for an axis
/// whose domain is empty at the point (a point that does not extend
/// into an axis precedes every point that does). The exterior sorts
/// after every in-lattice point: the enumeration principle is the
/// lattice, its exterior follows it.
fn lattice_key(rel: &str, line: &str) -> Vec<u32> {
    let entries = parse_entries(rel, line);
    if entries.iter().any(|(value, _)| value == EXTERIOR) {
        return vec![u32::MAX];
    }
    AXES.iter()
        .map(|(_, poles)| {
            entries
                .iter()
                .find_map(|(value, _)| poles.iter().position(|pole| pole == value))
                .map_or(0, |index| u32::try_from(index).expect("pole tables are tiny") + 1)
        })
        .collect()
}

/// Module names appearing in `text`, in file order, restricted to
/// the given set — the shape every enumeration surface reduces to.
fn enumeration_of(
    text: &str,
    pattern: impl Fn(&str) -> Option<String>,
    set: &[String],
) -> Vec<String> {
    text.lines().filter_map(pattern).filter(|name| set.contains(name)).collect()
}

/// (f) Every surface that enumerates the scenario space speaks the
/// lattice order. The order is derived, not chosen: shared-layer
/// points sort by their own coordinate lines under the axis
/// sequence and recorded pole orders, exterior last. Checked
/// surfaces: the adjudication table above (strictly ascending keys,
/// each shared layer followed by its grouped then groupless twins),
/// the Cargo.toml feature block, the crate root's module list and
/// scenario `mod` declarations, and the README module table. Birth
/// order cannot reappear on a pinned surface without turning this
/// red.
#[test]
fn enumeration_surfaces_follow_the_lattice_order() {
    // Pin the table's own order: keys strictly ascend across the
    // shared-layer rows, and each pair of dialect rows follows its
    // shared layer immediately, grouped before groupless.
    let mut modules: Vec<String> = Vec::new();
    let mut previous: Option<Vec<u32>> = None;
    let mut index = 0;
    while index < ADJUDICATED.len() {
        let (rel, body) = ADJUDICATED[index];
        assert!(!rel.contains('/'), "{rel}: expected a shared-layer row at this position");
        let line = format!("{MARKER}{body}.");
        let key = lattice_key(rel, &line);
        if let Some(prev) = &previous {
            assert!(
                *prev < key,
                "{rel}: adjudication table leaves the lattice order (key {key:?} after {prev:?})"
            );
        }
        previous = Some(key);
        let stem = rel.trim_end_matches(".rs");
        for (offset, dialect) in [(1, "grouped"), (2, "groupless")] {
            assert_eq!(
                ADJUDICATED[index + offset].0,
                format!("{stem}/{dialect}.rs"),
                "{stem}: dialect rows must follow their shared layer, grouped then groupless"
            );
        }
        modules.push(stem.to_owned());
        index += 3;
    }

    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let read = |rel: &str| {
        fs::read_to_string(root.join(rel))
            .unwrap_or_else(|error| panic!("{rel} is readable: {error}"))
    };

    // Cargo.toml: scenario feature declarations, grouped before
    // groupless, pairs in lattice order. Feature stems are kebab
    // throughout, so a module underscore (`stream_adopt`) reads as
    // a hyphen in its features (`stream-adopt-*`).
    let expected_features: Vec<String> = modules
        .iter()
        .map(|name| name.replace('_', "-"))
        .flat_map(|name| [format!("{name}-grouped"), format!("{name}-groupless")])
        .collect();
    let manifest = read("Cargo.toml");
    let features = enumeration_of(
        &manifest,
        |line| line.split_once(" = ").map(|(name, _)| name.trim().to_owned()),
        &expected_features,
    );
    assert_eq!(features, expected_features, "Cargo.toml feature block leaves the lattice order");

    // The crate root: the doc's module list and the scenario `mod`
    // declarations.
    let lib = read("src/lib.rs");
    let listed = enumeration_of(
        &lib,
        |line| {
            line.strip_prefix("//! - `")
                .and_then(|rest| rest.split_once('`'))
                .map(|(name, _)| name.to_owned())
        },
        &modules,
    );
    assert_eq!(listed, modules, "crate root module list leaves the lattice order");
    let declared = enumeration_of(
        &lib,
        |line| {
            line.trim()
                .strip_prefix("pub mod ")
                .and_then(|rest| rest.strip_suffix(';'))
                .map(str::to_owned)
        },
        &modules,
    );
    assert_eq!(declared, modules, "crate root mod declarations leave the lattice order");

    // README: the scenario table rows.
    let readme = read("README.md");
    let rows = enumeration_of(
        &readme,
        |line| {
            line.strip_prefix("| `")
                .and_then(|rest| rest.split_once('`'))
                .map(|(name, _)| name.to_owned())
        },
        &modules,
    );
    assert_eq!(rows, modules, "README module table leaves the lattice order");
}

/// The README's count sentences face the tree: the module count
/// answers the adjudication table's shared-layer rows, and the two
/// cell counts answer the manifest's feature roster — the check
/// matrix is every single-feature cell (`default` is a selection,
/// not a cell) plus the no-feature cell, so the matrix digit equals
/// the declaration count with `default` back in. Word-form numbers
/// cannot land here: the digits are parsed straight off the
/// sentence.
#[test]
fn readme_count_sentences_face_the_tree() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let readme = fs::read_to_string(root.join("README.md")).expect("README.md is readable");
    let count_before = |marker: &str| -> usize {
        let line = readme
            .lines()
            .find(|line| line.contains(marker))
            .unwrap_or_else(|| panic!("the README speaks a count beside {marker:?}"));
        let head = &line[..line.find(marker).expect("marker located")];
        let digits: String = head.chars().rev().take_while(char::is_ascii_digit).collect();
        let digits: String = digits.chars().rev().collect();
        digits.parse().unwrap_or_else(|_| panic!("no digit form beside {marker:?}: {line}"))
    };

    let modules = ADJUDICATED.iter().filter(|(rel, _)| !rel.contains('/')).count();
    assert_eq!(
        count_before(" scenario modules"),
        modules,
        "the README module count answers the adjudication table's shared-layer rows"
    );

    let manifest = fs::read_to_string(root.join("Cargo.toml")).expect("Cargo.toml is readable");
    let mut declared = 0_usize;
    let mut in_features = false;
    for line in manifest.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_features = trimmed == "[features]";
            continue;
        }
        if !in_features || trimmed.starts_with('#') {
            continue;
        }
        if let Some((name, _)) = line.split_once(" = ")
            && !name.starts_with(char::is_whitespace)
        {
            declared += 1;
        }
    }
    // The parse must have found the real roster, not a moved header.
    assert!(declared >= 50, "the feature parse found only {declared} entries");
    assert_eq!(
        count_before("-cell `cargo check` matrix"),
        declared,
        "the README matrix count answers the manifest roster plus the no-feature cell"
    );
    assert_eq!(
        count_before(" single-feature cells"),
        declared - 1,
        "the README single-feature count answers the manifest roster without `default`"
    );
}

/// (g) The crate root's shape claim — nothing moves shape under
/// any feature combination — rests on gate monotonicity: features
/// only ever add items. That premise is structural exactly while
/// no negative feature gate and no feature-conjunction gate exists
/// in `src/` — gate meaning shape gate, a condition on an item's
/// existence — so this census pins both inventories at empty
/// (whitespace-normalized scan, so attribute line breaks cannot
/// hide a form). One form is exempt before the scan: a
/// `cfg_attr` whose payloads are lint levels alone
/// (`allow`/`expect` — the replay strata arm `dead_code` exactly
/// while a consumer is absent). A lint attribute adds or removes
/// no item, so its condition — negated or conjoined — is not a
/// shape gate; any other conditional payload (a `derive`, a
/// `repr`) is judged as written, planted controls prove both
/// sides of the exemption, and the stripped count is pinned exact
/// below so a new exempt site cannot enter unnoticed. Feature
/// conjunctions are found structurally:
/// every `all(` group is extracted whole and its top-level
/// conjuncts counted, so a conjunction hiding behind a
/// non-feature first predicate is still seen. Two or more
/// feature-bearing conjuncts is the breaker — two feature axes
/// multiplied. Exactly one is lawful by name: the feature axis
/// stays monotone against fixed non-feature conjuncts, and a
/// feature disjunction inside one conjunct is itself additive.
/// The crate's two lawful shapes: the target×feature gate (the
/// wide-pointer pricing faces exist only where
/// `target_pointer_width = "64"`) and the test×any(features)
/// gate on shared test fixtures. Positive controls: the additive
/// gate shapes and the lawful conjunction forms the crate really
/// uses must be seen by the same scan.
#[test]
fn feature_gates_are_monotone() {
    // Non-monotone negative forms, whitespace-normalized: both
    // spellings of a negative gate, caught anywhere — including
    // inside an `all(` group.
    const BREAKERS: &[&str] = &["not(feature=", "not(any(feature"];

    /// Strips every `cfg_attr` group whose payloads are lint
    /// levels alone, returning the stripped text and the strip
    /// count. The group is cut at its balanced closing parenthesis
    /// and split at its depth-zero commas: the first piece is the
    /// condition, the rest are the attribute payloads, and only
    /// when every payload is an `allow(`/`expect(` does the group
    /// leave the text — anything else stays and is judged as
    /// written.
    fn without_conditional_lint_levels(normalized: &str) -> (String, usize) {
        const OPEN: &str = "cfg_attr(";
        let mut out = String::with_capacity(normalized.len());
        let mut rest = normalized;
        let mut stripped = 0_usize;
        while let Some(at) = rest.find(OPEN) {
            out.push_str(&rest[..at]);
            let tail = &rest[at..];
            let group = &tail[OPEN.len()..];
            let mut depth = 0_usize;
            let mut piece_start = 0_usize;
            let mut payloads_at = None;
            let mut lint_only = true;
            let mut end = None;
            for (offset, c) in group.char_indices() {
                match c {
                    '(' => depth += 1,
                    ')' if depth > 0 => depth -= 1,
                    ')' | ',' if depth == 0 => {
                        let piece = &group[piece_start..offset];
                        if payloads_at.is_none() {
                            payloads_at = Some(offset);
                        } else if !(piece.starts_with("allow(") || piece.starts_with("expect(")) {
                            lint_only = false;
                        }
                        piece_start = offset + 1;
                        if c == ')' {
                            end = Some(offset);
                            break;
                        }
                    }
                    _ => {}
                }
            }
            let Some(end) = end else {
                // An unterminated group is prose, not a gate: keep
                // it and move past the opener.
                out.push_str(OPEN);
                rest = group;
                continue;
            };
            let whole = OPEN.len() + end + 1;
            // A conditionless group (`cfg_attr(x)`) has no payload
            // to exempt.
            if lint_only && payloads_at.is_some_and(|p| p < end) {
                stripped += 1;
            } else {
                out.push_str(&tail[..whole]);
            }
            rest = &tail[whole..];
        }
        out.push_str(rest);
        (out, stripped)
    }

    /// Every `all(` conjunction group in the normalized text,
    /// classified by its top-level conjuncts: two or more
    /// feature-bearing conjuncts break monotonicity (two feature
    /// axes multiplied), exactly one is the lawful
    /// fixed-conjunct×feature form (a `any(feature…)` disjunction
    /// is one conjunct — disjunctions are additive). The group is
    /// cut at its balanced closing parenthesis and split at its
    /// depth-zero commas, so nesting depth and predicate order
    /// cannot hide a member.
    fn conjunctions(normalized: &str) -> (usize, usize) {
        let (mut breaking, mut lawful) = (0, 0);
        for (at, _) in normalized.match_indices("all(") {
            // Anchor on the bare word: `install(`, `.revert_all(`
            // and kin are calls, not cfg predicates.
            if at > 0
                && normalized[..at].ends_with(|c: char| c.is_alphanumeric() || c == '_' || c == '.')
            {
                continue;
            }
            let group = &normalized[at + "all(".len()..];
            let mut depth = 0_usize;
            let mut feature_conjuncts = 0_usize;
            let mut conjunct_start = 0_usize;
            let mut end = group.len();
            for (offset, c) in group.char_indices() {
                match c {
                    '(' => depth += 1,
                    ')' if depth > 0 => depth -= 1,
                    ')' | ',' if depth == 0 => {
                        if group[conjunct_start..offset].contains("feature=") {
                            feature_conjuncts += 1;
                        }
                        conjunct_start = offset + 1;
                        if c == ')' {
                            end = offset;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            // An unterminated group (prose, not a gate) still
            // classifies by the conjuncts it closed.
            if end == group.len() && group[conjunct_start..].contains("feature=") {
                feature_conjuncts += 1;
            }
            match feature_conjuncts {
                0 => {}
                1 => lawful += 1,
                _ => breaking += 1,
            }
        }
        (breaking, lawful)
    }

    // The detector must catch every escape shape and admit the
    // lawful one, or the clean scan below is vacuous. The first
    // three wrappers vary what surrounds the conjunction; the
    // fourth hides it behind a non-feature first predicate (the
    // shape a prefix match missed); the fifth is the lawful
    // target×feature form and must not break.
    for escape in [
        "cfg(all(feature=\"a\",feature=\"b\"))",
        "cfg(any(all(feature=\"a\",feature=\"b\")))",
        "cfg!(all(feature=\"a\",feature=\"b\"))",
        "cfg(all(target_pointer_width=\"64\",feature=\"a\",feature=\"b\"))",
    ] {
        assert_eq!(conjunctions(escape).0, 1, "the detector misses the escape form {escape:?}");
    }
    let lawful_form = "cfg(all(target_pointer_width=\"64\",feature=\"a\"))";
    assert_eq!(conjunctions(lawful_form), (0, 1), "the named lawful form must classify as such");
    let lawful_any = "cfg(all(test,not(miri),any(feature=\"a\",feature=\"b\")))";
    assert_eq!(conjunctions(lawful_any), (0, 1), "a one-conjunct disjunction must stay lawful");
    // A negation inside a conjunction is the string breakers' catch,
    // not the counter's: one feature= plus a not(feature= must trip.
    let negated = "cfg(all(feature=\"a\",not(feature=\"b\")))";
    assert!(
        BREAKERS.iter().any(|b| negated.contains(b)),
        "the breaker set misses the negated-conjunct form {negated:?}"
    );
    // Both sides of the lint-level exemption: the landed allowance
    // form leaves the text, while a non-lint payload and a bare
    // negative gate keep their negations in front of the breakers.
    let landed = "#[cfg_attr(not(any(feature=\"a\",feature=\"b\")),allow(dead_code,reason=\"r\"))]";
    let (clean, strips) = without_conditional_lint_levels(landed);
    assert_eq!(strips, 1, "the stripper misses the landed allowance form");
    assert!(
        !BREAKERS.iter().any(|b| clean.contains(b)),
        "a stripped lint allowance still trips the breakers"
    );
    let derived = "#[cfg_attr(not(feature=\"a\"),derive(Clone))]";
    let (kept, strips) = without_conditional_lint_levels(derived);
    assert_eq!(strips, 0, "a conditional derive is not a lint level");
    assert!(
        BREAKERS.iter().any(|b| kept.contains(b)),
        "a conditional derive's negation left the scan"
    );
    let bare = "cfg(not(feature=\"a\"))";
    let (kept, strips) = without_conditional_lint_levels(bare);
    assert_eq!(strips, 0, "a bare negative gate is not a cfg_attr");
    assert!(BREAKERS.iter().any(|b| kept.contains(b)), "a bare negative gate left the scan");

    let mut lint_levels = 0_usize;
    let mut additive_any = 0_usize;
    let mut additive_plain = 0_usize;
    let mut lawful_seen = 0_usize;
    let mut breakers = Vec::new();
    for (rel, text) in src_files() {
        // Comment lines are prose, not gates: doc examples may
        // lawfully guard a two-cell recipe with a conjunction (the
        // doctest is additive — more features run more examples).
        // Real cfg attributes live on code lines, which the scan
        // keeps in full.
        let normalized: String = text
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .flat_map(|line| line.chars())
            .filter(|c| !c.is_whitespace())
            .collect();
        let (normalized, stripped) = without_conditional_lint_levels(&normalized);
        lint_levels += stripped;
        additive_any += normalized.matches("cfg(any(feature=").count();
        additive_plain += normalized.matches("cfg(feature=").count();
        for form in BREAKERS {
            let hits = normalized.matches(form).count();
            if hits > 0 {
                breakers.push(format!("{rel}: {form:?} ×{hits}"));
            }
        }
        let (breaking, lawful) = conjunctions(&normalized);
        if breaking > 0 {
            breakers.push(format!("{rel}: feature conjunction ×{breaking}"));
        }
        lawful_seen += lawful;
    }
    assert!(
        breakers.is_empty(),
        "non-monotone feature gates in src/ — the shape claim needs re-derivation:\n{}",
        breakers.join("\n")
    );
    // The scan saw the real gate shapes, so the empty inventories
    // above are findings, not a broken instrument.
    assert!(additive_any > 0, "no cfg(any(feature gate seen: the scan is blind");
    assert!(additive_plain > 0, "no cfg(feature gate seen: the scan is blind");
    assert!(lawful_seen > 0, "no lawful conjunction gate seen: the scan is blind");
    // Exact, not merely nonzero: raising the count is a deliberate
    // act recorded with a reason, the digest baseline's bless
    // discipline.
    // Raised 6 → 7 with the maintain cell, lowered back to 6 when
    // the save-compile funding A/B settled on per-edge booking:
    // the surviving expectation covered the commission features,
    // which compiled the per-edge faces yet gated no cell module.
    // Lowered 6 → 4 when the refit and commission cells landed:
    // the two commission-naming expectations (the script's
    // fallible faces, the revising store macro) died with their
    // consumer. The four survivors arm only when no consumer
    // feature at all is on, each reason naming its full list.
    assert_eq!(lint_levels, 4, "the conditional lint-level inventory moved: bless deliberately");
}

/// (j) Fallible-conversion discipline: a `try_from`/`try_into`
/// verdict in live source is consumed by a named judgment (an
/// `Err` arm, an `ok().filter` chain, a documented clamp) — never
/// punched through with `.unwrap()`/`.expect(`. Test modules
/// assert however is convenient and are excluded (`tests.rs`
/// files and inline `#[cfg(test)] mod tests` tails); `unwrap_or*`
/// does not match, since it names its fallback. The matcher is
/// line-shaped, and the judge carries its own negative control: a
/// planted violation fed through the same matcher must trip.
#[test]
fn fallible_conversions_keep_their_refusal_paths_in_live_code() {
    /// True when the line couples a fallible conversion to a
    /// panicking consumption.
    fn trips(line: &str) -> bool {
        let lead = line.trim_start();
        if lead.starts_with("//") {
            return false;
        }
        let Some(at) = lead.find("try_from(").or_else(|| lead.find("try_into(")) else {
            return false;
        };
        let rest = &lead[at..];
        rest.contains(".unwrap()") || rest.contains(".expect(")
    }

    /// The live text of one source file: everything ahead of its
    /// inline test module, when it has one.
    fn live(text: &str) -> &str {
        text.split("#[cfg(test)]\nmod tests").next().expect("split always yields a head")
    }

    // Negative control (holed-copy form): the matcher trips on
    // planted violations and stays quiet on the named-fallback and
    // comment spellings.
    assert!(trips("let n = u32::try_from(len).unwrap();"), "the matcher misses a planted unwrap");
    assert!(trips("let n: u32 = len.try_into().expect(\"fits\");"), "misses a planted expect");
    assert!(!trips("let n = u32::try_from(len).unwrap_or(0);"), "unwrap_or names its fallback");
    assert!(!trips("// let n = u32::try_from(len).unwrap();"), "comments are not live code");

    let mut conversions = 0_usize;
    let mut hits = Vec::new();
    for (rel, text) in src_files() {
        // The stream-ingest test corpus is cfg(test) whole-file:
        // test code asserts however is convenient.
        if rel.ends_with("/tests.rs") || rel == "stream_corpus.rs" {
            continue;
        }
        for (index, line) in live(&text).lines().enumerate() {
            conversions += line.matches("try_from(").count() + line.matches("try_into(").count();
            if trips(line) {
                hits.push(format!("{rel}:{}: {}", index + 1, line.trim()));
            }
        }
    }
    assert!(conversions > 0, "no fallible conversion seen: the scan is blind");
    assert!(
        hits.is_empty(),
        "fallible conversions punched through with unwrap/expect in live code:\n{}",
        hits.join("\n")
    );
}

/// (h) Every integration target is wired into CI, and every CI
/// `--test` list is sorted. The top-level `tests/*.rs` files are
/// cargo targets (the `support/` subdir holds `#[path]` modules,
/// not targets); each must appear in some `ci.yml` `--test` list,
/// so a target added without wiring it into CI goes red here
/// instead of silently never running.
#[test]
fn ci_runs_every_integration_target() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let ci = fs::read_to_string(root.join(".github/workflows/ci.yml")).expect("ci.yml is readable");
    let mut targets: Vec<String> = fs::read_dir(root.join("tests"))
        .expect("tests directory is readable")
        .filter_map(|entry| {
            let path = entry.expect("directory entry is readable").path();
            (path.extension().is_some_and(|ext| ext == "rs"))
                .then(|| path.file_stem().expect("has a stem").to_str().unwrap().to_owned())
        })
        .collect();
    targets.sort();
    // The walk must have found the real targets, not an empty dir.
    assert!(targets.len() >= 12, "the tests walk found only {} targets", targets.len());
    let missing: Vec<&String> =
        targets.iter().filter(|t| !ci.contains(&format!("--test {t}"))).collect();
    assert!(
        missing.is_empty(),
        "integration targets absent from every CI --test list: {missing:?}"
    );
    // Each list is lexicographically sorted, so enumeration order
    // is a judged fact rather than a hand duty; a target spliced in
    // out of place reddens here instead of waiting for a reader.
    for (idx, line) in ci.lines().enumerate() {
        if !line.contains("--test ") {
            continue;
        }
        let names: Vec<&str> = line
            .split("--test ")
            .skip(1)
            .map(|rest| rest.split_whitespace().next().expect("a target name follows --test"))
            .collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(names, sorted, "ci.yml line {} lists --test targets out of order", idx + 1);
    }
}

/// (k) Every feature the manifest declares is enrolled in both CI
/// cell arrays — the virgin-check loop and the doc + doctest loop —
/// in the manifest's own declaration order, with the no-feature
/// cell leading each array. A capability cell added to `Cargo.toml`
/// without CI enrollment goes red here instead of silently skipping
/// its per-cell check, rustdoc, and doctest runs; a stray or
/// misspelled array entry reddens the same equality.
#[test]
fn ci_enrolls_every_declared_feature_in_both_cell_arrays() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let manifest = fs::read_to_string(root.join("Cargo.toml")).expect("Cargo.toml is readable");
    let mut declared: Vec<String> = Vec::new();
    let mut in_features = false;
    for line in manifest.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_features = trimmed == "[features]";
            continue;
        }
        if !in_features || trimmed.starts_with('#') {
            continue;
        }
        // Feature declarations open as `name = …` at line start;
        // continuation lines of a multi-line value never do.
        if let Some((name, _)) = line.split_once(" = ")
            && !name.starts_with(char::is_whitespace)
        {
            let name = name.trim();
            if name != "default" {
                declared.push(name.to_owned());
            }
        }
    }
    // The parse must have found the real roster, not a moved header.
    assert!(declared.len() >= 50, "the feature parse found only {} entries", declared.len());

    let ci = fs::read_to_string(root.join(".github/workflows/ci.yml")).expect("ci.yml is readable");
    let arrays: Vec<Vec<String>> = ci
        .lines()
        .filter_map(|line| line.trim().strip_prefix("cells=("))
        .map(|rest| {
            let inner = rest.strip_suffix(')').expect("a cells array closes on its own line");
            assert!(inner.starts_with("\"\" "), "a cells array must lead with the no-feature cell");
            inner.split_whitespace().filter(|w| *w != "\"\"").map(str::to_owned).collect()
        })
        .collect();
    assert_eq!(arrays.len(), 2, "ci.yml carries exactly two cells arrays (check, doc + doctest)");
    for (index, array) in arrays.iter().enumerate() {
        assert_eq!(
            *array, declared,
            "CI cells array {index} must equal the manifest's feature declarations in order"
        );
    }
}

/// (i) The auto-trait matrix is complete over the census's key
/// source: every public type declared in `src/` as a spelled
/// `pub struct`/`pub enum`, minted by a `fixed_family!` row,
/// emitted by a `machine`/`frames for`/`backing: copied` line or
/// a local `<family>_frames!` invocation, minted by a store
/// invocation's strata (the plain layer's `Handle` and command
/// vocabulary, the transfer form's stratum vocabulary), or named
/// on a `vocabulary` roster faces `tests/auto_traits.rs` under
/// its declaring path — or under an enumerated alias path where
/// the declaration is private and re-exported. Auto traits attach
/// to the type, not the path, so the remaining public re-export
/// paths carry no demand of their own; public traits are outside
/// the census by nature — a trait declares no instance an
/// auto-trait pin could instantiate. The pinned set is parsed
/// from real `send_and_sync::<…>()` calls (a commented-out call
/// or a prose mention cannot impersonate a pin), except the
/// enumerated negative roster, which is honoured by doc naming
/// because its pins are `compile_fail` doctests on the types
/// themselves. The census self-checks its discrimination by
/// commenting out one call in a copy of the matrix and demanding
/// the copy go incomplete — against a spelled declaration's pin,
/// a vocabulary-roster pin, a store-`Handle` pin, a store
/// command-vocabulary pin, and a frame-macro pin, so holing any
/// key class is provably seen.
#[test]
fn every_public_type_faces_the_auto_trait_matrix() {
    // When `COORDINATES_DUMP` names a path, the census's minted key
    // set, the alias pairs, and the trait roster are written there
    // before any verdict below runs, so the roster comparator
    // (`probes/roster_reconcile`) always reads the battery's own
    // mint — even at a tip where the census itself is red. Unset,
    // nothing is written and nothing changes.
    if let Some(path) = std::env::var_os("COORDINATES_DUMP") {
        let keys: BTreeSet<String> =
            declared().into_iter().map(|(rel, ident)| qualified(&rel, &ident)).collect();
        let mut dump = String::from("[declared]\n");
        for key in &keys {
            dump.push_str(key);
            dump.push('\n');
        }
        dump.push_str("[aliases]\n");
        for (declaration, pins) in ALIASES {
            for pin in *pins {
                dump.push_str(&format!("{declaration} => {pin}\n"));
            }
        }
        dump.push_str("[traits]\n");
        for name in TRAITS {
            dump.push_str(name);
            dump.push('\n');
        }
        fs::write(&path, dump).expect("the COORDINATES_DUMP path is writable");
    }

    let matrix =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/auto_traits.rs"))
            .expect("auto_traits.rs is readable");

    // Every fully qualified type path actually instantiated through
    // the pin. Comment lines are dropped first (they cannot
    // impersonate a pin), then the live lines join and shed
    // whitespace, so a pin rustfmt wrapped across lines still
    // parses whole.
    fn pinned(matrix: &str) -> Vec<String> {
        let live: String = matrix
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .flat_map(|line| line.chars())
            .filter(|c| !c.is_whitespace())
            .collect();
        let mut out = Vec::new();
        for (at, _) in live.match_indices("send_and_sync::<") {
            let rest = &live[at + "send_and_sync::<".len()..];
            let cut = rest.find(['<', '>']).expect("a pin closes its type argument");
            out.push(rest[..cut].to_owned());
        }
        out
    }

    // Public faces of privately-declared types: each entry maps a
    // census key (the declaring file's vocabulary) to the public
    // re-export paths facing consumers. Auto traits attach to the
    // type, not the path, so a pin at the key or at any listed
    // face discharges the demand; the roster comparator
    // (`probes/roster_reconcile`) holds every public path over a
    // private declaration to this table or the census keys, and
    // every entry's key side to a minted census key. The cursor
    // engines declare in the private stratum and face consumers as
    // the traverse paths, pinned there. The editor facades declare
    // their command vocabulary in the facade file's private strata
    // (`mod command`, the transfer stratum) and face it per
    // dialect — and, where the transfer capability is bought, per
    // dialect transfer face; the revising transfer stratum's own
    // `EditStatus` folds onto the command one under the file's
    // key, so one entry carries both types' faces.
    const ALIASES: &[(&str, &[&str])] = &[
        ("protobuf_edit::cursor::Oversize", &["protobuf_edit::traverse::Oversize"]),
        ("protobuf_edit::cursor::GroupDepth", &["protobuf_edit::traverse::GroupDepth"]),
        ("protobuf_edit::cursor::grouped::Cursor", &["protobuf_edit::traverse::grouped::Cursor"]),
        (
            "protobuf_edit::cursor::grouped::CanonicalCursor",
            &["protobuf_edit::traverse::grouped::CanonicalCursor"],
        ),
        ("protobuf_edit::cursor::grouped::Entry", &["protobuf_edit::traverse::grouped::Entry"]),
        (
            "protobuf_edit::cursor::grouped::EntryKind",
            &["protobuf_edit::traverse::grouped::EntryKind"],
        ),
        ("protobuf_edit::cursor::grouped::Fault", &["protobuf_edit::traverse::grouped::Fault"]),
        (
            "protobuf_edit::cursor::grouped::FaultKind",
            &["protobuf_edit::traverse::grouped::FaultKind"],
        ),
        (
            "protobuf_edit::cursor::groupless::Cursor",
            &["protobuf_edit::traverse::groupless::Cursor"],
        ),
        (
            "protobuf_edit::cursor::groupless::CanonicalCursor",
            &["protobuf_edit::traverse::groupless::CanonicalCursor"],
        ),
        ("protobuf_edit::cursor::groupless::Entry", &["protobuf_edit::traverse::groupless::Entry"]),
        (
            "protobuf_edit::cursor::groupless::EntryKind",
            &["protobuf_edit::traverse::groupless::EntryKind"],
        ),
        ("protobuf_edit::cursor::groupless::Fault", &["protobuf_edit::traverse::groupless::Fault"]),
        (
            "protobuf_edit::cursor::groupless::FaultKind",
            &["protobuf_edit::traverse::groupless::FaultKind"],
        ),
        (
            "protobuf_edit::adopt::EditStatus",
            &[
                "protobuf_edit::adopt::grouped::EditStatus",
                "protobuf_edit::adopt::groupless::EditStatus",
                "protobuf_edit::adopt::grouped::transfer::EditStatus",
                "protobuf_edit::adopt::groupless::transfer::EditStatus",
            ],
        ),
        (
            "protobuf_edit::adopt::InsertAt",
            &[
                "protobuf_edit::adopt::grouped::InsertAt",
                "protobuf_edit::adopt::groupless::InsertAt",
                "protobuf_edit::adopt::grouped::transfer::InsertAt",
                "protobuf_edit::adopt::groupless::transfer::InsertAt",
            ],
        ),
        (
            "protobuf_edit::adopt::PayloadTarget",
            &[
                "protobuf_edit::adopt::grouped::transfer::PayloadTarget",
                "protobuf_edit::adopt::groupless::transfer::PayloadTarget",
            ],
        ),
        (
            "protobuf_edit::amend::EditStatus",
            &[
                "protobuf_edit::amend::grouped::EditStatus",
                "protobuf_edit::amend::groupless::EditStatus",
                "protobuf_edit::amend::grouped::transfer::EditStatus",
                "protobuf_edit::amend::groupless::transfer::EditStatus",
            ],
        ),
        (
            "protobuf_edit::amend::InsertAt",
            &[
                "protobuf_edit::amend::grouped::InsertAt",
                "protobuf_edit::amend::groupless::InsertAt",
                "protobuf_edit::amend::grouped::transfer::InsertAt",
                "protobuf_edit::amend::groupless::transfer::InsertAt",
            ],
        ),
        (
            "protobuf_edit::amend::PayloadTarget",
            &[
                "protobuf_edit::amend::grouped::transfer::PayloadTarget",
                "protobuf_edit::amend::groupless::transfer::PayloadTarget",
            ],
        ),
        (
            "protobuf_edit::draft::EditStatus",
            &[
                "protobuf_edit::draft::grouped::EditStatus",
                "protobuf_edit::draft::groupless::EditStatus",
                "protobuf_edit::draft::grouped::transfer::EditStatus",
                "protobuf_edit::draft::groupless::transfer::EditStatus",
            ],
        ),
        (
            "protobuf_edit::draft::InsertAt",
            &[
                "protobuf_edit::draft::grouped::InsertAt",
                "protobuf_edit::draft::groupless::InsertAt",
                "protobuf_edit::draft::grouped::transfer::InsertAt",
                "protobuf_edit::draft::groupless::transfer::InsertAt",
            ],
        ),
        (
            "protobuf_edit::draft::PayloadTarget",
            &[
                "protobuf_edit::draft::grouped::transfer::PayloadTarget",
                "protobuf_edit::draft::groupless::transfer::PayloadTarget",
            ],
        ),
        (
            "protobuf_edit::fixed_patch::EditStatus",
            &[
                "protobuf_edit::fixed_patch::grouped::EditStatus",
                "protobuf_edit::fixed_patch::groupless::EditStatus",
            ],
        ),
        (
            "protobuf_edit::fixed_patch::InsertAt",
            &[
                "protobuf_edit::fixed_patch::grouped::InsertAt",
                "protobuf_edit::fixed_patch::groupless::InsertAt",
            ],
        ),
        (
            "protobuf_edit::intake::EditStatus",
            &[
                "protobuf_edit::intake::grouped::EditStatus",
                "protobuf_edit::intake::groupless::EditStatus",
                "protobuf_edit::intake::grouped::transfer::EditStatus",
                "protobuf_edit::intake::groupless::transfer::EditStatus",
            ],
        ),
        (
            "protobuf_edit::intake::InsertAt",
            &[
                "protobuf_edit::intake::grouped::InsertAt",
                "protobuf_edit::intake::groupless::InsertAt",
                "protobuf_edit::intake::grouped::transfer::InsertAt",
                "protobuf_edit::intake::groupless::transfer::InsertAt",
            ],
        ),
        (
            "protobuf_edit::intake::PayloadTarget",
            &[
                "protobuf_edit::intake::grouped::transfer::PayloadTarget",
                "protobuf_edit::intake::groupless::transfer::PayloadTarget",
            ],
        ),
        (
            "protobuf_edit::markup::EditStatus",
            &[
                "protobuf_edit::markup::grouped::EditStatus",
                "protobuf_edit::markup::groupless::EditStatus",
                "protobuf_edit::markup::grouped::transfer::EditStatus",
                "protobuf_edit::markup::groupless::transfer::EditStatus",
            ],
        ),
        (
            "protobuf_edit::markup::InsertAt",
            &[
                "protobuf_edit::markup::grouped::InsertAt",
                "protobuf_edit::markup::groupless::InsertAt",
                "protobuf_edit::markup::grouped::transfer::InsertAt",
                "protobuf_edit::markup::groupless::transfer::InsertAt",
            ],
        ),
        (
            "protobuf_edit::markup::PayloadTarget",
            &[
                "protobuf_edit::markup::grouped::transfer::PayloadTarget",
                "protobuf_edit::markup::groupless::transfer::PayloadTarget",
            ],
        ),
        (
            "protobuf_edit::patch::EditStatus",
            &[
                "protobuf_edit::patch::grouped::EditStatus",
                "protobuf_edit::patch::groupless::EditStatus",
                "protobuf_edit::patch::grouped::transfer::EditStatus",
                "protobuf_edit::patch::groupless::transfer::EditStatus",
            ],
        ),
        (
            "protobuf_edit::patch::InsertAt",
            &[
                "protobuf_edit::patch::grouped::InsertAt",
                "protobuf_edit::patch::groupless::InsertAt",
                "protobuf_edit::patch::grouped::transfer::InsertAt",
                "protobuf_edit::patch::groupless::transfer::InsertAt",
            ],
        ),
        (
            "protobuf_edit::patch::PayloadTarget",
            &[
                "protobuf_edit::patch::grouped::transfer::PayloadTarget",
                "protobuf_edit::patch::groupless::transfer::PayloadTarget",
            ],
        ),
        (
            "protobuf_edit::review::EditStatus",
            &[
                "protobuf_edit::review::grouped::EditStatus",
                "protobuf_edit::review::groupless::EditStatus",
                "protobuf_edit::review::grouped::transfer::EditStatus",
                "protobuf_edit::review::groupless::transfer::EditStatus",
            ],
        ),
        (
            "protobuf_edit::review::InsertAt",
            &[
                "protobuf_edit::review::grouped::InsertAt",
                "protobuf_edit::review::groupless::InsertAt",
                "protobuf_edit::review::grouped::transfer::InsertAt",
                "protobuf_edit::review::groupless::transfer::InsertAt",
            ],
        ),
        (
            "protobuf_edit::review::PayloadTarget",
            &[
                "protobuf_edit::review::grouped::transfer::PayloadTarget",
                "protobuf_edit::review::groupless::transfer::PayloadTarget",
            ],
        ),
        (
            "protobuf_edit::session::EditStatus",
            &[
                "protobuf_edit::session::grouped::EditStatus",
                "protobuf_edit::session::groupless::EditStatus",
                "protobuf_edit::session::grouped::transfer::EditStatus",
                "protobuf_edit::session::groupless::transfer::EditStatus",
            ],
        ),
        (
            "protobuf_edit::session::InsertAt",
            &[
                "protobuf_edit::session::grouped::InsertAt",
                "protobuf_edit::session::groupless::InsertAt",
                "protobuf_edit::session::grouped::transfer::InsertAt",
                "protobuf_edit::session::groupless::transfer::InsertAt",
            ],
        ),
        (
            "protobuf_edit::session::PayloadTarget",
            &[
                "protobuf_edit::session::grouped::transfer::PayloadTarget",
                "protobuf_edit::session::groupless::transfer::PayloadTarget",
            ],
        ),
        (
            "protobuf_edit::stream_adopt::EditStatus",
            &[
                "protobuf_edit::stream_adopt::grouped::EditStatus",
                "protobuf_edit::stream_adopt::groupless::EditStatus",
                "protobuf_edit::stream_adopt::grouped::transfer::EditStatus",
                "protobuf_edit::stream_adopt::groupless::transfer::EditStatus",
            ],
        ),
        (
            "protobuf_edit::stream_adopt::InsertAt",
            &[
                "protobuf_edit::stream_adopt::grouped::InsertAt",
                "protobuf_edit::stream_adopt::groupless::InsertAt",
                "protobuf_edit::stream_adopt::grouped::transfer::InsertAt",
                "protobuf_edit::stream_adopt::groupless::transfer::InsertAt",
            ],
        ),
        (
            "protobuf_edit::stream_adopt::PayloadTarget",
            &[
                "protobuf_edit::stream_adopt::grouped::transfer::PayloadTarget",
                "protobuf_edit::stream_adopt::groupless::transfer::PayloadTarget",
            ],
        ),
        (
            "protobuf_edit::stream_draft::EditStatus",
            &[
                "protobuf_edit::stream_draft::grouped::EditStatus",
                "protobuf_edit::stream_draft::groupless::EditStatus",
                "protobuf_edit::stream_draft::grouped::transfer::EditStatus",
                "protobuf_edit::stream_draft::groupless::transfer::EditStatus",
            ],
        ),
        (
            "protobuf_edit::stream_draft::InsertAt",
            &[
                "protobuf_edit::stream_draft::grouped::InsertAt",
                "protobuf_edit::stream_draft::groupless::InsertAt",
                "protobuf_edit::stream_draft::grouped::transfer::InsertAt",
                "protobuf_edit::stream_draft::groupless::transfer::InsertAt",
            ],
        ),
        (
            "protobuf_edit::stream_draft::PayloadTarget",
            &[
                "protobuf_edit::stream_draft::grouped::transfer::PayloadTarget",
                "protobuf_edit::stream_draft::groupless::transfer::PayloadTarget",
            ],
        ),
        (
            "protobuf_edit::stream_intake::EditStatus",
            &[
                "protobuf_edit::stream_intake::grouped::EditStatus",
                "protobuf_edit::stream_intake::groupless::EditStatus",
                "protobuf_edit::stream_intake::grouped::transfer::EditStatus",
                "protobuf_edit::stream_intake::groupless::transfer::EditStatus",
            ],
        ),
        (
            "protobuf_edit::stream_intake::InsertAt",
            &[
                "protobuf_edit::stream_intake::grouped::InsertAt",
                "protobuf_edit::stream_intake::groupless::InsertAt",
                "protobuf_edit::stream_intake::grouped::transfer::InsertAt",
                "protobuf_edit::stream_intake::groupless::transfer::InsertAt",
            ],
        ),
        (
            "protobuf_edit::stream_intake::PayloadTarget",
            &[
                "protobuf_edit::stream_intake::grouped::transfer::PayloadTarget",
                "protobuf_edit::stream_intake::groupless::transfer::PayloadTarget",
            ],
        ),
    ];

    // The reachable public trait roster: every trait a consumer can
    // name, under its declaring path. A trait declares no instance
    // an auto-trait pin could instantiate, so the census cannot
    // demand traits; this roster bounds the class by name instead,
    // and the roster comparator (`probes/roster_reconcile`) holds
    // it equal to the compiled crate's reachable public trait set
    // in both directions. `rewrite`'s sealing trait sits in a
    // private module with no re-export — not consumer-nameable, so
    // not a row here.
    const TRAITS: &[&str] = &[
        "protobuf_edit::collect::Advisor",
        "protobuf_edit::inspect::Advisor",
        "protobuf_edit::replay_source::ReplayWalk",
        "protobuf_edit::replay_source::StableReplaySource",
        "protobuf_edit::replay_splice::grouped::Rule",
        "protobuf_edit::replay_splice::groupless::Rule",
        "protobuf_edit::retain::Advisor",
        "protobuf_edit::rewrite::Sets",
        "protobuf_edit::route::grouped::Sink",
        "protobuf_edit::route::groupless::Sink",
        "protobuf_edit::scan::grouped::Sink",
        "protobuf_edit::scan::groupless::Sink",
        "protobuf_edit::splice::grouped::Rule",
        "protobuf_edit::splice::grouped::transfer::SourceRule",
        "protobuf_edit::splice::groupless::Rule",
        "protobuf_edit::splice::groupless::transfer::SourceRule",
        "protobuf_edit::survey::Advisor",
        "protobuf_edit::transcode::grouped::Rule",
        "protobuf_edit::transcode::groupless::Rule",
    ];

    // The adjudicated negative side: pinned by compile_fail
    // doctests on the types themselves, named here by backticked
    // doc mention against the roster (and only the roster).
    const NEGATIVE: &[&str] = &[
        "protobuf_edit::session::DocBytes",
        "protobuf_edit::session::grouped::Session",
        "protobuf_edit::session::grouped::PricedSession",
        "protobuf_edit::session::grouped::BorrowSession",
        "protobuf_edit::session::grouped::MixSession",
        "protobuf_edit::session::grouped::PayloadFrame",
        "protobuf_edit::session::grouped::SizedPayloadFrame",
        "protobuf_edit::session::grouped::MixPayloadFrame",
        "protobuf_edit::session::grouped::MixSizedPayloadFrame",
        "protobuf_edit::session::grouped::PricedPayloadFrame",
        "protobuf_edit::session::grouped::PricedSizedPayloadFrame",
        "protobuf_edit::session::groupless::Session",
        "protobuf_edit::session::groupless::PricedSession",
        "protobuf_edit::session::groupless::BorrowSession",
        "protobuf_edit::session::groupless::MixSession",
        "protobuf_edit::session::groupless::PayloadFrame",
        "protobuf_edit::session::groupless::SizedPayloadFrame",
        "protobuf_edit::session::groupless::MixPayloadFrame",
        "protobuf_edit::session::groupless::MixSizedPayloadFrame",
        "protobuf_edit::session::groupless::PricedPayloadFrame",
        "protobuf_edit::session::groupless::PricedSizedPayloadFrame",
        "protobuf_edit::session::grouped::transfer::TransferSession",
        "protobuf_edit::session::grouped::transfer::TransferBorrowSession",
        "protobuf_edit::session::grouped::transfer::PayloadFrame",
        "protobuf_edit::session::grouped::transfer::SizedPayloadFrame",
        "protobuf_edit::session::grouped::transfer::PricedTransferSession",
        "protobuf_edit::session::grouped::transfer::PricedPayloadFrame",
        "protobuf_edit::session::grouped::transfer::PricedSizedPayloadFrame",
        "protobuf_edit::session::groupless::transfer::TransferSession",
        "protobuf_edit::session::groupless::transfer::TransferBorrowSession",
        "protobuf_edit::session::groupless::transfer::PayloadFrame",
        "protobuf_edit::session::groupless::transfer::SizedPayloadFrame",
        "protobuf_edit::session::groupless::transfer::PricedTransferSession",
        "protobuf_edit::session::groupless::transfer::PricedPayloadFrame",
        "protobuf_edit::session::groupless::transfer::PricedSizedPayloadFrame",
    ];

    fn qualified(rel: &str, ident: &str) -> String {
        if rel == "lib.rs" {
            format!("protobuf_edit::{ident}")
        } else {
            format!("protobuf_edit::{}::{ident}", rel.trim_end_matches(".rs").replace('/', "::"))
        }
    }

    fn faces(matrix: &str, pins: &[String], key: &str) -> bool {
        if NEGATIVE.contains(&key) {
            let short = key.strip_prefix("protobuf_edit::").expect("negative keys are qualified");
            return matrix.contains(&format!("{short}`"));
        }
        let hit = |k: &str| pins.iter().any(|p| p == k);
        if hit(key) {
            return true;
        }
        ALIASES
            .iter()
            .find_map(|(from, to)| (*from == key).then_some(*to))
            .is_some_and(|paths| paths.iter().any(|p| hit(p)))
    }

    // Public type declarations: spelled ones, the ones the
    // fixed_family! invocations mint (`Name, width, type` rows),
    // the ones the one_shot_machine! invocations emit (the
    // `machine Name<…>` line plus the frame types its copied
    // backing names), the staged-frame pairs the dialect files'
    // local `<family>_frames!` invocations emit, the module-wide
    // types each `vocabulary` roster declares (the roster is
    // mandatory grammar, so no invocation can omit it; a roster
    // name that overclaims — a type the module never emits — is a
    // demand no pin can discharge, since the pin would not
    // compile), and each family store invocation's stratum: the
    // plain layer mints `Handle` and the command vocabulary
    // (`EditStatus`, `InsertAt`), the transfer form mints its
    // stratum's vocabulary (`PayloadTarget`, plus the revising
    // stratum's own `EditStatus`, which folds onto the command
    // one under the declaring file's key), and the borrow,
    // priced, and mixed store forms add none. The editor
    // family-core files are templates: their `pub` declarations
    // are macro bodies, emitted into the machines' own modules —
    // the census sees those under the machines' paths (patch::*,
    // adopt::*), where the pins already face them.
    fn declared() -> Vec<(String, String)> {
        const TEMPLATES: &[&str] = &[
            "editor.rs",
            "editor/grouped.rs",
            "editor/groupless.rs",
            "revise.rs",
            "revise/grouped.rs",
            "revise/groupless.rs",
            // Not a template but equally faceless: the stream-ingest
            // test corpus is a cfg(test) private module, so its item
            // visibility never reaches the public surface.
            "stream_corpus.rs",
        ];
        let mut out = Vec::new();
        for (rel, text) in src_files() {
            if TEMPLATES.contains(&rel.as_str()) {
                continue;
            }
            let mut in_family = false;
            let mut in_vocabulary = false;
            let mut in_store = false;
            for line in text.lines() {
                let lead = line.trim_start();
                if in_vocabulary {
                    if lead.starts_with(')') {
                        in_vocabulary = false;
                    } else {
                        for ident in lead.split(", ") {
                            let ident = ident.trim_end_matches(',');
                            if !ident.is_empty() {
                                out.push((rel.clone(), ident.to_owned()));
                            }
                        }
                    }
                    continue;
                }
                if lead == "vocabulary(" || lead == "vocabulary stream(" {
                    in_vocabulary = true;
                    continue;
                }
                if lead == "crate::editor::one_shot_store! {"
                    || lead == "crate::revise::revising_store! {"
                {
                    in_store = true;
                    continue;
                }
                if in_store {
                    if lead == "capability: plain," || lead == "layer plain," {
                        for ident in ["Handle", "EditStatus", "InsertAt"] {
                            out.push((rel.clone(), ident.to_owned()));
                        }
                        in_store = false;
                    } else if lead == "capability: transfer," {
                        out.push((rel.clone(), "PayloadTarget".to_owned()));
                        in_store = false;
                    } else if lead == "layer transfer," {
                        for ident in ["EditStatus", "PayloadTarget"] {
                            out.push((rel.clone(), ident.to_owned()));
                        }
                        in_store = false;
                    } else if lead.starts_with('}') {
                        in_store = false;
                    }
                    continue;
                }
                if let Some(rest) =
                    lead.strip_prefix("pub struct ").or_else(|| lead.strip_prefix("pub enum "))
                {
                    let ident: String =
                        rest.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
                    if !ident.is_empty() && !ident.starts_with('$') {
                        out.push((rel.clone(), ident));
                    }
                }
                if let Some(rest) = lead.strip_prefix("machine ") {
                    let ident: String =
                        rest.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
                    if !ident.is_empty() {
                        out.push((rel.clone(), ident));
                    }
                }
                if let Some(rest) = lead.strip_prefix("backing: copied(") {
                    for ident in rest.trim_end_matches("),").split(", ").skip(1) {
                        out.push((rel.clone(), ident.to_owned()));
                    }
                }
                if let Some(rest) = lead.strip_prefix("frames for ") {
                    let Some((_, frames)) = rest.split_once('(') else {
                        continue;
                    };
                    for ident in frames.trim_end_matches("),").split(", ") {
                        out.push((rel.clone(), ident.to_owned()));
                    }
                }
                // A dialect file's local frame-minting macro: each
                // `<family>_frames!(Machine, Frame, SizedFrame);`
                // invocation emits the named staged-frame pair as
                // public types of the invoking file (the machine
                // argument is a type the walk already saw declared).
                if let Some((name, args)) = lead.split_once("_frames!(")
                    && !name.is_empty()
                    && name.chars().all(|c| c.is_ascii_lowercase() || c == '_')
                {
                    for ident in args.trim_end_matches(");").split(", ").skip(1) {
                        out.push((rel.clone(), ident.to_owned()));
                    }
                }
                if lead.starts_with("fixed_family! {") {
                    in_family = true;
                    continue;
                }
                if in_family {
                    if lead.starts_with('}') {
                        in_family = false;
                    } else if lead.chars().next().is_some_and(|c| c.is_ascii_uppercase())
                        && lead.contains(", ")
                    {
                        let ident: String =
                            lead.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
                        out.push((rel.clone(), ident));
                    }
                }
            }
        }
        out
    }

    fn audit(matrix: &str) -> (usize, Vec<String>) {
        let pins = pinned(matrix);
        let mut missing = Vec::new();
        let declared = declared();
        let seen = declared.len();
        for (rel, ident) in declared {
            let key = qualified(&rel, &ident);
            if !faces(matrix, &pins, &key) {
                missing.push(key);
            }
        }
        (seen, missing)
    }

    // Self-check: commenting out one real call must be seen — a
    // deleted key would be too easy, since the mutated text no
    // longer contains it anywhere; a commented call still spells
    // the full path, and only call-form parsing refuses it.
    let target = "send_and_sync::<protobuf_edit::scan::groupless::Fault>();";
    let holed =
        matrix.replacen(target, "// send_and_sync::<protobuf_edit::scan::groupless::Fault>();", 1);
    assert_ne!(holed, matrix, "the self-check mutation found nothing to comment out");
    let (_, holed_missing) = audit(&holed);
    assert!(
        holed_missing.iter().any(|k| k == "protobuf_edit::scan::groupless::Fault"),
        "the census did not notice a commented-out pin — prose can impersonate the matrix"
    );
    // The same discrimination for a vocabulary-roster key: the
    // roster mints the demand, so holing a vocabulary type's pin
    // must go red exactly like a spelled declaration's.
    let target = "send_and_sync::<protobuf_edit::session::groupless::transfer::EditFault>();";
    let holed = matrix.replacen(
        target,
        "// send_and_sync::<protobuf_edit::session::groupless::transfer::EditFault>();",
        1,
    );
    assert_ne!(holed, matrix, "the vocabulary self-check found nothing to comment out");
    let (_, holed_missing) = audit(&holed);
    assert!(
        holed_missing.iter().any(|k| k == "protobuf_edit::session::groupless::transfer::EditFault"),
        "the census did not notice a holed vocabulary pin — the roster mints no demand"
    );
    // The same discrimination for a store-Handle key: the store
    // invocation's plain layer mints the demand, so holing a
    // Handle pin must go red exactly like the other key classes.
    let target = "send_and_sync::<protobuf_edit::session::Handle>();";
    let holed = matrix.replacen(target, "// send_and_sync::<protobuf_edit::session::Handle>();", 1);
    assert_ne!(holed, matrix, "the store self-check found nothing to comment out");
    let (_, holed_missing) = audit(&holed);
    assert!(
        holed_missing.iter().any(|k| k == "protobuf_edit::session::Handle"),
        "the census did not notice a holed Handle pin — the store invocation mints no demand"
    );
    // The same discrimination for a store command-vocabulary key:
    // the plain layer mints the demand beside Handle's, so holing
    // a command pin must go red exactly like the other key classes.
    let target = "send_and_sync::<protobuf_edit::adopt::EditStatus>();";
    let holed =
        matrix.replacen(target, "// send_and_sync::<protobuf_edit::adopt::EditStatus>();", 1);
    assert_ne!(holed, matrix, "the command self-check found nothing to comment out");
    let (_, holed_missing) = audit(&holed);
    assert!(
        holed_missing.iter().any(|k| k == "protobuf_edit::adopt::EditStatus"),
        "the census did not notice a holed command pin — the store invocation mints no \
         command-vocabulary demand"
    );
    // The same discrimination for a frame-macro key: the
    // `<family>_frames!` invocation mints the demand, so holing a
    // staged-frame pin must go red exactly like the other key
    // classes.
    let target =
        "send_and_sync::<protobuf_edit::maintain::grouped::PayloadFrame<'static, Slice>>();";
    let holed = matrix.replacen(
        target,
        "// send_and_sync::<protobuf_edit::maintain::grouped::PayloadFrame<'static, Slice>>();",
        1,
    );
    assert_ne!(holed, matrix, "the frame self-check found nothing to comment out");
    let (_, holed_missing) = audit(&holed);
    assert!(
        holed_missing.iter().any(|k| k == "protobuf_edit::maintain::grouped::PayloadFrame"),
        "the census did not notice a holed frame pin — the frame invocation mints no demand"
    );

    let (seen, missing) = audit(&matrix);
    // The walk currently sees ~980 declarations, ~490 of them
    // vocabulary-roster keys; a floor of 900 catches the walk (or
    // the roster parse) going blind without pinning the exact count.
    assert!(seen >= 900, "the public-type walk saw only {seen} declarations");
    assert!(
        missing.is_empty(),
        "public types never facing the auto-trait matrix under their qualified names:\n{}",
        missing.join("\n")
    );
}

/// The crate root and the README declare one fallible family: the
/// allocation-partition paragraphs enumerate the same machines —
/// the eighteen base revising forms, their eight transfer
/// siblings, and the two priced wrappers — so the two
/// constitutions cannot drift apart (the crate root once named
/// the session alone while the README already carried the
/// family).
#[test]
fn the_fallible_partition_names_one_enumerated_family() {
    const FAMILY: [&str; 28] = [
        "BorrowCommission",
        "BorrowDraft",
        "BorrowMaintain",
        "BorrowMarkup",
        "BorrowReview",
        "BorrowSession",
        "Commission",
        "Draft",
        "Maintain",
        "Markup",
        "MixCommission",
        "MixDraft",
        "MixMaintain",
        "MixMarkup",
        "MixReview",
        "MixSession",
        "PricedSession",
        "PricedTransferSession",
        "Review",
        "Session",
        "TransferBorrowDraft",
        "TransferBorrowMarkup",
        "TransferBorrowReview",
        "TransferBorrowSession",
        "TransferDraft",
        "TransferMarkup",
        "TransferReview",
        "TransferSession",
    ];

    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let read = |rel: &str| {
        fs::read_to_string(root.join(rel))
            .unwrap_or_else(|error| panic!("{rel} is readable: {error}"))
    };

    // The enumerated set: backticked capitalized names inside the
    // paragraph running from the anchor line to the first line the
    // terminator admits.
    fn enumerated(text: &str, anchor: &str, done: impl Fn(&str) -> bool) -> Vec<String> {
        let lines: Vec<&str> = text.lines().collect();
        let start = lines
            .iter()
            .position(|line| line.contains(anchor))
            .unwrap_or_else(|| panic!("partition anchor {anchor:?} exists"));
        let mut names: Vec<String> = Vec::new();
        for line in &lines[start..] {
            if !line.contains(anchor) && done(line) {
                break;
            }
            for piece in line.split('`').skip(1).step_by(2) {
                if piece.chars().next().is_some_and(|c| c.is_ascii_uppercase())
                    && !names.iter().any(|have| have == piece)
                {
                    names.push(piece.to_owned());
                }
            }
        }
        names.sort_unstable();
        names
    }

    let lib = read("src/lib.rs");
    let readme = read("README.md");
    let lib_family =
        enumerated(&lib, "One rule partitions allocation behavior", |line| line.trim() == "//!");
    let readme_family = enumerated(&readme, "**Declared allocation policy.**", |line| {
        line.trim_start().starts_with("- **")
    });

    // Self-check: the judge must notice a name falling out of one
    // text — a decapitalized copy leaves the enumeration.
    let holed = lib.replacen("`BorrowMarkup`", "`borrowmarkup`", 1);
    assert_ne!(holed, lib, "the self-check mutation found nothing to hole");
    let holed_family =
        enumerated(&holed, "One rule partitions allocation behavior", |line| line.trim() == "//!");
    assert_ne!(holed_family, FAMILY, "the judge did not notice a holed name");

    assert_eq!(lib_family, FAMILY, "the crate root's partition names the adjudicated family");
    assert_eq!(readme_family, FAMILY, "the README's partition names the adjudicated family");
}

/// (e) No retired axis vocabulary survives in live text: `src/`
/// and the README speak only the adjudicated axis system.
#[test]
fn every_shared_layer_faces_the_role_census() {
    // The shared layers are the ADJUDICATED rows without a dialect
    // file component.
    let shared: Vec<&str> =
        ADJUDICATED.iter().map(|(file, _)| *file).filter(|f| !f.contains('/')).collect();
    let axes: Vec<&str> = AXES.iter().map(|(name, _)| *name).collect();

    let check = |census: &[(&str, &str, [&str; 4])]| -> Result<(), String> {
        for module in &shared {
            for axis in &axes {
                let rows: Vec<_> =
                    census.iter().filter(|(m, a, _)| m == module && a == axis).collect();
                if rows.len() != 1 {
                    return Err(format!("{module} × {axis}: {} rows", rows.len()));
                }
                for (role, cell) in ROLES.iter().zip(rows[0].2.iter()) {
                    if cell.is_empty() {
                        return Err(format!("{module} × {axis} × {role}: silent cell"));
                    }
                    if let Some(rest) = cell.strip_prefix("n/a")
                        && rest.strip_prefix(": ").is_none_or(str::is_empty)
                    {
                        return Err(format!("{module} × {axis} × {role}: n/a needs a reason"));
                    }
                }
            }
        }
        for (m, a, _) in census {
            if !shared.contains(m) {
                return Err(format!("{m}: not a shared layer"));
            }
            if !axes.contains(a) {
                return Err(format!("{a}: not an axis"));
            }
        }
        Ok(())
    };

    check(ROLE_CENSUS).unwrap_or_else(|hole| panic!("role census: {hole}"));

    // Mutation control: a missing row must redden the judge.
    let holed: Vec<_> = ROLE_CENSUS.iter().copied().skip(1).collect();
    assert!(check(&holed).is_err(), "the checker is blind to a missing row");
}

/// The revising rows' edit state has an enumerated writer set
/// outside construction: per capability arm, the ordinary
/// transition primitive's one assignment — the only site a backing
/// flip can pass through, the ground the derived-slot witness and
/// the orphan walk rest on — and, in the transfer-bearing arms
/// alone, the move faces' coupled primitive and unwind, whose two
/// source-side assignments only exchange `Intact` with `Moved`, a
/// pair sharing the scanned speaker, so no flip can pass there
/// (their destination sides route through the ordinary primitive).
/// The file text holds the plain arm's primitive beside the
/// transfer arms' three sites, so the source-level pin is four; a
/// fifth assignment would invalidate the unchecked arms without
/// changing their code. Emission-level enumeration is the
/// expansion judge's job: no single machine sees more than its
/// capability's set.
#[test]
fn the_row_edit_state_has_an_enumerated_writer_set() {
    let files = src_files();
    for rel in ["revise/grouped.rs", "revise/groupless.rs"] {
        let (_, text) = files.iter().find(|(r, _)| r == rel).expect("revise core files are walked");
        let writes = text.matches(".edit = ").count();
        assert_eq!(
            writes, 4,
            "{rel}: expected the enumerated Row::edit writer set (the plain arm's \
             transition primitive beside the transfer arms' primitive and coupled \
             move pair)"
        );
    }
}

#[test]
fn no_retired_axis_vocabulary_survives_in_live_text() {
    let readme = Path::new(env!("CARGO_MANIFEST_DIR")).join("README.md");
    let mut texts = src_files();
    texts
        .push(("README.md".to_owned(), fs::read_to_string(readme).expect("README.md is readable")));

    let mut hits = Vec::new();
    for (rel, text) in &texts {
        for (index, line) in text.lines().enumerate() {
            for retired in RETIRED_VOCABULARY {
                if line.contains(retired) {
                    hits.push(format!("{rel}:{}: {retired:?}", index + 1));
                }
            }
        }
    }
    assert!(hits.is_empty(), "retired axis vocabulary survives in live text:\n{}", hits.join("\n"));
}
