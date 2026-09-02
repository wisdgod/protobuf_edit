//! The substrate compile-presence judge: in any cell, an
//! unselected substrate leaf must be absent from the public
//! surface, and a selected one present. The scenario cells that
//! share private strata ride the same judge: each compiles alone
//! with its own public faces, and the cells it shares a stratum
//! with stay absent unless selected themselves.
//!
//! Mechanism: for each leaf, a probe crate that imports the leaf's
//! public vocabulary is `cargo check`ed against this crate (path
//! dependency, re-selecting exactly the ambient feature set, so
//! the probe judges the same cell this test runs under — without
//! `cfg(test)`, so the gates' test arms do not fire and the judged
//! surface is the production one). An expected-present leaf's
//! probe must compile; an expected-absent leaf's probe must fail
//! with an unresolved-path error naming the leaf (E0432 when the
//! path's last segment is the absentee, E0433 when an intermediate
//! module is) — any other failure is a harness fault and reds the
//! judge.
//!
//! Red capability: the root-vocabulary probe runs first and must
//! always compile — it proves the harness (path, features,
//! toolchain) can tell presence from absence before any absence
//! verdict is accepted, so a broken harness cannot green as
//! absence. Mis-gating either side flips a verdict: a leaf that
//! leaks into a foreign cell compiles where absence is expected
//! (red), and a leaf gated too narrowly fails where presence is
//! expected (red).
//!
//! The expectation lists below mirror the leaf gates in `src/`
//! (minus their `test` arms) on purpose: the gates and this judge
//! are independent spellings of the same closure, so a drift in
//! either goes red here instead of shipping.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::Command;
use std::{env, fs};

/// Every feature this crate declares, with its build-time state —
/// the probe manifest re-selects exactly the enabled set.
const FEATURES: &[(&str, bool)] = &[
    ("wire-grouped", cfg!(feature = "wire-grouped")),
    ("wire-groupless", cfg!(feature = "wire-groupless")),
    ("varint-slice", cfg!(feature = "varint-slice")),
    ("varint-carry", cfg!(feature = "varint-carry")),
    ("scalar", cfg!(feature = "scalar")),
    ("replay-source", cfg!(feature = "replay-source")),
    ("select-grouped", cfg!(feature = "select-grouped")),
    ("select-groupless", cfg!(feature = "select-groupless")),
    ("traverse-grouped", cfg!(feature = "traverse-grouped")),
    ("traverse-groupless", cfg!(feature = "traverse-groupless")),
    ("inspect-grouped", cfg!(feature = "inspect-grouped")),
    ("inspect-groupless", cfg!(feature = "inspect-groupless")),
    ("fixed-inspect-grouped", cfg!(feature = "fixed-inspect-grouped")),
    ("fixed-inspect-groupless", cfg!(feature = "fixed-inspect-groupless")),
    ("retain-grouped", cfg!(feature = "retain-grouped")),
    ("retain-groupless", cfg!(feature = "retain-groupless")),
    ("route-grouped", cfg!(feature = "route-grouped")),
    ("route-groupless", cfg!(feature = "route-groupless")),
    ("scan-grouped", cfg!(feature = "scan-grouped")),
    ("scan-groupless", cfg!(feature = "scan-groupless")),
    ("collect-grouped", cfg!(feature = "collect-grouped")),
    ("collect-groupless", cfg!(feature = "collect-groupless")),
    ("survey-grouped", cfg!(feature = "survey-grouped")),
    ("survey-groupless", cfg!(feature = "survey-groupless")),
    ("rewrite-grouped", cfg!(feature = "rewrite-grouped")),
    ("rewrite-groupless", cfg!(feature = "rewrite-groupless")),
    ("transfer-rewrite-grouped", cfg!(feature = "transfer-rewrite-grouped")),
    ("transfer-rewrite-groupless", cfg!(feature = "transfer-rewrite-groupless")),
    ("inplace-grouped", cfg!(feature = "inplace-grouped")),
    ("inplace-groupless", cfg!(feature = "inplace-groupless")),
    ("fixed-inplace-grouped", cfg!(feature = "fixed-inplace-grouped")),
    ("fixed-inplace-groupless", cfg!(feature = "fixed-inplace-groupless")),
    ("convert-grouped", cfg!(feature = "convert-grouped")),
    ("convert-groupless", cfg!(feature = "convert-groupless")),
    ("splice-grouped", cfg!(feature = "splice-grouped")),
    ("splice-groupless", cfg!(feature = "splice-groupless")),
    ("transfer-splice-grouped", cfg!(feature = "transfer-splice-grouped")),
    ("transfer-splice-groupless", cfg!(feature = "transfer-splice-groupless")),
    ("patch-grouped", cfg!(feature = "patch-grouped")),
    ("patch-groupless", cfg!(feature = "patch-groupless")),
    ("transfer-patch-grouped", cfg!(feature = "transfer-patch-grouped")),
    ("transfer-patch-groupless", cfg!(feature = "transfer-patch-groupless")),
    ("fixed-patch-grouped", cfg!(feature = "fixed-patch-grouped")),
    ("fixed-patch-groupless", cfg!(feature = "fixed-patch-groupless")),
    ("markup-grouped", cfg!(feature = "markup-grouped")),
    ("markup-groupless", cfg!(feature = "markup-groupless")),
    ("transfer-markup-grouped", cfg!(feature = "transfer-markup-grouped")),
    ("transfer-markup-groupless", cfg!(feature = "transfer-markup-groupless")),
    ("adopt-grouped", cfg!(feature = "adopt-grouped")),
    ("adopt-groupless", cfg!(feature = "adopt-groupless")),
    ("transfer-adopt-grouped", cfg!(feature = "transfer-adopt-grouped")),
    ("transfer-adopt-groupless", cfg!(feature = "transfer-adopt-groupless")),
    ("draft-grouped", cfg!(feature = "draft-grouped")),
    ("draft-groupless", cfg!(feature = "draft-groupless")),
    ("transfer-draft-grouped", cfg!(feature = "transfer-draft-grouped")),
    ("transfer-draft-groupless", cfg!(feature = "transfer-draft-groupless")),
    ("amend-grouped", cfg!(feature = "amend-grouped")),
    ("amend-groupless", cfg!(feature = "amend-groupless")),
    ("transfer-amend-grouped", cfg!(feature = "transfer-amend-grouped")),
    ("transfer-amend-groupless", cfg!(feature = "transfer-amend-groupless")),
    ("review-grouped", cfg!(feature = "review-grouped")),
    ("review-groupless", cfg!(feature = "review-groupless")),
    ("transfer-review-grouped", cfg!(feature = "transfer-review-grouped")),
    ("transfer-review-groupless", cfg!(feature = "transfer-review-groupless")),
    ("intake-grouped", cfg!(feature = "intake-grouped")),
    ("intake-groupless", cfg!(feature = "intake-groupless")),
    ("transfer-intake-grouped", cfg!(feature = "transfer-intake-grouped")),
    ("transfer-intake-groupless", cfg!(feature = "transfer-intake-groupless")),
    ("session-grouped", cfg!(feature = "session-grouped")),
    ("session-groupless", cfg!(feature = "session-groupless")),
    ("priced-session-grouped", cfg!(feature = "priced-session-grouped")),
    ("priced-session-groupless", cfg!(feature = "priced-session-groupless")),
    ("transfer-session-grouped", cfg!(feature = "transfer-session-grouped")),
    ("transfer-session-groupless", cfg!(feature = "transfer-session-groupless")),
    ("priced-transfer-session-grouped", cfg!(feature = "priced-transfer-session-grouped")),
    ("priced-transfer-session-groupless", cfg!(feature = "priced-transfer-session-groupless")),
    ("rewire-grouped", cfg!(feature = "rewire-grouped")),
    ("rewire-groupless", cfg!(feature = "rewire-groupless")),
    ("transcode-grouped", cfg!(feature = "transcode-grouped")),
    ("transcode-groupless", cfg!(feature = "transcode-groupless")),
    ("stream-adopt-grouped", cfg!(feature = "stream-adopt-grouped")),
    ("stream-adopt-groupless", cfg!(feature = "stream-adopt-groupless")),
    ("transfer-stream-adopt-grouped", cfg!(feature = "transfer-stream-adopt-grouped")),
    ("transfer-stream-adopt-groupless", cfg!(feature = "transfer-stream-adopt-groupless")),
    ("stream-draft-grouped", cfg!(feature = "stream-draft-grouped")),
    ("stream-draft-groupless", cfg!(feature = "stream-draft-groupless")),
    ("transfer-stream-draft-grouped", cfg!(feature = "transfer-stream-draft-grouped")),
    ("transfer-stream-draft-groupless", cfg!(feature = "transfer-stream-draft-groupless")),
    ("stream-intake-grouped", cfg!(feature = "stream-intake-grouped")),
    ("stream-intake-groupless", cfg!(feature = "stream-intake-groupless")),
    ("transfer-stream-intake-grouped", cfg!(feature = "transfer-stream-intake-grouped")),
    ("transfer-stream-intake-groupless", cfg!(feature = "transfer-stream-intake-groupless")),
    ("replay-rewrite-grouped", cfg!(feature = "replay-rewrite-grouped")),
    ("replay-rewrite-groupless", cfg!(feature = "replay-rewrite-groupless")),
    ("replay-convert-grouped", cfg!(feature = "replay-convert-grouped")),
    ("replay-convert-groupless", cfg!(feature = "replay-convert-groupless")),
    ("replay-splice-grouped", cfg!(feature = "replay-splice-grouped")),
    ("replay-splice-groupless", cfg!(feature = "replay-splice-groupless")),
    ("overhaul-grouped", cfg!(feature = "overhaul-grouped")),
    ("overhaul-groupless", cfg!(feature = "overhaul-groupless")),
    ("maintain-grouped", cfg!(feature = "maintain-grouped")),
    ("maintain-groupless", cfg!(feature = "maintain-groupless")),
    ("refit-grouped", cfg!(feature = "refit-grouped")),
    ("refit-groupless", cfg!(feature = "refit-groupless")),
    ("commission-grouped", cfg!(feature = "commission-grouped")),
    ("commission-groupless", cfg!(feature = "commission-groupless")),
    ("construct-grouped", cfg!(feature = "construct-grouped")),
    ("construct-groupless", cfg!(feature = "construct-groupless")),
];

/// The table above IS the declared roster: a feature added to the
/// manifest without a table row (or a row for a feature the
/// manifest dropped) reddens here, so "every feature" stays a
/// judged fact rather than a comment's hope.
#[test]
fn the_features_table_is_the_declared_roster() {
    let manifest = fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
        .expect("Cargo.toml is readable");
    let mut declared: Vec<&str> = Vec::new();
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
        // Declarations open as `name = …` at line start; multi-line
        // value continuations never do.
        if let Some((name, _)) = line.split_once(" = ")
            && !name.starts_with(char::is_whitespace)
            && name.trim() != "default"
        {
            declared.push(name.trim());
        }
    }
    assert!(declared.len() >= 90, "the feature parse found only {} entries", declared.len());
    let table: Vec<&str> = FEATURES.iter().map(|(name, _)| *name).collect();
    let missing: Vec<&&str> = declared.iter().filter(|f| !table.contains(f)).collect();
    let stray: Vec<&&str> = table.iter().filter(|f| !declared.contains(f)).collect();
    assert!(
        missing.is_empty() && stray.is_empty(),
        "the FEATURES table drifted from the manifest — missing: {missing:?}, stray: {stray:?}"
    );
}

/// The grouped dialect table's consuming closure (mirror of the
/// gate on `wire::grouped`).
const fn wire_grouped_expected() -> bool {
    cfg!(any(
        feature = "wire-grouped",
        feature = "select-grouped",
        feature = "traverse-grouped",
        feature = "scan-grouped",
        feature = "route-grouped",
        feature = "rewrite-grouped",
        feature = "inplace-grouped",
        feature = "fixed-inplace-grouped",
        feature = "rewire-grouped",
        feature = "transcode-grouped",
        feature = "convert-grouped",
        feature = "convert-groupless",
        feature = "splice-grouped",
        feature = "inspect-grouped",
        feature = "fixed-inspect-grouped",
        feature = "retain-grouped",
        feature = "collect-grouped",
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
        feature = "survey-grouped",
        feature = "replay-rewrite-grouped",
        feature = "replay-convert-grouped",
        feature = "replay-convert-groupless",
        feature = "replay-splice-grouped",
        feature = "overhaul-grouped",
        feature = "maintain-grouped",
        feature = "refit-grouped",
        feature = "commission-grouped",
        feature = "construct-grouped"
    ))
}

/// `wire_grouped_expected`'s adjacent twin — the gate's feature
/// tokens in gate order, held set-equal to `src/wire.rs` by the
/// sync judge.
const WIRE_GROUPED_GATE: &[&str] = &[
    "wire-grouped",
    "select-grouped",
    "traverse-grouped",
    "scan-grouped",
    "route-grouped",
    "rewrite-grouped",
    "inplace-grouped",
    "fixed-inplace-grouped",
    "rewire-grouped",
    "transcode-grouped",
    "convert-grouped",
    "convert-groupless",
    "splice-grouped",
    "inspect-grouped",
    "fixed-inspect-grouped",
    "retain-grouped",
    "collect-grouped",
    "patch-grouped",
    "fixed-patch-grouped",
    "adopt-grouped",
    "amend-grouped",
    "intake-grouped",
    "markup-grouped",
    "draft-grouped",
    "review-grouped",
    "session-grouped",
    "stream-adopt-grouped",
    "stream-draft-grouped",
    "stream-intake-grouped",
    "survey-grouped",
    "replay-rewrite-grouped",
    "replay-convert-grouped",
    "replay-convert-groupless",
    "replay-splice-grouped",
    "overhaul-grouped",
    "maintain-grouped",
    "refit-grouped",
    "commission-grouped",
    "construct-grouped",
];

/// The groupless dialect table's consuming closure (mirror of the
/// gate on `wire::groupless`).
const fn wire_groupless_expected() -> bool {
    cfg!(any(
        feature = "wire-groupless",
        feature = "select-groupless",
        feature = "traverse-groupless",
        feature = "scan-groupless",
        feature = "route-groupless",
        feature = "rewrite-groupless",
        feature = "inplace-groupless",
        feature = "fixed-inplace-groupless",
        feature = "rewire-groupless",
        feature = "transcode-groupless",
        feature = "convert-grouped",
        feature = "convert-groupless",
        feature = "splice-groupless",
        feature = "inspect-groupless",
        feature = "fixed-inspect-groupless",
        feature = "retain-groupless",
        feature = "collect-groupless",
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
        feature = "survey-groupless",
        feature = "replay-rewrite-groupless",
        feature = "replay-convert-grouped",
        feature = "replay-convert-groupless",
        feature = "replay-splice-groupless",
        feature = "overhaul-groupless",
        feature = "maintain-groupless",
        feature = "refit-groupless",
        feature = "commission-groupless",
        feature = "construct-groupless"
    ))
}

/// `wire_groupless_expected`'s adjacent twin — the gate's feature
/// tokens in gate order, held set-equal to `src/wire.rs` by the
/// sync judge.
const WIRE_GROUPLESS_GATE: &[&str] = &[
    "wire-groupless",
    "select-groupless",
    "traverse-groupless",
    "scan-groupless",
    "route-groupless",
    "rewrite-groupless",
    "inplace-groupless",
    "fixed-inplace-groupless",
    "rewire-groupless",
    "transcode-groupless",
    "convert-grouped",
    "convert-groupless",
    "splice-groupless",
    "inspect-groupless",
    "fixed-inspect-groupless",
    "retain-groupless",
    "collect-groupless",
    "patch-groupless",
    "fixed-patch-groupless",
    "adopt-groupless",
    "amend-groupless",
    "intake-groupless",
    "markup-groupless",
    "draft-groupless",
    "review-groupless",
    "session-groupless",
    "stream-adopt-groupless",
    "stream-draft-groupless",
    "stream-intake-groupless",
    "survey-groupless",
    "replay-rewrite-groupless",
    "replay-convert-grouped",
    "replay-convert-groupless",
    "replay-splice-groupless",
    "overhaul-groupless",
    "maintain-groupless",
    "refit-groupless",
    "commission-groupless",
    "construct-groupless",
];

/// The buffered kernel's consuming closure (mirror of the gate on
/// `varint::slice`).
const fn varint_slice_expected() -> bool {
    cfg!(any(
        feature = "varint-slice",
        feature = "select-grouped",
        feature = "select-groupless",
        feature = "traverse-grouped",
        feature = "traverse-groupless",
        feature = "rewrite-grouped",
        feature = "rewrite-groupless",
        feature = "inplace-grouped",
        feature = "inplace-groupless",
        feature = "fixed-inplace-grouped",
        feature = "fixed-inplace-groupless",
        feature = "convert-grouped",
        feature = "convert-groupless",
        feature = "splice-grouped",
        feature = "splice-groupless",
        feature = "inspect-grouped",
        feature = "inspect-groupless",
        feature = "fixed-inspect-grouped",
        feature = "fixed-inspect-groupless",
        feature = "retain-grouped",
        feature = "retain-groupless",
        feature = "collect-grouped",
        feature = "collect-groupless",
        feature = "patch-grouped",
        feature = "patch-groupless",
        feature = "fixed-patch-grouped",
        feature = "fixed-patch-groupless",
        feature = "adopt-grouped",
        feature = "adopt-groupless",
        feature = "amend-grouped",
        feature = "amend-groupless",
        feature = "intake-grouped",
        feature = "intake-groupless",
        feature = "markup-grouped",
        feature = "markup-groupless",
        feature = "draft-grouped",
        feature = "draft-groupless",
        feature = "review-grouped",
        feature = "review-groupless",
        feature = "session-grouped",
        feature = "session-groupless",
        feature = "stream-adopt-grouped",
        feature = "stream-adopt-groupless",
        feature = "stream-draft-grouped",
        feature = "stream-draft-groupless",
        feature = "stream-intake-grouped",
        feature = "stream-intake-groupless",
        feature = "construct-grouped",
        feature = "construct-groupless"
    ))
}

/// `varint_slice_expected`'s adjacent twin — the gate's feature
/// tokens in gate order, held set-equal to `src/varint.rs` by the
/// sync judge.
const VARINT_SLICE_GATE: &[&str] = &[
    "varint-slice",
    "select-grouped",
    "select-groupless",
    "traverse-grouped",
    "traverse-groupless",
    "rewrite-grouped",
    "rewrite-groupless",
    "inplace-grouped",
    "inplace-groupless",
    "fixed-inplace-grouped",
    "fixed-inplace-groupless",
    "convert-grouped",
    "convert-groupless",
    "splice-grouped",
    "splice-groupless",
    "inspect-grouped",
    "inspect-groupless",
    "fixed-inspect-grouped",
    "fixed-inspect-groupless",
    "retain-grouped",
    "retain-groupless",
    "collect-grouped",
    "collect-groupless",
    "patch-grouped",
    "patch-groupless",
    "fixed-patch-grouped",
    "fixed-patch-groupless",
    "adopt-grouped",
    "adopt-groupless",
    "amend-grouped",
    "amend-groupless",
    "intake-grouped",
    "intake-groupless",
    "markup-grouped",
    "markup-groupless",
    "draft-grouped",
    "draft-groupless",
    "review-grouped",
    "review-groupless",
    "session-grouped",
    "session-groupless",
    "stream-adopt-grouped",
    "stream-adopt-groupless",
    "stream-draft-grouped",
    "stream-draft-groupless",
    "stream-intake-grouped",
    "stream-intake-groupless",
    "construct-grouped",
    "construct-groupless",
];

/// The stream kernel's consuming closure (mirror of the gate on
/// `varint::carry`).
const fn varint_carry_expected() -> bool {
    cfg!(any(
        feature = "varint-carry",
        feature = "scan-grouped",
        feature = "scan-groupless",
        feature = "route-grouped",
        feature = "route-groupless",
        feature = "rewire-grouped",
        feature = "rewire-groupless",
        feature = "transcode-grouped",
        feature = "transcode-groupless",
        feature = "survey-grouped",
        feature = "survey-groupless",
        feature = "replay-rewrite-grouped",
        feature = "replay-rewrite-groupless",
        feature = "replay-convert-grouped",
        feature = "replay-convert-groupless",
        feature = "replay-splice-grouped",
        feature = "replay-splice-groupless",
        feature = "overhaul-grouped",
        feature = "overhaul-groupless",
        feature = "maintain-grouped",
        feature = "maintain-groupless",
        feature = "refit-grouped",
        feature = "refit-groupless",
        feature = "commission-grouped",
        feature = "commission-groupless"
    ))
}

/// `varint_carry_expected`'s adjacent twin — the gate's feature
/// tokens in gate order, held set-equal to `src/varint.rs` by the
/// sync judge.
const VARINT_CARRY_GATE: &[&str] = &[
    "varint-carry",
    "scan-grouped",
    "scan-groupless",
    "route-grouped",
    "route-groupless",
    "rewire-grouped",
    "rewire-groupless",
    "transcode-grouped",
    "transcode-groupless",
    "survey-grouped",
    "survey-groupless",
    "replay-rewrite-grouped",
    "replay-rewrite-groupless",
    "replay-convert-grouped",
    "replay-convert-groupless",
    "replay-splice-grouped",
    "replay-splice-groupless",
    "overhaul-grouped",
    "overhaul-groupless",
    "maintain-grouped",
    "maintain-groupless",
    "refit-grouped",
    "refit-groupless",
    "commission-grouped",
    "commission-groupless",
];

/// The scalar matrix's consuming closure (mirror of the gate on
/// `scalar`).
const fn scalar_expected() -> bool {
    cfg!(any(feature = "scalar", feature = "construct-grouped", feature = "construct-groupless"))
}

/// `scalar_expected`'s adjacent twin — the gate's feature tokens
/// in gate order, held set-equal to `src/lib.rs` by the sync
/// judge.
const SCALAR_GATE: &[&str] = &["scalar", "construct-grouped", "construct-groupless"];

/// The stable-replay supply stratum's consuming closure (mirror
/// of the gate on `replay_source`).
const fn replay_source_expected() -> bool {
    cfg!(any(
        feature = "replay-source",
        feature = "survey-grouped",
        feature = "survey-groupless",
        feature = "replay-rewrite-grouped",
        feature = "replay-rewrite-groupless",
        feature = "replay-convert-grouped",
        feature = "replay-convert-groupless",
        feature = "replay-splice-grouped",
        feature = "replay-splice-groupless",
        feature = "overhaul-grouped",
        feature = "overhaul-groupless",
        feature = "maintain-grouped",
        feature = "maintain-groupless",
        feature = "refit-grouped",
        feature = "refit-groupless",
        feature = "commission-grouped",
        feature = "commission-groupless"
    ))
}

/// `replay_source_expected`'s adjacent twin — the gate's feature
/// tokens in gate order, held set-equal to `src/lib.rs` by the
/// sync judge.
const REPLAY_SOURCE_GATE: &[&str] = &[
    "replay-source",
    "survey-grouped",
    "survey-groupless",
    "replay-rewrite-grouped",
    "replay-rewrite-groupless",
    "replay-convert-grouped",
    "replay-convert-groupless",
    "replay-splice-grouped",
    "replay-splice-groupless",
    "overhaul-grouped",
    "overhaul-groupless",
    "maintain-grouped",
    "maintain-groupless",
    "refit-grouped",
    "refit-groupless",
    "commission-grouped",
    "commission-groupless",
];

/// The writers' trail element follows the five cells that mint it
/// (mirror of the gate on `replay_source::SourceCrossing`).
const fn source_crossing_expected() -> bool {
    cfg!(any(
        feature = "replay-rewrite-grouped",
        feature = "replay-rewrite-groupless",
        feature = "replay-convert-grouped",
        feature = "replay-splice-grouped",
        feature = "replay-splice-groupless"
    ))
}

/// `source_crossing_expected`'s adjacent twin — the gate's feature
/// tokens in gate order, held set-equal to `src/replay_source.rs`
/// by the sync judge.
const SOURCE_CROSSING_GATE: &[&str] = &[
    "replay-rewrite-grouped",
    "replay-rewrite-groupless",
    "replay-convert-grouped",
    "replay-splice-grouped",
    "replay-splice-groupless",
];

/// One probed leaf's tie to its source gate: the file that owns
/// the gated declaration, the declaration line itself (the
/// extraction anchor), and the token list the mirror keeps. Each
/// list is the adjacent twin of the leaf's `cfg!` expectation —
/// the named consts above for the mirror fns, the inline lists
/// here for the single-cell probes below.
struct GateSite {
    leaf: &'static str,
    file: &'static str,
    anchor: &'static str,
    tokens: &'static [&'static str],
}

/// Every probed leaf, tied to the gate its expectation mirrors,
/// in probe order.
const LEAF_GATES: &[GateSite] = &[
    GateSite {
        leaf: "wire::grouped",
        file: "src/wire.rs",
        anchor: "pub mod grouped;",
        tokens: WIRE_GROUPED_GATE,
    },
    GateSite {
        leaf: "wire::groupless",
        file: "src/wire.rs",
        anchor: "pub mod groupless;",
        tokens: WIRE_GROUPLESS_GATE,
    },
    GateSite {
        leaf: "varint::slice",
        file: "src/varint.rs",
        anchor: "pub mod slice;",
        tokens: VARINT_SLICE_GATE,
    },
    GateSite {
        leaf: "varint::carry",
        file: "src/varint.rs",
        anchor: "pub mod carry;",
        tokens: VARINT_CARRY_GATE,
    },
    GateSite { leaf: "scalar", file: "src/lib.rs", anchor: "pub mod scalar;", tokens: SCALAR_GATE },
    GateSite {
        leaf: "scan",
        file: "src/lib.rs",
        anchor: "pub mod scan;",
        tokens: &["scan-grouped", "scan-groupless"],
    },
    GateSite {
        leaf: "route::grouped",
        file: "src/route.rs",
        anchor: "pub mod grouped;",
        tokens: &["route-grouped"],
    },
    GateSite {
        leaf: "route::groupless",
        file: "src/route.rs",
        anchor: "pub mod groupless;",
        tokens: &["route-groupless"],
    },
    GateSite {
        leaf: "transcode::grouped",
        file: "src/transcode.rs",
        anchor: "pub mod grouped;",
        tokens: &["transcode-grouped"],
    },
    GateSite {
        leaf: "transcode::groupless",
        file: "src/transcode.rs",
        anchor: "pub mod groupless;",
        tokens: &["transcode-groupless"],
    },
    GateSite {
        leaf: "rewire::grouped",
        file: "src/rewire.rs",
        anchor: "pub mod grouped;",
        tokens: &["rewire-grouped"],
    },
    GateSite {
        leaf: "rewire::groupless",
        file: "src/rewire.rs",
        anchor: "pub mod groupless;",
        tokens: &["rewire-groupless"],
    },
    GateSite {
        leaf: "traverse",
        file: "src/lib.rs",
        anchor: "pub mod traverse;",
        tokens: &["traverse-grouped", "traverse-groupless"],
    },
    GateSite {
        leaf: "select::grouped",
        file: "src/select.rs",
        anchor: "pub mod grouped;",
        tokens: &["select-grouped"],
    },
    GateSite {
        leaf: "select::groupless",
        file: "src/select.rs",
        anchor: "pub mod groupless;",
        tokens: &["select-groupless"],
    },
    GateSite {
        leaf: "rewrite::grouped",
        file: "src/rewrite.rs",
        anchor: "pub mod grouped;",
        tokens: &["rewrite-grouped"],
    },
    GateSite {
        leaf: "rewrite::groupless",
        file: "src/rewrite.rs",
        anchor: "pub mod groupless;",
        tokens: &["rewrite-groupless"],
    },
    GateSite {
        leaf: "inplace::grouped",
        file: "src/inplace.rs",
        anchor: "pub mod grouped;",
        tokens: &["inplace-grouped"],
    },
    GateSite {
        leaf: "inplace::groupless",
        file: "src/inplace.rs",
        anchor: "pub mod groupless;",
        tokens: &["inplace-groupless"],
    },
    GateSite {
        leaf: "convert::grouped",
        file: "src/convert.rs",
        anchor: "pub mod grouped;",
        tokens: &["convert-grouped"],
    },
    GateSite {
        leaf: "convert::groupless",
        file: "src/convert.rs",
        anchor: "pub mod groupless;",
        tokens: &["convert-groupless"],
    },
    GateSite {
        leaf: "splice::grouped",
        file: "src/splice.rs",
        anchor: "pub mod grouped;",
        tokens: &["splice-grouped"],
    },
    GateSite {
        leaf: "splice::groupless",
        file: "src/splice.rs",
        anchor: "pub mod groupless;",
        tokens: &["splice-groupless"],
    },
    GateSite {
        leaf: "replay_source",
        file: "src/lib.rs",
        anchor: "pub mod replay_source;",
        tokens: REPLAY_SOURCE_GATE,
    },
    GateSite {
        leaf: "replay_source::SourceCrossing",
        file: "src/replay_source.rs",
        anchor: "pub struct SourceCrossing {",
        tokens: SOURCE_CROSSING_GATE,
    },
];

/// Reads the `feature = "…"` tokens of the attribute block sitting
/// immediately above `anchor` in `text`. The block is collected
/// upward line by line — multi-line attributes by square-bracket
/// balance, `//` comment lines tolerated anywhere — and every
/// failure mode is loud: a missing or ambiguous anchor, a
/// malformed block, a block with no `#[cfg(` attribute, and a gate
/// naming zero features all panic rather than read as an empty
/// gate.
fn gate_tokens(text: &str, file: &str, anchor: &str) -> Vec<String> {
    let lines: Vec<&str> = text.lines().collect();
    let hits: Vec<usize> = (0..lines.len()).filter(|&i| lines[i].trim() == anchor).collect();
    let &[at] = hits.as_slice() else {
        panic!("{file}: anchor `{anchor}` matched {} lines, need exactly one", hits.len());
    };
    let mut attrs: Vec<&str> = Vec::new();
    let mut pending = 0usize;
    for i in (0..at).rev() {
        let t = lines[i].trim();
        if t.starts_with("//") {
            continue;
        }
        let opens = t.matches('[').count();
        let closes = t.matches(']').count();
        if pending == 0 && closes <= opens && !(t.starts_with("#[") && closes == opens) {
            break;
        }
        attrs.push(t);
        pending = (pending + closes)
            .checked_sub(opens)
            .unwrap_or_else(|| panic!("{file}: unbalanced attribute above `{anchor}`"));
        if pending == 0 {
            assert!(
                t.starts_with("#["),
                "{file}: the attribute block above `{anchor}` does not open with `#[`"
            );
        }
    }
    assert!(pending == 0, "{file}: the attribute above `{anchor}` never opens");
    assert!(!attrs.is_empty(), "{file}: no attribute block above `{anchor}`");
    attrs.reverse();
    let block = attrs.join("\n");
    assert!(block.contains("#[cfg("), "{file}: the block above `{anchor}` is not a cfg gate");
    let mut tokens = Vec::new();
    let mut rest = block.as_str();
    while let Some(hit) = rest.find("feature") {
        rest = &rest[hit + "feature".len()..];
        let Some(eq) = rest.trim_start().strip_prefix('=') else { continue };
        let Some(quoted) = eq.trim_start().strip_prefix('"') else { continue };
        let end = quoted
            .find('"')
            .unwrap_or_else(|| panic!("{file}: unterminated feature token above `{anchor}`"));
        tokens.push(quoted[..end].to_string());
        rest = &quoted[end..];
    }
    assert!(!tokens.is_empty(), "{file}: the gate above `{anchor}` names no features");
    tokens
}

/// The source-vs-mirror sync judge: for every probed leaf, the
/// real gate is read out of the owning source file and its
/// `feature` tokens must be set-equal to the leaf's mirror list
/// (`test` arms fall away because only feature names are
/// tokenized). This closes the coverage boundary the compile
/// probes leave open: a stale mirror reds here under every feature
/// set, where the probes alone red it only in the sibling-only
/// cells CI's feature unions never build.
#[test]
fn the_expectation_mirrors_transcribe_the_source_gates() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for site in LEAF_GATES {
        let text = fs::read_to_string(root.join(site.file))
            .unwrap_or_else(|fault| panic!("{} is readable: {fault}", site.file));
        let gate = gate_tokens(&text, site.file, site.anchor);
        let gate: BTreeSet<&str> = gate.iter().map(String::as_str).collect();
        let mirror: BTreeSet<&str> = site.tokens.iter().copied().collect();
        let missing: Vec<&&str> = gate.difference(&mirror).collect();
        let stray: Vec<&&str> = mirror.difference(&gate).collect();
        assert!(
            missing.is_empty() && stray.is_empty(),
            "{}: the mirror drifted from the gate on `{}` in {} — gate tokens absent from \
             the mirror: {missing:?}, mirror tokens absent from the gate: {stray:?}",
            site.leaf,
            site.anchor,
            site.file
        );
    }
}

/// One leaf probe: the import lines that must resolve exactly when
/// the leaf is selected, and the unresolved-import marker that must
/// name the leaf when it is not.
struct Probe {
    leaf: &'static str,
    source: &'static str,
    absence_marker: &'static str,
    expected_present: bool,
}

fn probes() -> Vec<Probe> {
    vec![
        Probe {
            leaf: "wire::grouped",
            source: "pub use protobuf_edit::wire::grouped::{\n    RecordKind, TagClass, classify, group_end_word, head_word,\n};\n",
            absence_marker: "`grouped`",
            expected_present: wire_grouped_expected(),
        },
        Probe {
            leaf: "wire::groupless",
            source: "pub use protobuf_edit::wire::groupless::{RecordKind, TagClass, classify, head_word};\n",
            absence_marker: "`groupless`",
            expected_present: wire_groupless_expected(),
        },
        Probe {
            leaf: "varint::slice",
            source: "pub use protobuf_edit::varint::slice::{ReadFault, len_word, tag_word, value64};\n",
            absence_marker: "`slice`",
            expected_present: varint_slice_expected(),
        },
        Probe {
            leaf: "varint::carry",
            source: "pub use protobuf_edit::varint::carry::{Carry, Step};\n",
            absence_marker: "`carry`",
            expected_present: varint_carry_expected(),
        },
        Probe {
            leaf: "scalar",
            source: "pub use protobuf_edit::scalar::{OutOfDomain, decode_uint32, encode_sint32};\n",
            absence_marker: "`scalar`",
            expected_present: scalar_expected(),
        },
        // The scan/route/transcode/rewire cells share the private
        // stream pump: each cell's own faces compile exactly under
        // its own feature, and no partner's surface rides along.
        Probe {
            leaf: "scan",
            source: "pub use protobuf_edit::scan::{Flow, LenDisposition, ReadFault};\n",
            absence_marker: "protobuf_edit::scan",
            expected_present: cfg!(any(feature = "scan-grouped", feature = "scan-groupless")),
        },
        Probe {
            leaf: "route::grouped",
            source: "pub use protobuf_edit::route::grouped::{Router, Sink};\n",
            absence_marker: "protobuf_edit::route::grouped",
            expected_present: cfg!(feature = "route-grouped"),
        },
        Probe {
            leaf: "route::groupless",
            source: "pub use protobuf_edit::route::groupless::{Router, Sink};\n",
            absence_marker: "protobuf_edit::route::groupless",
            expected_present: cfg!(feature = "route-groupless"),
        },
        Probe {
            leaf: "transcode::grouped",
            source: "pub use protobuf_edit::transcode::grouped::{Rule, Transcoder};\n",
            absence_marker: "protobuf_edit::transcode::grouped",
            expected_present: cfg!(feature = "transcode-grouped"),
        },
        Probe {
            leaf: "transcode::groupless",
            source: "pub use protobuf_edit::transcode::groupless::{Rule, Transcoder};\n",
            absence_marker: "protobuf_edit::transcode::groupless",
            expected_present: cfg!(feature = "transcode-groupless"),
        },
        Probe {
            leaf: "rewire::grouped",
            source: "pub use protobuf_edit::rewire::grouped::{Fault, Rewirer};\n",
            absence_marker: "protobuf_edit::rewire::grouped",
            expected_present: cfg!(feature = "rewire-grouped"),
        },
        Probe {
            leaf: "rewire::groupless",
            source: "pub use protobuf_edit::rewire::groupless::{Fault, Rewirer};\n",
            absence_marker: "protobuf_edit::rewire::groupless",
            expected_present: cfg!(feature = "rewire-groupless"),
        },
        // The select/rewrite/inplace/convert/splice cells share
        // the private cursor engines with traverse: same
        // discipline as the pump trio above.
        Probe {
            leaf: "traverse",
            source: "pub use protobuf_edit::traverse::{Oversize, packed::Varints};\n",
            absence_marker: "protobuf_edit::traverse",
            expected_present: cfg!(any(
                feature = "traverse-grouped",
                feature = "traverse-groupless"
            )),
        },
        Probe {
            leaf: "select::grouped",
            source: "pub use protobuf_edit::select::grouped::{Match, Matches};\n",
            absence_marker: "protobuf_edit::select::grouped",
            expected_present: cfg!(feature = "select-grouped"),
        },
        Probe {
            leaf: "select::groupless",
            source: "pub use protobuf_edit::select::groupless::{Match, Matches};\n",
            absence_marker: "protobuf_edit::select::groupless",
            expected_present: cfg!(feature = "select-groupless"),
        },
        Probe {
            leaf: "rewrite::grouped",
            source: "pub use protobuf_edit::rewrite::grouped::{Fault, rewrite};\n",
            absence_marker: "protobuf_edit::rewrite::grouped",
            expected_present: cfg!(feature = "rewrite-grouped"),
        },
        Probe {
            leaf: "rewrite::groupless",
            source: "pub use protobuf_edit::rewrite::groupless::{Fault, rewrite};\n",
            absence_marker: "protobuf_edit::rewrite::groupless",
            expected_present: cfg!(feature = "rewrite-groupless"),
        },
        Probe {
            leaf: "inplace::grouped",
            source: "pub use protobuf_edit::inplace::grouped::{Fault, apply};\n",
            absence_marker: "protobuf_edit::inplace::grouped",
            expected_present: cfg!(feature = "inplace-grouped"),
        },
        Probe {
            leaf: "inplace::groupless",
            source: "pub use protobuf_edit::inplace::groupless::{Fault, apply};\n",
            absence_marker: "protobuf_edit::inplace::groupless",
            expected_present: cfg!(feature = "inplace-groupless"),
        },
        Probe {
            leaf: "convert::grouped",
            source: "pub use protobuf_edit::convert::grouped::{Converter, Fault};\n",
            absence_marker: "protobuf_edit::convert::grouped",
            expected_present: cfg!(feature = "convert-grouped"),
        },
        Probe {
            leaf: "convert::groupless",
            source: "pub use protobuf_edit::convert::groupless::{Converter, Fault};\n",
            absence_marker: "protobuf_edit::convert::groupless",
            expected_present: cfg!(feature = "convert-groupless"),
        },
        Probe {
            leaf: "splice::grouped",
            source: "pub use protobuf_edit::splice::grouped::{Fault, splice};\n",
            absence_marker: "protobuf_edit::splice::grouped",
            expected_present: cfg!(feature = "splice-grouped"),
        },
        Probe {
            leaf: "splice::groupless",
            source: "pub use protobuf_edit::splice::groupless::{Fault, splice};\n",
            absence_marker: "protobuf_edit::splice::groupless",
            expected_present: cfg!(feature = "splice-groupless"),
        },
        // The stable-replay supply stratum: the roster minus the
        // writers' trail element rides the union of its consumers,
        // and the trail element follows the five writer cells that
        // mint it — so a replay-source-only build publishes exactly
        // the constructible set.
        Probe {
            leaf: "replay_source",
            source: "pub use protobuf_edit::replay_source::{\n    Chunk, Handed, ReplayFault, ReplayPhase, ReplayWalk, SliceFault, SliceSource, SliceWalk,\n    SourceSpan, StableReplaySource, SupplyFault, discard_skip,\n};\n",
            absence_marker: "protobuf_edit::replay_source",
            expected_present: replay_source_expected(),
        },
        Probe {
            leaf: "replay_source::SourceCrossing",
            source: "pub use protobuf_edit::replay_source::SourceCrossing;\n",
            // The unresolved-import error names the deepest segment
            // that exists: the type when only the type is gated off,
            // the module when `replay_source` itself is absent.
            absence_marker: if replay_source_expected() {
                "`SourceCrossing`"
            } else {
                "`replay_source`"
            },
            expected_present: source_crossing_expected(),
        },
    ]
}

/// The standing positive control: root vocabulary present in every
/// cell. Its compilation is the harness proof — path dependency,
/// feature re-selection, and toolchain all work — required before
/// any absence verdict is accepted.
const CONTROL_SOURCE: &str = "pub use protobuf_edit::wire::{FieldNumber, Low3, PayloadLen};\npub use protobuf_edit::{DepthLimit, FaultClass, Span, Stage, Standard};\n";

/// Lays down the probe package and returns its directory; the
/// manifest re-selects exactly the ambient feature set.
fn probe_dir() -> PathBuf {
    let manifest = env::var("CARGO_MANIFEST_DIR").expect("cargo sets the manifest dir");
    let target = env::var("CARGO_TARGET_DIR")
        .map_or_else(|_| PathBuf::from(&manifest).join("target"), PathBuf::from);
    let dir = target.join("substrate_presence_probe");
    fs::create_dir_all(dir.join("src")).expect("probe directory is writable");
    let features: Vec<String> = FEATURES
        .iter()
        .filter(|(_, enabled)| *enabled)
        .map(|(name, _)| format!("\"{name}\""))
        .collect();
    let manifest_text = format!(
        "[package]\nname = \"substrate_presence_probe\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n[workspace]\n\n[dependencies]\nprotobuf_edit = {{ path = \"{}\", default-features = false, features = [{}] }}\n",
        manifest.replace('\\', "/"),
        features.join(", ")
    );
    fs::write(dir.join("Cargo.toml"), manifest_text).expect("probe manifest is writable");
    dir
}

/// Checks one probe source; returns the compiler's verdict.
fn check(dir: &PathBuf, source: &str) -> (bool, String) {
    fs::write(dir.join("src").join("lib.rs"), format!("#![no_std]\n{source}"))
        .expect("probe source is writable");
    let cargo = env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let out = Command::new(cargo)
        .args(["check", "--offline", "--quiet"])
        .current_dir(dir)
        .env("CARGO_TARGET_DIR", dir.join("target"))
        .output()
        .expect("cargo spawns");
    (out.status.success(), String::from_utf8_lossy(&out.stderr).into_owned())
}

#[test]
fn substrate_leaves_track_their_selection() {
    let dir = probe_dir();

    // Harness proof first: presence detection must work in this
    // cell before absence is believed.
    let (ok, stderr) = check(&dir, CONTROL_SOURCE);
    assert!(ok, "positive control failed — the harness cannot judge this cell:\n{stderr}");

    for probe in probes() {
        let (ok, stderr) = check(&dir, probe.source);
        if probe.expected_present {
            assert!(
                ok,
                "{}: selected by this cell but its vocabulary does not compile \
                 (gate too narrow, or judge expectation stale):\n{stderr}",
                probe.leaf
            );
        } else {
            assert!(
                !ok,
                "{}: not selected by this cell but its vocabulary compiles — \
                 a compile-presence leak (gate too wide, or judge expectation stale)",
                probe.leaf
            );
            assert!(
                (stderr.contains("E0432") || stderr.contains("E0433"))
                    && stderr.contains(probe.absence_marker),
                "{}: probe failed for a reason other than the leaf's absence — \
                 harness fault, not a verdict:\n{stderr}",
                probe.leaf
            );
        }
    }
}
