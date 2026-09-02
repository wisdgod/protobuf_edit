//! Corpus alignment: every dialect against the frozen libprotoc
//! 35.1 observations in `references/vectors/cases.toml`.
//!
//! The corpus file is local (gitignored) but content-addressed
//! here: its SHA-256 digest is tracked below and judged at every
//! load, so the observations these suites pin are exactly one
//! reproducible byte sequence — a drifted or swapped corpus fails
//! by name, and a missing file is an incomplete environment and
//! panics by name — never a silent skip. Alignment is three-state:
//! the reference accepts cleanly (this crate must too, rendering
//! included where a renderer exists), accepts by a silent wrap
//! this crate deliberately refuses (divergent, faulted by class),
//! or rejects (a fault must exist).

#![cfg(any(
    feature = "inspect-grouped",
    feature = "inspect-groupless",
    feature = "session-grouped",
    feature = "session-groupless",
    feature = "scan-grouped",
    feature = "scan-groupless",
    feature = "traverse-grouped",
    feature = "traverse-groupless",
    feature = "rewrite-grouped",
    feature = "rewrite-groupless",
    feature = "transcode-grouped",
    feature = "transcode-groupless",
    feature = "construct-grouped",
    feature = "construct-groupless"
))]

// The rows that take an explicit depth limit.
#[cfg(any(
    feature = "inspect-grouped",
    feature = "inspect-groupless",
    feature = "scan-grouped",
    feature = "rewrite-grouped",
    feature = "rewrite-groupless",
    feature = "transcode-grouped",
    feature = "transcode-groupless"
))]
use protobuf_edit::DepthLimit;
#[cfg(any(feature = "inspect-grouped", feature = "inspect-groupless"))]
use protobuf_edit::inspect::{Admitted, NoAdvice};

#[cfg(any(feature = "inspect-grouped", feature = "inspect-groupless"))]
#[path = "support/render.rs"]
mod render;

#[path = "support/sha256.rs"]
mod sha256;

// ─── corpus loading (micro TOML subset) ───

/// The frozen corpus's tracked address: 61 decode_raw cases plus
/// the schema-aware rows, 22729 bytes. Regenerating or editing the
/// local file is a corpus change and moves this digest in the same
/// commit.
const CORPUS_SHA256: &str = "6d84cf51791ff36e8bd2fdd43ac0910e87e09b64d76f95fe6a324723c1d23636";

/// The digest's observer, pinned beside it: the corpus header's
/// own `protoc = "…"` provenance must equal this at every load, so
/// a regenerated corpus cannot swap judges silently — the observer
/// moves with the digest, in the same commit.
const CORPUS_PROTOC: &str = "libprotoc 35.1";

#[derive(Default, Clone)]
struct Case {
    name: String,
    mode: String,
    hex: String,
    expect: String,
    output: Option<String>,
    spec_class: Option<String>,
    rc_only: bool,
}

#[track_caller]
fn corpus() -> Vec<Case> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/references/vectors/cases.toml");
    let text =
        std::fs::read_to_string(path).unwrap_or_else(|e| panic!("corpus not found at {path}: {e}"));
    let digest = sha256::digest_hex(text.as_bytes());
    assert_eq!(
        digest, CORPUS_SHA256,
        "corpus at {path} drifted from its tracked digest — pins below would judge \
         different bytes than the frozen observations"
    );
    let observer = text
        .lines()
        .find_map(|line| line.trim().strip_prefix("protoc = "))
        .map(|rest| rest.trim().trim_matches('"'))
        .unwrap_or_else(|| panic!("corpus at {path} carries no protoc provenance header"));
    assert_eq!(
        observer, CORPUS_PROTOC,
        "corpus provenance drifted from the pinned observer — the frozen expectations \
         would be another libprotoc's observations"
    );
    parse_cases(&text)
}

/// Parses exactly the subset the corpus uses — and refuses
/// everything else: `[[case]]` array tables, `key = "basic"` /
/// `key = 'literal'` / `key = """multi"""` strings, bare booleans,
/// and full-line comments. Consumed keys fill the [`Case`];
/// documentation keys are whitelisted by name and deliberately
/// unread. An unknown key, a malformed line, a duplicate key, a
/// header entry other than the provenance line, or a case missing
/// its mode's required fields refuses by name — harness drift is a
/// red, never a silently thinner corpus.
#[track_caller]
fn parse_cases(text: &str) -> Vec<Case> {
    /// Documentation keys the corpus carries for people and for
    /// judges outside this suite: present, whole, unread here.
    const IGNORED: &[&str] = &["claim", "note", "message", "proto", "text", "stderr_contains"];

    /// One completed case faces its mode's required-field law
    /// (presence is judged by key, so an empty document's own
    /// `hex = ""` stays lawful).
    fn finish(case: Case, seen: &[String]) -> Case {
        let has = |key: &str| seen.iter().any(|s| s == key);
        assert!(!case.name.is_empty(), "a corpus case is missing its name");
        let name = case.name.as_str();
        match case.mode.as_str() {
            "decode_raw" | "decode" => {
                assert!(has("hex"), "{name}: missing hex");
                assert!(
                    matches!(case.expect.as_str(), "accept" | "reject"),
                    "{name}: unknown expectation {:?}",
                    case.expect
                );
                if let Some(class) = case.spec_class.as_deref() {
                    assert_eq!(class, "invalid", "{name}: unknown spec class");
                }
                assert!(
                    case.expect != "accept" || case.rc_only || case.output.is_some(),
                    "{name}: an accept case owes its frozen output"
                );
            }
            "encode" => assert!(case.output.is_some(), "{name}: missing output"),
            "compile_fail" => {}
            other => panic!("{name}: unknown mode {other:?}"),
        }
        case
    }

    let mut cases = Vec::new();
    let mut cur: Option<(Case, Vec<String>)> = None;
    let mut lines = text.lines();
    while let Some(line) = lines.next() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line == "[[case]]" {
            if let Some((done, seen)) = cur.take() {
                cases.push(finish(done, &seen));
            }
            cur = Some((Case::default(), Vec::new()));
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            panic!("malformed corpus line (no assignment): {line:?}");
        };
        let (key, value) = (key.trim(), value.trim());
        let Some((case, seen)) = cur.as_mut() else {
            // The header carries exactly the provenance line the
            // loader pins; any other top-level entry is drift.
            assert_eq!(key, "protoc", "unknown corpus header entry {key:?}");
            continue;
        };
        assert!(!seen.iter().any(|s| s == key), "duplicate corpus key {key:?}");
        seen.push(key.to_owned());
        // Three string forms plus bare booleans: a match ladder, not
        // a two-arm Option fold.
        #[allow(clippy::option_if_let_else)]
        let parsed = if let Some(rest) = value.strip_prefix("\"\"\"") {
            // Multi-line basic string: gather until the closing fence.
            let mut body = String::from(rest);
            while !body.trim_end().ends_with("\"\"\"") {
                body.push('\n');
                body.push_str(lines.next().expect("unterminated multi-line string"));
            }
            let trimmed = body.trim_end();
            trimmed[..trimmed.len() - 3].to_string()
        } else if value.starts_with('"') {
            let inner = &value[1..value.rfind('"').expect("unterminated string")];
            inner.replace("\\\"", "\"").replace("\\\\", "\\")
        } else if value.starts_with('\'') {
            value[1..value.rfind('\'').expect("unterminated string")].to_string()
        } else {
            value.to_string() // bare boolean
        };
        match key {
            "name" => case.name = parsed,
            "mode" => case.mode = parsed,
            "hex" => case.hex = parsed,
            "expect" => case.expect = parsed,
            "output" => case.output = Some(parsed),
            "spec_class" => case.spec_class = Some(parsed),
            "rc_only" => case.rc_only = parsed == "true",
            other if IGNORED.contains(&other) => {}
            other => panic!("unknown corpus key {other:?} — teach the parser or fix the corpus"),
        }
    }
    cases.extend(cur.take().map(|(done, seen)| finish(done, &seen)));
    cases
}

/// The parser's own discrimination: every drift shape the
/// whitelist bans must refuse, and the lawful shapes must parse —
/// judged on synthetic text so the frozen corpus stays the only
/// digest-pinned input.
#[test]
fn the_parser_refuses_drift_shapes() {
    use std::panic::{AssertUnwindSafe, catch_unwind};
    let refused = |text: &str| catch_unwind(AssertUnwindSafe(|| parse_cases(text))).is_err();
    // An unknown key.
    assert!(refused("[[case]]\nname = \"x\"\nmode = \"compile_fail\"\nbogus = \"1\"\n"));
    // A malformed non-assignment line.
    assert!(refused("[[case]]\nname up\n"));
    // A duplicate key.
    assert!(refused("[[case]]\nname = \"x\"\nname = \"y\"\nmode = \"compile_fail\"\n"));
    // A header entry other than the provenance line.
    assert!(refused("author = \"nobody\"\n"));
    // A missing required field: decode_raw without hex.
    assert!(refused("[[case]]\nname = \"x\"\nmode = \"decode_raw\"\nexpect = \"accept\"\n"));
    // An unknown mode.
    assert!(refused("[[case]]\nname = \"x\"\nmode = \"observe\"\n"));
    // The lawful shapes parse: the provenance header, a consumed
    // set, an ignored documentation key, and an empty hex value
    // (an empty document is a lawful case).
    let ok = parse_cases(
        "protoc = \"libprotoc 35.1\"\n\n[[case]]\nname = \"x\"\nmode = \"decode_raw\"\n\
         hex = \"\"\nexpect = \"accept\"\noutput = \"\"\nnote = \"docs\"\n",
    );
    assert_eq!(ok.len(), 1);
    assert_eq!(ok[0].name, "x");
}

#[track_caller]
fn unhex(s: &str) -> Vec<u8> {
    let hex: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    assert!(hex.len().is_multiple_of(2), "odd hex literal");
    hex.chunks(2)
        .map(|pair| {
            let hi = (pair[0] as char).to_digit(16).unwrap();
            let lo = (pair[1] as char).to_digit(16).unwrap();
            (hi * 16 + lo) as u8
        })
        .collect()
}

#[track_caller]
fn decode_raw_cases() -> Vec<Case> {
    let cases = corpus();
    assert!(cases.len() > 60, "positive control: the corpus parser found {}", cases.len());
    let cases: Vec<Case> = cases.into_iter().filter(|c| c.mode == "decode_raw").collect();
    // Empty or shrunken loops pass vacuously: pin the population,
    // pin each alignment class (a shrunken class passes vacuously
    // through its own loop arm), and spot-check members from both
    // ends of the file.
    assert_eq!(cases.len(), 61, "decode_raw census drifted");
    let mut split = (0_usize, 0_usize, 0_usize);
    for case in &cases {
        match alignment(case) {
            Alignment::Accept => split.0 += 1,
            Alignment::Divergent => split.1 += 1,
            Alignment::Reject => split.2 += 1,
        }
    }
    assert_eq!(split, (35, 3, 23), "alignment-class census drifted (accept, divergent, reject)");
    for pinned in ["varint_u64_max", "group_depth_101", "cascade_after", "empty_message"] {
        assert!(cases.iter().any(|c| c.name == pinned), "missing pinned case {pinned}");
    }
    cases
}

/// The three-state alignment rule (`oracle_harness.md`).
enum Alignment {
    /// Reference accepts, no divergence: complete + rendered match.
    Accept,
    /// Reference accepts by silent wrap; this crate refuses forgery
    /// (deliberate, on record).
    Divergent,
    /// Reference rejects: a fault must exist.
    Reject,
}

#[track_caller]
fn alignment(case: &Case) -> Alignment {
    match (case.expect.as_str(), case.spec_class.as_deref()) {
        ("accept", None) => Alignment::Accept,
        ("accept", Some("invalid")) => Alignment::Divergent,
        ("reject", _) => Alignment::Reject,
        other => panic!("case {}: unknown expectation {other:?}", case.name),
    }
}

/// Cases whose bytes carry group codes: p3 refuses these as
/// capability faults. Explicit list — not derived from the full
/// dialect's product, to keep the oracle chain free of self-made
/// links. Compiled with its consumers, the groupless dialects'
/// capability arms — the grouped dialects walk these cases through
/// the ordinary alignment path instead.
#[cfg(any(
    feature = "inspect-groupless",
    feature = "scan-groupless",
    feature = "traverse-groupless",
    feature = "rewrite-groupless",
    feature = "transcode-groupless",
    feature = "session-groupless"
))]
const GROUP_CASES: &[&str] = &[
    "group_nonminimal_sgroup_tag",
    "group_nonminimal_egroup_tag",
    "group_match",
    "group_empty",
    "group_mismatch",
    "group_stray_egroup",
    "group_unterminated",
    "group_nested",
    "group_depth_100",
    "group_depth_101",
];

// ─── full dialect ───

#[cfg(feature = "inspect-grouped")]
mod grouped_dialect {
    use protobuf_edit::inspect::Stage;
    use protobuf_edit::inspect::grouped::{FaultKind, Tree};
    use protobuf_edit::varint::slice::ReadFault;
    use super::render::grouped::render;
    use super::*;

    /// One case through the production alignment path — the
    /// verdicts and the render comparison as a result, consumed by
    /// the real loop and by the corrupted-case control alike.
    fn judge(case: &Case) -> Result<(), String> {
        let bytes = unhex(&case.hex);
        let tree =
            Tree::parse(Admitted::new(&bytes).unwrap(), DepthLimit::REFERENCE, &mut NoAdvice);
        let name = case.name.as_str();
        match alignment(case) {
            Alignment::Accept => {
                if !tree.is_complete() {
                    return Err(format!(
                        "{name}: reference accepts, inspector faulted: {:?}",
                        tree.fault()
                    ));
                }
                if !case.rc_only {
                    let expected = case
                        .output
                        .as_deref()
                        .unwrap_or_else(|| panic!("{name}: accept case without frozen output"));
                    if render(&tree) != expected {
                        return Err(format!("{name}: rendered mismatch"));
                    }
                }
            }
            Alignment::Divergent => {
                let Some(fault) = tree.fault() else {
                    return Err(format!("{name}: divergence case must fault"));
                };
                let ok = match name {
                    "varint_terminal_overflow" => {
                        matches!(
                            fault.kind(),
                            FaultKind::Read {
                                stage: Stage::Value { .. },
                                cause: ReadFault::OutOfClass
                            }
                        )
                    }
                    "tag_terminal_0x10" | "tag_terminal_0x1F" => {
                        matches!(
                            fault.kind(),
                            FaultKind::Read { stage: Stage::Tag, cause: ReadFault::OutOfClass }
                        )
                    }
                    other => panic!("unregistered divergence case {other}"),
                };
                if !ok {
                    return Err(format!("{name}: wrong fault class {:?}", fault.kind()));
                }
            }
            Alignment::Reject => {
                if tree.fault().is_none() {
                    return Err(format!("{name}: reference rejects, inspector completed"));
                }
            }
        }
        Ok(())
    }

    #[test]
    fn grouped_dialect_aligns_with_the_reference() {
        for case in decode_raw_cases() {
            if let Err(finding) = judge(&case) {
                panic!("{finding}");
            }
        }
    }

    /// The judge's own discrimination: corrupt one real parsed
    /// case, and the exact path the loop runs must reject it.
    #[test]
    fn the_judge_rejects_a_corrupted_case() {
        let cases = decode_raw_cases();
        let real = cases.iter().find(|c| c.name == "varint_u64_max").expect("pinned case");
        assert!(judge(real).is_ok(), "the uncorrupted case must pass its own judge");

        let mut wrong_output = real.clone();
        wrong_output.output = Some("1: 151".into());
        assert!(judge(&wrong_output).is_err(), "a corrupted frozen output slipped the judge");

        let mut wrong_expect = real.clone();
        wrong_expect.expect = "reject".into();
        assert!(judge(&wrong_expect).is_err(), "a flipped expectation slipped the judge");
    }

    /// The acceptance-complete differential: for every corpus item
    /// and every standard, the buffered parse's verdict equals the
    /// stream validator's fed whole (zero advice speculates every
    /// payload — exactly the validator's never-descend stance);
    /// where the refusal is the canonical family's own, the fault
    /// coordinates agree exactly.
    #[cfg(feature = "scan-grouped")]
    #[test]
    fn parse_standard_verdicts_differential_against_the_scan_validator() {
        use protobuf_edit::Standard;
        use protobuf_edit::scan::grouped::Validator;
        let mut canonical_only = 0_usize;
        for case in decode_raw_cases() {
            let bytes = unhex(&case.hex);
            let name = case.name.as_str();
            let scan = |standard: Standard| {
                let mut v = Validator::new(standard, DepthLimit::REFERENCE);
                v.feed(&bytes).and_then(|()| v.finish())
            };
            let parse = |standard: Standard| {
                Tree::parse_standard(
                    Admitted::new(&bytes).unwrap(),
                    standard,
                    DepthLimit::REFERENCE,
                    &mut NoAdvice,
                )
            };
            let tolerant = parse(Standard::Tolerant);
            assert_eq!(
                scan(Standard::Tolerant).is_ok(),
                tolerant.is_complete(),
                "{name}: tolerant faces disagree"
            );
            let canonical = parse(Standard::CanonicalMinimal);
            let scan_canonical = scan(Standard::CanonicalMinimal);
            assert_eq!(
                scan_canonical.is_ok(),
                canonical.is_complete(),
                "{name}: canonical faces disagree"
            );
            if tolerant.is_complete()
                && let Some(fault) = canonical.fault()
            {
                canonical_only += 1;
                let scan_fault = scan_canonical.expect_err(name);
                assert_eq!(
                    u64::from(fault.at()),
                    scan_fault.at(),
                    "{name}: minimality coordinates disagree"
                );
                assert!(
                    matches!(
                        fault.kind(),
                        FaultKind::NonMinimalTag
                            | FaultKind::NonMinimalLen { .. }
                            | FaultKind::NonMinimalValue { .. }
                    ),
                    "{name}: a canonical-only refusal must be the minimality family, got {:?}",
                    fault.kind()
                );
            }
        }
        assert!(canonical_only >= 3, "the corpus exercised only {canonical_only} padded cases");
    }
}

// ─── p3 dialect ───

#[cfg(feature = "inspect-groupless")]
mod groupless_dialect {
    use protobuf_edit::inspect::Stage;
    use protobuf_edit::inspect::groupless::{FaultKind, Tree};
    use protobuf_edit::varint::slice::ReadFault;

    use super::render::groupless::render;
    use super::*;

    /// One case through the production alignment path (the grouped
    /// module documents the shape), with this dialect's capability
    /// arm: group bytes must refuse as `GroupCode`.
    fn judge(case: &Case) -> Result<(), String> {
        let bytes = unhex(&case.hex);
        let tree =
            Tree::parse(Admitted::new(&bytes).unwrap(), DepthLimit::REFERENCE, &mut NoAdvice);
        let name = case.name.as_str();
        if GROUP_CASES.contains(&name) {
            let Some(fault) = tree.fault() else {
                return Err(format!("{name}: group bytes must fault in p3"));
            };
            if !matches!(fault.kind(), FaultKind::GroupCode { .. }) {
                return Err(format!(
                    "{name}: expected the capability refusal, got {:?}",
                    fault.kind()
                ));
            }
            return Ok(());
        }
        match alignment(case) {
            Alignment::Accept => {
                if !tree.is_complete() {
                    return Err(format!(
                        "{name}: reference accepts, inspector faulted: {:?}",
                        tree.fault()
                    ));
                }
                if !case.rc_only {
                    let expected = case.output.as_deref().unwrap();
                    if render(&tree) != expected {
                        return Err(format!("{name}: rendered mismatch"));
                    }
                }
            }
            Alignment::Divergent => {
                let Some(fault) = tree.fault() else {
                    return Err(format!("{name}: divergence case must fault"));
                };
                let ok = match name {
                    "varint_terminal_overflow" => {
                        matches!(
                            fault.kind(),
                            FaultKind::Read {
                                stage: Stage::Value { .. },
                                cause: ReadFault::OutOfClass
                            }
                        )
                    }
                    "tag_terminal_0x10" | "tag_terminal_0x1F" => {
                        matches!(
                            fault.kind(),
                            FaultKind::Read { stage: Stage::Tag, cause: ReadFault::OutOfClass }
                        )
                    }
                    other => panic!("unregistered divergence case {other}"),
                };
                if !ok {
                    return Err(format!("{name}: wrong fault class {:?}", fault.kind()));
                }
            }
            Alignment::Reject => {
                if tree.fault().is_none() {
                    return Err(format!("{name}: reference rejects, inspector completed"));
                }
            }
        }
        Ok(())
    }

    #[test]
    fn groupless_dialect_aligns_with_the_reference_modulo_groups() {
        for case in decode_raw_cases() {
            if let Err(finding) = judge(&case) {
                panic!("{finding}");
            }
        }
    }

    /// The judge's own discrimination, groupless: a corrupted real
    /// case must be rejected by the exact path the loop runs — the
    /// capability arm included.
    #[test]
    fn the_judge_rejects_a_corrupted_case() {
        let cases = decode_raw_cases();
        let real = cases.iter().find(|c| c.name == "varint_u64_max").expect("pinned case");
        assert!(judge(real).is_ok(), "the uncorrupted case must pass its own judge");

        let mut wrong_output = real.clone();
        wrong_output.output = Some("1: 151".into());
        assert!(judge(&wrong_output).is_err(), "a corrupted frozen output slipped the judge");

        let mut wrong_expect = real.clone();
        wrong_expect.expect = "reject".into();
        assert!(judge(&wrong_expect).is_err(), "a flipped expectation slipped the judge");
    }

    /// The groupless acceptance-complete differential
    /// (the grouped module documents the shape).
    #[cfg(feature = "scan-groupless")]
    #[test]
    fn parse_standard_verdicts_differential_against_the_scan_validator() {
        use protobuf_edit::Standard;
        use protobuf_edit::scan::groupless::Validator;
        let mut canonical_only = 0_usize;
        for case in decode_raw_cases() {
            let bytes = unhex(&case.hex);
            let name = case.name.as_str();
            let scan = |standard: Standard| {
                let mut v = Validator::new(standard);
                v.feed(&bytes).and_then(|()| v.finish())
            };
            let parse = |standard: Standard| {
                Tree::parse_standard(
                    Admitted::new(&bytes).unwrap(),
                    standard,
                    DepthLimit::REFERENCE,
                    &mut NoAdvice,
                )
            };
            let tolerant = parse(Standard::Tolerant);
            assert_eq!(
                scan(Standard::Tolerant).is_ok(),
                tolerant.is_complete(),
                "{name}: tolerant faces disagree"
            );
            let canonical = parse(Standard::CanonicalMinimal);
            let scan_canonical = scan(Standard::CanonicalMinimal);
            assert_eq!(
                scan_canonical.is_ok(),
                canonical.is_complete(),
                "{name}: canonical faces disagree"
            );
            if tolerant.is_complete()
                && let Some(fault) = canonical.fault()
            {
                canonical_only += 1;
                let scan_fault = scan_canonical.expect_err(name);
                assert_eq!(
                    u64::from(fault.at()),
                    scan_fault.at(),
                    "{name}: minimality coordinates disagree"
                );
                assert!(
                    matches!(
                        fault.kind(),
                        FaultKind::NonMinimalTag
                            | FaultKind::NonMinimalLen { .. }
                            | FaultKind::NonMinimalValue { .. }
                    ),
                    "{name}: a canonical-only refusal must be the minimality family, got {:?}",
                    fault.kind()
                );
            }
        }
        assert!(canonical_only >= 3, "the corpus exercised only {canonical_only} padded cases");
    }
}

// ─── session dialects: round-trip alignment ───
//
// The editors accept canonical-minimal wire only (an on-record
// divergence): against every oracle-accepted case a session has
// exactly two lawful reactions — open (and then save pointer-clean,
// bit-identical) or a minimality/capability refusal. A wire fault
// on an oracle-accepted input is an implementation error.

#[cfg(feature = "session-grouped")]
mod session_grouped_dialect {
    use protobuf_edit::session::DocBytes;
    use protobuf_edit::session::grouped::{OpenFault, Session};

    use super::*;

    #[test]
    fn oracle_accepted_documents_open_or_refuse_minimality() {
        for case in decode_raw_cases() {
            if case.expect != "accept" {
                continue;
            }
            let bytes = unhex(&case.hex);
            if case.spec_class.is_some() {
                // The wrap forgeries the reference accepts silently:
                // refused here through the kernel's class judgment —
                // the same on-record divergence the inspectors pin.
                assert!(
                    matches!(Session::open_copy(&bytes), Err(OpenFault::Wire(_))),
                    "{}: wrap forgery must be refused by class",
                    case.name
                );
                continue;
            }
            match Session::open_copy(&bytes) {
                Ok(s) => {
                    let saved = s.save().expect("clean session saves");
                    assert!(
                        DocBytes::ptr_eq(s.doc(), &saved),
                        "{}: clean save must be the same allocation",
                        case.name
                    );
                    assert_eq!(saved.as_slice(), &bytes[..], "{}: bit-true", case.name);
                }
                Err(OpenFault::Refused(_)) => {
                    // Canonical-minimal policy; the oracle's padded
                    // and wrapped cases land here by design.
                }
                Err(other) => {
                    panic!("{}: oracle accepts, session faulted: {other:?}", case.name)
                }
            }
        }
    }
}

// ─── scan dialects: verdict alignment ───
//
// The scan validator is wire-level: it skips every LEN payload
// — exactly decode_raw's own stance (the corpus notes pin that its
// rejects are driven by top-level bytes alone, LEN interiors only
// degrade to blob rendering). The judgment faces are therefore
// congruent: accept ⇒ no fault, reject ⇒ fault, and the wrap
// divergences fault by class. Each case runs whole and byte-at-a-
// time, pinning chunking invariance against the corpus too.

#[cfg(feature = "scan-grouped")]
mod scan_grouped_dialect {
    use protobuf_edit::scan::grouped::{Fault, FaultKind, Validator};
    use protobuf_edit::scan::{ReadFault, Stage, Standard};

    use super::*;

    #[track_caller]
    fn verdict(bytes: &[u8], step: usize) -> Result<(), Fault> {
        let mut validator = Validator::new(Standard::Tolerant, DepthLimit::REFERENCE);
        for chunk in bytes.chunks(step.max(1)) {
            validator.feed(chunk)?;
        }
        validator.finish()
    }

    #[test]
    fn full_verdicts_align_with_the_reference() {
        for case in decode_raw_cases() {
            let bytes = unhex(&case.hex);
            let name = case.name.as_str();
            let whole = verdict(&bytes, bytes.len());
            // Chunking homomorphism: every step size, not a sample
            // — the verdict may not move under any segmentation.
            for step in 1..=bytes.len().max(1) {
                assert_eq!(whole, verdict(&bytes, step), "{name}: step {step} moved the verdict");
            }
            match alignment(&case) {
                Alignment::Accept => {
                    assert_eq!(whole, Ok(()), "{name}: reference accepts, validator faulted");
                }
                Alignment::Divergent => {
                    let fault = whole.expect_err(name);
                    assert!(
                        matches!(
                            fault.kind(),
                            FaultKind::Read {
                                stage: Stage::Tag | Stage::Value { .. },
                                cause: ReadFault::OutOfClass
                            }
                        ),
                        "{name}: expected a class refusal, got {:?}",
                        fault.kind()
                    );
                }
                Alignment::Reject => {
                    assert!(whole.is_err(), "{name}: reference rejects, validator completed");
                }
            }
        }
    }
}

#[cfg(feature = "scan-groupless")]
mod scan_groupless_dialect {
    use protobuf_edit::scan::groupless::{Fault, FaultKind, Validator};
    use protobuf_edit::scan::{ReadFault, Stage, Standard};

    use super::*;

    #[track_caller]
    fn verdict(bytes: &[u8], step: usize) -> Result<(), Fault> {
        let mut validator = Validator::new(Standard::Tolerant);
        for chunk in bytes.chunks(step.max(1)) {
            validator.feed(chunk)?;
        }
        validator.finish()
    }

    #[test]
    fn p3_verdicts_align_with_the_reference_modulo_groups() {
        for case in decode_raw_cases() {
            let bytes = unhex(&case.hex);
            let name = case.name.as_str();
            let whole = verdict(&bytes, bytes.len());
            // Chunking homomorphism: every step size, not a sample
            // — the verdict may not move under any segmentation.
            for step in 1..=bytes.len().max(1) {
                assert_eq!(whole, verdict(&bytes, step), "{name}: step {step} moved the verdict");
            }
            if GROUP_CASES.contains(&name) {
                let fault = whole.expect_err(name);
                assert!(
                    matches!(fault.kind(), FaultKind::GroupCode { .. }),
                    "{name}: expected the capability refusal, got {:?}",
                    fault.kind()
                );
                continue;
            }
            match alignment(&case) {
                Alignment::Accept => {
                    assert_eq!(whole, Ok(()), "{name}: reference accepts, validator faulted");
                }
                Alignment::Divergent => {
                    let fault = whole.expect_err(name);
                    assert!(
                        matches!(
                            fault.kind(),
                            FaultKind::Read {
                                stage: Stage::Tag | Stage::Value { .. },
                                cause: ReadFault::OutOfClass
                            }
                        ),
                        "{name}: expected a class refusal, got {:?}",
                        fault.kind()
                    );
                }
                Alignment::Reject => {
                    assert!(whole.is_err(), "{name}: reference rejects, validator completed");
                }
            }
        }
    }
}

// ─── traverse dialects: verdict alignment ───
//
// The traversal cursor never descends into LEN payloads — again
// decode_raw's own stance — so its accept/reject face is congruent
// with the reference verdicts: accept ⇒ the walk completes without
// a fault, reject ⇒ a fault surfaces, wrap divergences fault by
// class (the cursor is width-tolerant, so padded corpus cases are
// accepted as-is).

#[cfg(feature = "traverse-grouped")]
mod traverse_grouped_dialect {
    #[cfg(feature = "scan-grouped")]
    use protobuf_edit::traverse::grouped::CanonicalCursor;
    use protobuf_edit::traverse::grouped::{Cursor, Fault, FaultKind};
    use protobuf_edit::traverse::{GroupDepth, Stage};
    use protobuf_edit::varint::slice::ReadFault;

    use super::*;

    #[track_caller]
    fn verdict(bytes: &[u8]) -> Result<(), Fault> {
        let cursor = Cursor::over(bytes, GroupDepth::REFERENCE).expect("corpus inputs are small");
        for item in cursor {
            item?;
        }
        Ok(())
    }

    // Consumed by the scan differential alone: the canonical twin
    // has no standalone alignment loop of its own.
    #[cfg(feature = "scan-grouped")]
    #[track_caller]
    fn canonical_verdict(bytes: &[u8]) -> Result<(), Fault> {
        let cursor =
            CanonicalCursor::over(bytes, GroupDepth::REFERENCE).expect("corpus inputs are small");
        for item in cursor {
            item?;
        }
        Ok(())
    }

    /// The acceptance-complete differential: for every corpus item
    /// and every standard, the buffered cursor's verdict equals the
    /// stream validator's fed whole; where the refusal is the
    /// canonical family's own (the tolerant face accepts the same
    /// bytes), the fault coordinates agree exactly — both machines
    /// judge minimality at the construct's first byte.
    #[cfg(feature = "scan-grouped")]
    #[test]
    fn cursor_verdicts_differential_against_the_scan_validator() {
        use protobuf_edit::scan::Standard;
        use protobuf_edit::scan::grouped::Validator;
        let mut canonical_only = 0_usize;
        for case in decode_raw_cases() {
            let bytes = unhex(&case.hex);
            let name = case.name.as_str();
            let scan = |standard: Standard| {
                let mut v = Validator::new(standard, DepthLimit::REFERENCE);
                v.feed(&bytes).and_then(|()| v.finish())
            };
            let tolerant = verdict(&bytes);
            assert_eq!(
                scan(Standard::Tolerant).is_ok(),
                tolerant.is_ok(),
                "{name}: tolerant faces disagree"
            );
            let canonical = canonical_verdict(&bytes);
            let scan_canonical = scan(Standard::CanonicalMinimal);
            assert_eq!(
                scan_canonical.is_ok(),
                canonical.is_ok(),
                "{name}: canonical faces disagree"
            );
            if tolerant.is_ok()
                && let Err(fault) = canonical
            {
                canonical_only += 1;
                let scan_fault = scan_canonical.expect_err(name);
                assert_eq!(
                    u64::from(fault.at()),
                    scan_fault.at(),
                    "{name}: minimality coordinates disagree"
                );
                assert!(
                    matches!(
                        fault.kind(),
                        FaultKind::NonMinimalTag
                            | FaultKind::NonMinimalLen { .. }
                            | FaultKind::NonMinimalValue { .. }
                    ),
                    "{name}: a canonical-only refusal must be the minimality family, got {:?}",
                    fault.kind()
                );
            }
        }
        assert!(canonical_only >= 3, "the corpus exercised only {canonical_only} padded cases");
    }

    #[test]
    fn full_verdicts_align_with_the_reference() {
        for case in decode_raw_cases() {
            let bytes = unhex(&case.hex);
            let name = case.name.as_str();
            let out = verdict(&bytes);
            match alignment(&case) {
                Alignment::Accept => {
                    assert_eq!(out, Ok(()), "{name}: reference accepts, cursor faulted");
                }
                Alignment::Divergent => {
                    let fault = out.expect_err(name);
                    assert!(
                        matches!(
                            fault.kind(),
                            FaultKind::Read {
                                stage: Stage::Tag | Stage::Value { .. },
                                cause: ReadFault::OutOfClass
                            }
                        ),
                        "{name}: expected a class refusal, got {:?}",
                        fault.kind()
                    );
                }
                Alignment::Reject => {
                    assert!(out.is_err(), "{name}: reference rejects, cursor completed");
                }
            }
        }
    }
}

#[cfg(feature = "traverse-groupless")]
mod traverse_groupless_dialect {
    use protobuf_edit::traverse::Stage;
    #[cfg(feature = "scan-groupless")]
    use protobuf_edit::traverse::groupless::CanonicalCursor;
    use protobuf_edit::traverse::groupless::{Cursor, Fault, FaultKind};
    use protobuf_edit::varint::slice::ReadFault;

    use super::*;

    #[track_caller]
    fn verdict(bytes: &[u8]) -> Result<(), Fault> {
        let cursor = Cursor::over(bytes).expect("corpus inputs are small");
        for item in cursor {
            item?;
        }
        Ok(())
    }

    // Consumed by the scan differential alone: the canonical twin
    // has no standalone alignment loop of its own.
    #[cfg(feature = "scan-groupless")]
    #[track_caller]
    fn canonical_verdict(bytes: &[u8]) -> Result<(), Fault> {
        let cursor = CanonicalCursor::over(bytes).expect("corpus inputs are small");
        for item in cursor {
            item?;
        }
        Ok(())
    }

    /// The acceptance-complete differential, groupless: verdict
    /// congruence per standard, coordinate equality on the
    /// canonical family's own refusals.
    #[cfg(feature = "scan-groupless")]
    #[test]
    fn cursor_verdicts_differential_against_the_scan_validator() {
        use protobuf_edit::scan::Standard;
        use protobuf_edit::scan::groupless::Validator;
        let mut canonical_only = 0_usize;
        for case in decode_raw_cases() {
            let bytes = unhex(&case.hex);
            let name = case.name.as_str();
            let scan = |standard: Standard| {
                let mut v = Validator::new(standard);
                v.feed(&bytes).and_then(|()| v.finish())
            };
            let tolerant = verdict(&bytes);
            assert_eq!(
                scan(Standard::Tolerant).is_ok(),
                tolerant.is_ok(),
                "{name}: tolerant faces disagree"
            );
            let canonical = canonical_verdict(&bytes);
            let scan_canonical = scan(Standard::CanonicalMinimal);
            assert_eq!(
                scan_canonical.is_ok(),
                canonical.is_ok(),
                "{name}: canonical faces disagree"
            );
            if tolerant.is_ok()
                && let Err(fault) = canonical
            {
                canonical_only += 1;
                let scan_fault = scan_canonical.expect_err(name);
                assert_eq!(
                    u64::from(fault.at()),
                    scan_fault.at(),
                    "{name}: minimality coordinates disagree"
                );
                assert!(
                    matches!(
                        fault.kind(),
                        FaultKind::NonMinimalTag
                            | FaultKind::NonMinimalLen { .. }
                            | FaultKind::NonMinimalValue { .. }
                    ),
                    "{name}: a canonical-only refusal must be the minimality family, got {:?}",
                    fault.kind()
                );
            }
        }
        assert!(canonical_only >= 3, "the corpus exercised only {canonical_only} padded cases");
    }

    #[test]
    fn p3_verdicts_align_with_the_reference_modulo_groups() {
        for case in decode_raw_cases() {
            let bytes = unhex(&case.hex);
            let name = case.name.as_str();
            let out = verdict(&bytes);
            if GROUP_CASES.contains(&name) {
                let fault = out.expect_err(name);
                assert!(
                    matches!(fault.kind(), FaultKind::GroupCode { .. }),
                    "{name}: expected the capability refusal, got {:?}",
                    fault.kind()
                );
                continue;
            }
            match alignment(&case) {
                Alignment::Accept => {
                    assert_eq!(out, Ok(()), "{name}: reference accepts, cursor faulted");
                }
                Alignment::Divergent => {
                    let fault = out.expect_err(name);
                    assert!(
                        matches!(
                            fault.kind(),
                            FaultKind::Read {
                                stage: Stage::Tag | Stage::Value { .. },
                                cause: ReadFault::OutOfClass
                            }
                        ),
                        "{name}: expected a class refusal, got {:?}",
                        fault.kind()
                    );
                }
                Alignment::Reject => {
                    assert!(out.is_err(), "{name}: reference rejects, cursor completed");
                }
            }
        }
    }
}

// ─── rewrite dialects: identity round-trip alignment ───
//
// A ruleless job commits only the root (LEN payloads stay opaque
// unless a rule routes into them — decode_raw's stance again), so
// against every oracle case it has exactly two lawful outcomes:
// accept ⇒ a bit-true identity copy, reject ⇒ a fault before any
// byte is emitted. Wrap divergences fault by class through the
// wrapped traversal vocabulary.

#[cfg(feature = "rewrite-grouped")]
mod rewrite_grouped_dialect {
    use protobuf_edit::rewrite::RuleSet;
    use protobuf_edit::rewrite::grouped::{FaultKind, rewrite};

    use super::*;

    /// The acceptance-complete differential: ruleless jobs under
    /// each standard against the scan validator fed whole —
    /// verdict congruence, byte-true identity on accepts, and
    /// coordinate equality on the canonical family's own refusals.
    #[cfg(feature = "scan-grouped")]
    #[test]
    fn standard_jobs_differential_against_the_scan_validator() {
        use protobuf_edit::Standard;
        use protobuf_edit::rewrite::grouped::{WireBreach, rewrite_standard};
        use protobuf_edit::scan::grouped::Validator;
        let rules = RuleSet::over(&[]).expect("the empty set admits");
        let mut canonical_only = 0_usize;
        for case in decode_raw_cases() {
            let bytes = unhex(&case.hex);
            let name = case.name.as_str();
            let scan = |standard: Standard| {
                let mut v = Validator::new(standard, DepthLimit::REFERENCE);
                v.feed(&bytes).and_then(|()| v.finish())
            };
            let tolerant =
                rewrite_standard(&bytes, &rules, Standard::Tolerant, DepthLimit::REFERENCE);
            assert_eq!(
                scan(Standard::Tolerant).is_ok(),
                tolerant.is_ok(),
                "{name}: tolerant faces disagree"
            );
            let canonical =
                rewrite_standard(&bytes, &rules, Standard::CanonicalMinimal, DepthLimit::REFERENCE);
            let scan_canonical = scan(Standard::CanonicalMinimal);
            assert_eq!(
                scan_canonical.is_ok(),
                canonical.is_ok(),
                "{name}: canonical faces disagree"
            );
            match (tolerant, canonical) {
                (Ok(_), Ok((copy, _))) => {
                    assert_eq!(copy, bytes, "{name}: canonical identity must be bit-true");
                }
                (Ok(_), Err(fault)) => {
                    canonical_only += 1;
                    let scan_fault = scan_canonical.expect_err(name);
                    assert_eq!(
                        u64::from(fault.at()),
                        scan_fault.at(),
                        "{name}: minimality coordinates disagree"
                    );
                    assert!(
                        matches!(fault.kind(), FaultKind::Wire(WireBreach::NonMinimal)),
                        "{name}: a canonical-only refusal must be the width breach, got {:?}",
                        fault.kind()
                    );
                }
                (Err(_), _) => {}
            }
        }
        assert!(canonical_only >= 3, "the corpus exercised only {canonical_only} padded cases");
    }

    #[test]
    fn ruleless_jobs_round_trip_the_reference_verdicts() {
        let rules = RuleSet::over(&[]).expect("the empty set admits");
        for case in decode_raw_cases() {
            let bytes = unhex(&case.hex);
            let name = case.name.as_str();
            let out = rewrite(&bytes, &rules, DepthLimit::REFERENCE);
            match alignment(&case) {
                Alignment::Accept => {
                    let (copy, stats) = out.expect(name);
                    assert_eq!(copy, bytes, "{name}: identity job must be bit-true");
                    assert_eq!(stats, protobuf_edit::rewrite::Stats::default());
                }
                Alignment::Divergent => {
                    let fault = out.expect_err(name);
                    assert!(
                        matches!(
                            fault.kind(),
                            FaultKind::Wire(protobuf_edit::rewrite::grouped::WireBreach::Varint,)
                        ),
                        "{name}: expected a class refusal, got {:?}",
                        fault.kind()
                    );
                }
                Alignment::Reject => {
                    assert!(out.is_err(), "{name}: reference rejects, rewriter copied");
                }
            }
        }
    }
}

#[cfg(feature = "rewrite-groupless")]
mod rewrite_groupless_dialect {
    use protobuf_edit::rewrite::RuleSet;
    use protobuf_edit::rewrite::groupless::{FaultKind, rewrite};

    use super::*;

    /// The groupless acceptance-complete differential (the grouped
    /// module documents the shape).
    #[cfg(feature = "scan-groupless")]
    #[test]
    fn standard_jobs_differential_against_the_scan_validator() {
        use protobuf_edit::Standard;
        use protobuf_edit::rewrite::groupless::{WireBreach, rewrite_standard};
        use protobuf_edit::scan::groupless::Validator;
        let rules = RuleSet::over(&[]).expect("the empty set admits");
        let mut canonical_only = 0_usize;
        for case in decode_raw_cases() {
            let bytes = unhex(&case.hex);
            let name = case.name.as_str();
            let scan = |standard: Standard| {
                let mut v = Validator::new(standard);
                v.feed(&bytes).and_then(|()| v.finish())
            };
            let tolerant =
                rewrite_standard(&bytes, &rules, Standard::Tolerant, DepthLimit::REFERENCE);
            assert_eq!(
                scan(Standard::Tolerant).is_ok(),
                tolerant.is_ok(),
                "{name}: tolerant faces disagree"
            );
            let canonical =
                rewrite_standard(&bytes, &rules, Standard::CanonicalMinimal, DepthLimit::REFERENCE);
            let scan_canonical = scan(Standard::CanonicalMinimal);
            assert_eq!(
                scan_canonical.is_ok(),
                canonical.is_ok(),
                "{name}: canonical faces disagree"
            );
            match (tolerant, canonical) {
                (Ok(_), Ok((copy, _))) => {
                    assert_eq!(copy, bytes, "{name}: canonical identity must be bit-true");
                }
                (Ok(_), Err(fault)) => {
                    canonical_only += 1;
                    let scan_fault = scan_canonical.expect_err(name);
                    assert_eq!(
                        u64::from(fault.at()),
                        scan_fault.at(),
                        "{name}: minimality coordinates disagree"
                    );
                    assert!(
                        matches!(fault.kind(), FaultKind::Wire(WireBreach::NonMinimal)),
                        "{name}: a canonical-only refusal must be the width breach, got {:?}",
                        fault.kind()
                    );
                }
                (Err(_), _) => {}
            }
        }
        assert!(canonical_only >= 3, "the corpus exercised only {canonical_only} padded cases");
    }

    #[test]
    fn ruleless_jobs_round_trip_modulo_groups() {
        let rules = RuleSet::over(&[]).expect("the empty set admits");
        for case in decode_raw_cases() {
            let bytes = unhex(&case.hex);
            let name = case.name.as_str();
            let out = rewrite(&bytes, &rules, DepthLimit::REFERENCE);
            if GROUP_CASES.contains(&name) {
                let fault = out.expect_err(name);
                assert!(
                    matches!(
                        fault.kind(),
                        FaultKind::Wire(protobuf_edit::rewrite::groupless::WireBreach::GroupCode)
                    ),
                    "{name}: expected the capability refusal, got {:?}",
                    fault.kind()
                );
                continue;
            }
            match alignment(&case) {
                Alignment::Accept => {
                    let (copy, _) = out.expect(name);
                    assert_eq!(copy, bytes, "{name}: identity job must be bit-true");
                }
                Alignment::Divergent => {
                    assert!(out.is_err(), "{name}: wrap forgery must fault");
                }
                Alignment::Reject => {
                    assert!(out.is_err(), "{name}: reference rejects, rewriter copied");
                }
            }
        }
    }
}

// ─── transcode dialects: identity round-trip alignment ───
//
// The all-default rule is the bit-identical transcoder and the
// machine walks the same wire law as the scan validator: accept
// ⇒ the output equals the input byte for byte, reject ⇒ a wire
// fault before finish succeeds, wrap divergences fault by class.
// Each case runs whole and byte-at-a-time.

#[cfg(feature = "transcode-grouped")]
mod transcode_grouped_dialect {
    use protobuf_edit::transcode::Standard;
    use protobuf_edit::transcode::grouped::{Fault, Transcoder};

    use super::*;

    #[track_caller]
    fn job(bytes: &[u8], step: usize) -> Result<Vec<u8>, Fault> {
        let mut out = Vec::new();
        let mut sink = |b: &[u8]| out.extend_from_slice(b);
        let mut t = Transcoder::new(Standard::Tolerant, DepthLimit::REFERENCE);
        for chunk in bytes.chunks(step.max(1)) {
            t.feed(chunk, &mut (), &mut sink)?;
        }
        t.finish(&mut (), &mut sink)?;
        Ok(out)
    }

    #[test]
    fn identity_jobs_round_trip_the_reference_verdicts() {
        for case in decode_raw_cases() {
            let bytes = unhex(&case.hex);
            let name = case.name.as_str();
            let whole = job(&bytes, bytes.len());
            assert_eq!(whole, job(&bytes, 1), "{name}: chunking moved the outcome");
            match alignment(&case) {
                Alignment::Accept => {
                    assert_eq!(whole.expect(name), bytes, "{name}: identity must be bit-true");
                }
                Alignment::Divergent | Alignment::Reject => {
                    assert!(whole.is_err(), "{name}: reference rejects, transcoder passed");
                }
            }
        }
    }
}

#[cfg(feature = "transcode-groupless")]
mod transcode_groupless_dialect {
    use protobuf_edit::transcode::Standard;
    use protobuf_edit::transcode::groupless::{Fault, Transcoder};

    use super::*;

    #[track_caller]
    fn job(bytes: &[u8], step: usize) -> Result<Vec<u8>, Fault> {
        let mut out = Vec::new();
        let mut sink = |b: &[u8]| out.extend_from_slice(b);
        let mut t = Transcoder::new(Standard::Tolerant, DepthLimit::REFERENCE);
        for chunk in bytes.chunks(step.max(1)) {
            t.feed(chunk, &mut (), &mut sink)?;
        }
        t.finish(&mut (), &mut sink)?;
        Ok(out)
    }

    #[test]
    fn identity_jobs_round_trip_modulo_groups() {
        for case in decode_raw_cases() {
            let bytes = unhex(&case.hex);
            let name = case.name.as_str();
            let whole = job(&bytes, bytes.len());
            assert_eq!(whole, job(&bytes, 1), "{name}: chunking moved the outcome");
            if GROUP_CASES.contains(&name) {
                let fault = whole.expect_err(name);
                assert!(
                    matches!(
                        fault,
                        Fault::Wire {
                            breach: protobuf_edit::transcode::groupless::WireBreach::GroupCode,
                            ..
                        }
                    ),
                    "{name}: expected the capability refusal, got {fault:?}"
                );
                continue;
            }
            match alignment(&case) {
                Alignment::Accept => {
                    assert_eq!(whole.expect(name), bytes, "{name}: identity must be bit-true");
                }
                Alignment::Divergent | Alignment::Reject => {
                    assert!(whole.is_err(), "{name}: reference rejects, transcoder passed");
                }
            }
        }
    }
}

// ─── construct dialects: corpus reconstruction ───
//
// The constructor has no input; its oracle face is semantic
// reconstruction — rebuild a corpus case's meaning through the
// builder and the bytes must equal the frozen hex exactly (the
// corpus pins minimal emission, which is the authored duty).

#[cfg(feature = "construct-grouped")]
mod construct_grouped_dialect {
    use protobuf_edit::construct::grouped::Builder;
    use protobuf_edit::wire::FieldNumber;

    use super::*;

    const fn f(n: u32) -> FieldNumber {
        match FieldNumber::new(n) {
            Some(field) => field,
            None => panic!("test field in range"),
        }
    }

    #[test]
    fn corpus_cases_reconstruct_bit_true() {
        let cases = decode_raw_cases();
        let hex = |name: &str| {
            unhex(&cases.iter().find(|c| c.name == name).unwrap_or_else(|| panic!("{name}")).hex)
        };

        // varint_u64_max: field 1 = u64::MAX.
        let mut b = Builder::new();
        b.push_varint(f(1), u64::MAX);
        let out = b.finish().unwrap();
        assert_eq!(out, hex("varint_u64_max"));

        // group_match: a matched group pair (field 1 group holding
        // field 1 varint 150 — corpus hex 0B 089601 0C).
        let mut b = Builder::new();
        b.group(f(1), |g| g.push_varint(f(1), 150));
        let out = b.finish().unwrap();
        assert_eq!(out, hex("group_match"));

        // cascade_after: 3 { 1: 300 2: "a" }.
        let mut b = Builder::new();
        b.message(f(3), |m| {
            m.push_varint(f(1), 300);
            m.push_string(f(2), "a");
        });
        let out = b.finish().unwrap();
        assert_eq!(out, hex("cascade_after"));

        // empty_message: no fields at all.
        let out = Builder::new().finish().unwrap();
        assert_eq!(out, hex("empty_message"));
    }
}

#[cfg(feature = "construct-groupless")]
mod construct_groupless_dialect {
    use protobuf_edit::construct::groupless::Builder;
    use protobuf_edit::wire::FieldNumber;

    use super::*;

    const fn f(n: u32) -> FieldNumber {
        match FieldNumber::new(n) {
            Some(field) => field,
            None => panic!("test field in range"),
        }
    }

    #[test]
    fn groupless_corpus_cases_reconstruct_bit_true() {
        let cases = decode_raw_cases();
        let hex = |name: &str| {
            unhex(&cases.iter().find(|c| c.name == name).unwrap_or_else(|| panic!("{name}")).hex)
        };

        let mut b = Builder::new();
        b.push_varint(f(1), u64::MAX);
        let out = b.finish().unwrap();
        assert_eq!(out, hex("varint_u64_max"));

        let mut b = Builder::new();
        b.message(f(3), |m| {
            m.push_varint(f(1), 300);
            m.push_string(f(2), "a");
        });
        let out = b.finish().unwrap();
        assert_eq!(out, hex("cascade_after"));
    }
}

#[cfg(feature = "session-groupless")]
mod session_groupless_dialect {
    use protobuf_edit::session::DocBytes;
    use protobuf_edit::session::groupless::{OpenFault, Refusal, Session};

    use super::*;

    #[test]
    fn oracle_accepted_documents_open_or_refuse_capability() {
        for case in decode_raw_cases() {
            if case.expect != "accept" {
                continue;
            }
            let bytes = unhex(&case.hex);
            if case.spec_class.is_some() {
                assert!(
                    matches!(Session::open_copy(&bytes), Err(OpenFault::Wire(_))),
                    "{}: wrap forgery must be refused by class",
                    case.name
                );
                continue;
            }
            let grouped = GROUP_CASES.contains(&case.name.as_str());
            match Session::open_copy(&bytes) {
                Ok(s) => {
                    assert!(!grouped, "{}: group bytes must refuse in p3", case.name);
                    let saved = s.save().expect("clean session saves");
                    assert!(DocBytes::ptr_eq(s.doc(), &saved), "{}: pointer-clean", case.name);
                    assert_eq!(saved.as_slice(), &bytes[..], "{}: bit-true", case.name);
                }
                Err(OpenFault::Refused(refusal)) => {
                    if grouped {
                        // Judgment order: the minimality gate sits
                        // before classify, so a padded group tag
                        // refuses as NonMinimal first; both are the
                        // capability-refusal family.
                        assert!(
                            matches!(
                                refusal,
                                Refusal::GroupCode { .. } | Refusal::NonMinimalTag { .. }
                            ),
                            "{}: expected a capability refusal, got {refusal:?}",
                            case.name
                        );
                    }
                }
                Err(other) => {
                    panic!("{}: oracle accepts, session faulted: {other:?}", case.name)
                }
            }
        }
    }
}
