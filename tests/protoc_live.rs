//! protoc-in-the-loop: the write-side oracle and the scalar
//! semantics judge.
//!
//! Everything here asks the protoc on PATH (the reference
//! implementation) live, instead of comparing against frozen
//! expectations: emitted bytes must decode (`--decode_raw`), and
//! schema-typed semantics (`--decode=M`/`--encode=M` over
//! `references/vectors/wire.proto`) judge the two scalar questions
//! this target carries — the sint32 reduction order and the sint
//! encodings, the ones with no other external judge — and the
//! padded-corpus value reading rides the same protoc
//! (`--decode_raw` against both dialects' renders). The rest of
//! the scalar matrix is pinned offline by boundary and round-trip
//! tests under the crate's explicitly strict domain policy: the
//! plain widths refuse out-of-domain words a permissive reference
//! read would truncate, and sint32's recorded reduction order is
//! the carved-out fold this target itself judges.
//!
//! Oracle absence is an explicit verdict, never a silent pass:
//! every test here fails by name when protoc is not on PATH (run
//! this target where the oracle exists, or filter it out — the
//! summary then says which happened), and the schema the typed
//! judges decode against is content-addressed by a tracked digest,
//! so a drifted materialization fails before it can misjudge. The
//! corpus pins in `oracle.rs` remain the offline baseline.

// The full consumer closure this suite drives; under any narrower
// feature set the target compiles empty, so per-cell `--all-targets`
// builds stay green. Individual rows carry their own tighter gates.
#![cfg(all(
    feature = "construct-grouped",
    feature = "convert-grouped",
    feature = "convert-groupless",
    feature = "inplace-grouped",
    feature = "inplace-groupless",
    feature = "inspect-grouped",
    feature = "inspect-groupless",
    feature = "rewrite-grouped",
    feature = "session-grouped",
    feature = "session-groupless",
    feature = "traverse-grouped"
))]

extern crate alloc;

use std::io::Write;
use std::process::{Command, Stdio};

use protobuf_edit::FieldNumber;

#[cfg(any(feature = "inspect-grouped", feature = "inspect-groupless"))]
#[path = "support/padded.rs"]
mod padded;
#[cfg(any(feature = "inspect-grouped", feature = "inspect-groupless"))]
#[path = "support/render.rs"]
mod render;

const VECTORS: &str = "references/vectors";

/// The materialized schema's tracked address: `wire.proto` as the
/// CI definition spells it, byte for byte — the materializer is
/// deterministic exactly while this digest holds, and the typed
/// judges below interpret against no other bytes.
const SCHEMA_SHA256: &str = "29e02e3055f0da9ed4c1a9fe9e368477a28b1ec22ca4b3baf779d362b125163c";

#[path = "support/sha256.rs"]
mod sha256;

/// The environment judgment every live test opens with: protoc on
/// PATH — its version captured and asserted into the judgment
/// record, so a green run names its judge — or a red naming the
/// absence. An unexercised oracle is a finding the summary must
/// carry, not a pass.
#[track_caller]
fn require_protoc() {
    let out = Command::new("protoc").arg("--version").stderr(Stdio::null()).output();
    let out = out.ok().filter(|out| out.status.success()).unwrap_or_else(|| {
        panic!(
            "protoc absent: the live write-side oracle cannot run — install protoc \
             or filter out --test protoc_live"
        )
    });
    let version = String::from_utf8_lossy(&out.stdout);
    let version = version.trim();
    assert!(
        version.starts_with("libprotoc "),
        "unrecognized oracle: `protoc --version` answered {version:?}"
    );
    println!("live oracle judge: {version}");
}

/// The schema judge: the local `wire.proto` must be the tracked
/// materialization (missing counts as drift — the environment is
/// incomplete either way).
#[test]
fn the_materialized_schema_matches_its_tracked_digest() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/references/vectors/wire.proto");
    let text =
        std::fs::read_to_string(path).unwrap_or_else(|e| panic!("schema not found at {path}: {e}"));
    assert_eq!(
        sha256::digest_hex(text.as_bytes()),
        SCHEMA_SHA256,
        "wire.proto at {path} drifted from the tracked materialization — the typed \
         judges would decode against different field assignments"
    );
}

#[track_caller]
fn run_protoc(args: &[&str], input: &[u8]) -> (bool, String) {
    let mut child = Command::new("protoc")
        .args(args)
        .current_dir(VECTORS)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("protoc spawns");
    child.stdin.as_mut().unwrap().write_all(input).unwrap();
    let out = child.wait_with_output().unwrap();
    (out.status.success(), String::from_utf8_lossy(&out.stdout).into_owned())
}

/// `--decode_raw` accepts the bytes (the write-side lawfulness
/// judge; no text comparison, protoc's acceptance is the verdict).
#[track_caller]
fn reference_accepts(bytes: &[u8]) -> bool {
    run_protoc(&["--decode_raw"], bytes).0
}

fn norm(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

const fn f(n: u32) -> FieldNumber {
    match FieldNumber::new(n) {
        Some(field) => field,
        None => panic!("test field in range"),
    }
}

#[track_caller]
fn h(s: &str) -> Vec<u8> {
    let hex: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    hex.chunks(2)
        .map(|p| {
            let hi = (p[0] as char).to_digit(16).unwrap();
            let lo = (p[1] as char).to_digit(16).unwrap();
            (hi * 16 + lo) as u8
        })
        .collect()
}

#[cfg(all(feature = "session-grouped", feature = "session-groupless"))]
#[test]
fn saved_sessions_decode_under_the_reference() {
    require_protoc();
    let doc = h("089601 12026869 1A03089601");
    {
        use protobuf_edit::session::grouped::{InsertAt, Session};
        let mut s = Session::open_copy(&doc).unwrap();
        let t: Vec<_> = s.top().collect();
        s.set_varint(t[0], 7).unwrap();
        s.set_payload(t[1], b"world").unwrap();
        s.insert_varint(InsertAt::After(t[0]), f(9), u64::MAX).unwrap();
        s.delete(t[2]).unwrap();
        let saved = s.save().unwrap();
        assert!(reference_accepts(saved.as_slice()), "protoc rejected grouped save");
    }
    {
        use protobuf_edit::session::groupless::Session;
        let mut s = Session::open_copy(&doc).unwrap();
        let t: Vec<_> = s.top().collect();
        s.set_varint(t[0], 7).unwrap();
        let saved = s.save().unwrap();
        assert!(reference_accepts(saved.as_slice()), "protoc rejected groupless save");
    }
}

#[cfg(feature = "construct-grouped")]
#[test]
fn constructed_bytes_decode_under_the_reference() {
    require_protoc();
    use protobuf_edit::construct::grouped::Builder;
    let mut b = Builder::new();
    b.push_int64(f(1), -1);
    b.push_string(f(2), "hé"); // multi-byte UTF-8
    b.message(f(3), |m| {
        m.push_sint32(f(4), i32::MIN);
        m.push_sint64(f(5), i64::MIN);
    });
    b.push_packed_uint32(f(6), &[0, 1, u32::MAX]);
    b.group(f(7), |g| g.push_varint(f(1), 1));
    let bytes = b.finish().unwrap();
    assert!(reference_accepts(&bytes), "protoc rejected constructed bytes {bytes:02X?}");
}

#[cfg(all(feature = "rewrite-grouped", feature = "traverse-grouped"))]
#[test]
fn rewritten_bytes_decode_under_the_reference() {
    require_protoc();
    use protobuf_edit::DepthLimit;
    use protobuf_edit::rewrite::grouped::rewrite;
    use protobuf_edit::path::Segment;
    use protobuf_edit::rewrite::{Action, Rule, RuleSet, Value};
    let doc = h("089601 12026869 12016A");
    let rules =
        [Rule { path: &[Segment::Field(f(2))], action: Action::Replace(Value::Len(b"swapped")) }];
    let set = RuleSet::over(&rules).unwrap();
    let (out, _) = rewrite(&doc, &set, DepthLimit::REFERENCE).unwrap();
    assert!(reference_accepts(&out), "protoc rejected rewrite output {out:02X?}");
}

#[cfg(all(feature = "inplace-grouped", feature = "inplace-groupless"))]
#[test]
fn inplace_edited_bytes_decode_under_the_reference() {
    require_protoc();
    use protobuf_edit::inplace::{Action, Rule, RuleSet};
    use protobuf_edit::path::Segment;
    use protobuf_edit::{DepthLimit, Standard};

    // Groupless, tolerant: a padded fill, an equal-length payload
    // overwrite, a renumber, a kind-crossing substitution, and a
    // tombstone — every authored shape in one document.
    let doc = h("089601 12026869 189601 25AABBCCDD 2A03616263");
    let rules = [
        Rule { path: &[Segment::Field(f(1))], action: Action::SetVarint(7) },
        Rule { path: &[Segment::Field(f(2))], action: Action::SetPayload(b"no") },
        Rule { path: &[Segment::Field(f(3))], action: Action::Renumber(f(6)) },
        Rule {
            path: &[Segment::Field(f(4))],
            action: Action::ReplaceRecord(&[0x40, 0x80, 0x80, 0x80, 0x01]),
        },
        Rule { path: &[Segment::Field(f(5))], action: Action::Tombstone { field: f(9) } },
    ];
    let set = RuleSet::over(&rules).unwrap();
    let mut buf = doc;
    let stats =
        protobuf_edit::inplace::groupless::apply(&mut buf, &set, DepthLimit::REFERENCE).unwrap();
    assert_eq!(
        (stats.replaced(), stats.renumbered(), stats.substituted(), stats.tombstoned()),
        (2, 1, 1, 1)
    );
    assert!(reference_accepts(&buf), "protoc rejected groupless in-place output {buf:02X?}");

    // The canonical pair-split tombstone: a 130-byte extent under a
    // one-byte filler tag sits exactly on the prefix-class gap, so
    // the filler is a minimal pair — the one subtle emission shape.
    let mut gap = h("8201 7F");
    gap.extend(std::iter::repeat_n(0xAA, 127));
    let rules =
        [Rule { path: &[Segment::Field(f(16))], action: Action::Tombstone { field: f(1) } }];
    let set = RuleSet::over(&rules).unwrap();
    let stats = protobuf_edit::inplace::groupless::apply_standard(
        &mut gap,
        &set,
        Standard::CanonicalMinimal,
        DepthLimit::REFERENCE,
    )
    .unwrap();
    assert_eq!(stats.tombstoned(), 1);
    assert!(reference_accepts(&gap), "protoc rejected the pair-split tombstone {gap:02X?}");

    // Grouped: an atomic pair renumber and a whole-group tombstone.
    let doc = h("0B 109601 0C 1B 089601 1C 209601");
    let rules = [
        Rule { path: &[Segment::Field(f(1))], action: Action::Renumber(f(5)) },
        Rule { path: &[Segment::Field(f(3))], action: Action::Tombstone { field: f(9) } },
    ];
    let set = RuleSet::over(&rules).unwrap();
    let mut buf = doc;
    let stats =
        protobuf_edit::inplace::grouped::apply(&mut buf, &set, DepthLimit::REFERENCE).unwrap();
    assert_eq!((stats.renumbered(), stats.tombstoned()), (1, 1));
    assert!(reference_accepts(&buf), "protoc rejected grouped in-place output {buf:02X?}");
}

/// The conversion value judge: `--decode_raw` heuristically parses
/// message-shaped LEN payloads, so a group and its converted LEN
/// twin render identically under the reference — for non-empty
/// bodies (an empty group prints braced while an empty LEN prints
/// as a string, so the fixtures here keep every container
/// populated; the seeded differential's structural walk covers the
/// empty-container value equality offline). Both directions: the
/// reference must accept each cell's output and read the same
/// values from input and output.
#[cfg(all(
    feature = "convert-grouped",
    feature = "convert-groupless",
    feature = "construct-grouped"
))]
#[test]
fn converted_documents_read_identically_under_the_reference() {
    use protobuf_edit::path::{Program, Segment};
    use protobuf_edit::{DepthLimit, Standard};

    require_protoc();

    // Direction A: grouped input, every group re-framed as a LEN.
    let grouped_doc = {
        use protobuf_edit::construct::grouped::Builder;
        let mut b = Builder::new();
        b.push_varint(f(1), 150);
        b.group(f(2), |g| {
            g.push_string(f(3), "hé");
            g.group(f(4), |inner| inner.push_sint32(f(5), -3));
        });
        b.push_len(f(6), &[0xA5, 0x5A]);
        b.finish().unwrap()
    };
    let to_groupless = protobuf_edit::convert::groupless::Converter::new(
        Standard::Tolerant,
        DepthLimit::REFERENCE,
    );
    let (groupless_out, stats) = to_groupless.convert(&grouped_doc).unwrap();
    assert_eq!(stats.converted(), 2);
    let (in_ok, in_text) = run_protoc(&["--decode_raw"], &grouped_doc);
    let (out_ok, out_text) = run_protoc(&["--decode_raw"], &groupless_out);
    assert!(in_ok, "protoc rejected the grouped source {grouped_doc:02X?}");
    assert!(out_ok, "protoc rejected the converted output {groupless_out:02X?}");
    assert_eq!(
        norm(&out_text),
        norm(&in_text),
        "the reference reads different values after group-to-LEN conversion"
    );

    // Direction B: groupless input, the designated LEN re-framed
    // as a group — and the round trip through direction A is the
    // exact identity over this minimally framed source.
    let paths: [&[Segment<'_>]; 1] = [&[Segment::Field(f(2))]];
    let program = Program::over(&paths).unwrap();
    let to_grouped = protobuf_edit::convert::grouped::Converter::new(
        Standard::Tolerant,
        DepthLimit::REFERENCE,
        program,
    );
    let (grouped_out, stats) = to_grouped.convert(&groupless_out).unwrap();
    assert_eq!(stats.converted(), 1);
    let (back_ok, back_text) = run_protoc(&["--decode_raw"], &grouped_out);
    assert!(back_ok, "protoc rejected the re-framed output {grouped_out:02X?}");
    assert_eq!(
        norm(&back_text),
        norm(&in_text),
        "the reference reads different values after LEN-to-group conversion"
    );
    let (round, _) = to_groupless.convert(&grouped_out).unwrap();
    assert_eq!(round, groupless_out, "the conversion round trip moved bytes");
}

/// The tolerant value judge: padding changes encoding geometry,
/// never the value reading. Every padded document must be accepted
/// by `--decode_raw`, and the reference's text must equal what the
/// inspect parse renders — per dialect, over its lawful subset.
#[cfg(any(feature = "inspect-grouped", feature = "inspect-groupless"))]
#[test]
fn padded_values_match_the_reference_reading() {
    require_protoc();
    use protobuf_edit::DepthLimit;
    use protobuf_edit::inspect::{Admitted, NoAdvice};
    let docs = padded::DOCS;
    assert_eq!(docs.len(), 12, "padded census drifted");
    assert_eq!(docs.iter().filter(|d| d.groupless).count(), 10, "groupless census drifted");
    for doc in docs {
        let bytes = h(doc.padded);
        let (ok, text) = run_protoc(&["--decode_raw"], &bytes);
        assert!(ok, "{}: the reference rejected the padded document", doc.name);
        let reference = norm(&text);
        // The reference judges the twin relation directly too:
        // padding must not move protoc's own text.
        let twin = h(doc.twin);
        let (twin_ok, twin_text) = run_protoc(&["--decode_raw"], &twin);
        assert!(twin_ok, "{}: the reference rejected the canonical twin", doc.name);
        assert_eq!(
            norm(&twin_text),
            reference,
            "{}: the reference reads the twin differently",
            doc.name
        );
        #[cfg(feature = "inspect-grouped")]
        {
            use protobuf_edit::inspect::grouped::Tree;
            let tree =
                Tree::parse(Admitted::new(&bytes).unwrap(), DepthLimit::REFERENCE, &mut NoAdvice);
            assert!(
                tree.is_complete(),
                "{}: the reference accepts, inspector faulted: {:?}",
                doc.name,
                tree.fault()
            );
            assert_eq!(
                norm(&render::grouped::render(&tree)),
                reference,
                "{}: the grouped reading diverges from the reference",
                doc.name
            );
        }
        #[cfg(feature = "inspect-groupless")]
        if doc.groupless {
            use protobuf_edit::inspect::groupless::Tree;
            let tree =
                Tree::parse(Admitted::new(&bytes).unwrap(), DepthLimit::REFERENCE, &mut NoAdvice);
            assert!(
                tree.is_complete(),
                "{}: the reference accepts, inspector faulted: {:?}",
                doc.name,
                tree.fault()
            );
            assert_eq!(
                norm(&render::groupless::render(&tree)),
                reference,
                "{}: the groupless reading diverges from the reference",
                doc.name
            );
        }
    }
}

/// The scalar semantics judge: schema-typed decode over wire.proto.
/// `z32` is `sint32` (field 4) — a wire word wider than 2^32 - 1
/// distinguishes truncate-then-unzigzag from unzigzag-then-truncate.
#[test]
fn sint32_reduction_order_matches_the_reference() {
    require_protoc();
    // field 4, varint: word = (1 << 32) + 3.
    let wire = h("20 8380808010");
    let (ok, text) = run_protoc(&["--decode=M", "wire.proto"], &wire);
    assert!(ok, "protoc rejected the sint32 probe");
    let reference = norm(&text);

    let ours = protobuf_edit::scalar::decode_sint32((1 << 32) + 3);
    assert_eq!(
        reference,
        format!("z32: {ours}"),
        "sint32 reduction order diverges from the reference"
    );
}

/// The other direction: our zigzag encoding must be protoc's.
#[test]
fn sint_encodings_match_the_reference_encoder() {
    require_protoc();
    for (text, field_word) in [
        ("z32: -2147483648", (4u32, protobuf_edit::scalar::encode_sint32(i32::MIN))),
        ("z64: -1", (5u32, protobuf_edit::scalar::encode_sint64(-1))),
    ] {
        let mut child = Command::new("protoc")
            .args(["--encode=M", "wire.proto"])
            .current_dir(VECTORS)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        child.stdin.as_mut().unwrap().write_all(text.as_bytes()).unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success());

        // Ours: one varint record with the same field and word.
        let (field, word) = field_word;
        let mut ours = Vec::new();
        protobuf_edit::varint::push64(&mut ours, u64::from(field << 3));
        protobuf_edit::varint::push64(&mut ours, word);
        assert_eq!(out.stdout, ours, "zigzag encoding diverges for {text}");
    }
}
