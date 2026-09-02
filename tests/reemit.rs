//! The re-emission law: bytes any writer face emits successfully
//! must be accepted by the same dialect's own validator, and the
//! values written must read back through the inspector.
//!
//! This crosses independent implementations inside the crate — the
//! writer's framing arithmetic against the scan machine's wire
//! law and the inspector's tree — so a framing bug on either side
//! breaks it. It is the in-crate half of the write-side oracle
//! (the protoc-in-the-loop half lives in `protoc_live.rs`).

// The full consumer closure this suite drives; under any narrower
// feature set the target compiles empty, so per-cell `--all-targets`
// builds stay green.
#![cfg(all(
    feature = "adopt-grouped",
    feature = "adopt-groupless",
    feature = "amend-grouped",
    feature = "amend-groupless",
    feature = "construct-grouped",
    feature = "construct-groupless",
    feature = "convert-grouped",
    feature = "convert-groupless",
    feature = "draft-grouped",
    feature = "draft-groupless",
    feature = "inspect-grouped",
    feature = "inspect-groupless",
    feature = "intake-grouped",
    feature = "intake-groupless",
    feature = "markup-grouped",
    feature = "markup-groupless",
    feature = "patch-grouped",
    feature = "patch-groupless",
    feature = "review-grouped",
    feature = "review-groupless",
    feature = "rewrite-grouped",
    feature = "rewrite-groupless",
    feature = "scan-grouped",
    feature = "scan-groupless",
    feature = "session-grouped",
    feature = "session-groupless",
    feature = "transcode-grouped",
    feature = "transcode-groupless",
))]

extern crate alloc;

use protobuf_edit::{DepthLimit, FieldNumber};

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

macro_rules! dialect_reemit {
    ($mod_name:ident, $helpers:ident, $construct:path, $session:path, $insert_at:path,
     $draft:path, $draft_insert_at:path,
     $validate:expr, $validate_canonical:expr, $inspect_tree:path, $admitted:path) => {
        mod $mod_name {
            use super::*;

            fn accepts(bytes: &[u8]) -> bool {
                let check: fn(&[u8]) -> bool = $validate;
                check(bytes)
            }

            fn closes_canonical(bytes: &[u8]) -> bool {
                let check: fn(&[u8]) -> bool = $validate_canonical;
                check(bytes)
            }

            #[test]
            fn constructed_bytes_pass_the_dialect_validator_and_read_back() {
                use $construct as Builder;
                let mut b = Builder::new();
                b.push_varint(f(1), 150);
                b.push_string(f(2), "hi");
                b.message(f(3), |m| {
                    m.push_sint64(f(4), -7);
                    m.push_packed_uint32(f(6), &[1, 2, 300]);
                });
                b.push_double(f(5), 1.5);
                let bytes = b.finish().unwrap();
                assert!(accepts(&bytes), "validator refused constructed bytes {bytes:02X?}");

                use $inspect_tree as Tree;
                let admitted = <$admitted>::new(&bytes).unwrap();
                let tree = Tree::parse(admitted, DepthLimit::REFERENCE, &mut NoAdvice);
                assert!(tree.fault().is_none(), "inspector faulted: {:?}", tree.fault());
                let top: Vec<_> = tree.top().collect();
                assert_eq!(tree.varint_word(top[0]), Some(150));
                assert_eq!(tree.field(top[1]), f(2));
            }

            #[test]
            fn saved_sessions_pass_the_dialect_validator() {
                use $insert_at as InsertAt;
                use $session as Session;
                let doc = h("089601 12026869 1A03089601");
                let mut s = Session::open_copy(&doc).unwrap();
                let t: Vec<_> = s.top().collect();
                s.set_varint(t[0], 7).unwrap();
                s.set_payload(t[1], b"world").unwrap();
                s.insert_varint(InsertAt::After(t[0]), f(9), u64::MAX).unwrap();
                s.delete(t[2]).unwrap();
                let saved = s.save().unwrap();
                assert!(accepts(saved.as_slice()), "validator refused saved bytes");

                // And after reverting everything, the clean save.
                s.revert_all();
                assert!(accepts(s.save().unwrap().as_slice()));
            }

            #[test]
            fn saved_patches_pass_the_dialect_validator() {
                use super::$helpers::patch_face;
                let doc = h("089601 12026869 1A03089601");
                let saved = patch_face(&doc);
                assert!(accepts(&saved), "validator refused patched bytes {saved:02X?}");
            }

            #[test]
            fn rewritten_bytes_pass_the_dialect_validator() {
                use protobuf_edit::path::Segment;
                use protobuf_edit::rewrite::{Action, Rule, RuleSet, Value};
                let doc = h("089601 12026869 12016A 089701");
                let delete_two = [Rule { path: &[Segment::Field(f(2))], action: Action::Delete }];
                let replace_one = [Rule {
                    path: &[Segment::Field(f(1))],
                    action: Action::Replace(Value::Varint(5)),
                }];
                for rules in [&delete_two[..], &replace_one[..]] {
                    let set = RuleSet::over(rules).unwrap();
                    let (out, _stats) = super::$helpers::rewrite_face(&doc, &set);
                    assert!(accepts(&out), "validator refused rewrite output {out:02X?}");
                }
            }

            #[test]
            fn transcoded_identity_passes_the_dialect_validator() {
                let doc = h("089601 12026869 1A03089601");
                let out = super::$helpers::transcode_identity(&doc);
                assert_eq!(out, doc, "the all-default rule is bit-identical");
                assert!(accepts(&out));
            }

            // The output-acceptance roll-ups (each writer module
            // doc's "Output acceptance" sentence is the claim
            // under judgment here).

            #[test]
            fn construct_and_session_outputs_close_under_canonical_minimal() {
                use $construct as Builder;
                let mut b = Builder::new();
                b.push_varint(f(1), 150);
                b.message(f(3), |m| m.push_string(f(2), "hi"));
                let bytes = b.finish().unwrap();
                assert!(closes_canonical(&bytes), "constructed bytes are minimal words");

                use $insert_at as InsertAt;
                use $session as Session;
                let mut s = Session::open_copy(&bytes).unwrap();
                let t: Vec<_> = s.top().collect();
                s.set_varint(t[0], u64::MAX).unwrap();
                // An authored payload's interior is the caller's
                // declaration (opaque bytes) — padded words inside
                // it do not touch the document's own framing.
                s.insert_payload(InsertAt::TailOf(None), f(9), &h("8800 9601")).unwrap();
                assert!(
                    closes_canonical(s.save().unwrap().as_slice()),
                    "canonical admission plus minimal authoring closes the save"
                );
            }

            #[test]
            fn edits_over_padded_sources_reingest_tolerant_and_refuse_canonical() {
                // Field 1's tag padded to two bytes: fidelity keeps
                // the padding, so the output re-ingests under
                // Tolerant and cannot close under CanonicalMinimal.
                let padded = h("8800 9601 100A");
                let saved = super::$helpers::patch_face_value_edit(&padded);
                assert!(accepts(&saved), "padded survivors still re-ingest under Tolerant");
                assert!(
                    !closes_canonical(&saved),
                    "a padded survivor must keep CanonicalMinimal refusing"
                );

                use protobuf_edit::path::Segment;
                use protobuf_edit::rewrite::{Action, Rule, RuleSet, Value};
                let rules = [Rule {
                    path: &[Segment::Field(f(2))],
                    action: Action::Replace(Value::Varint(5)),
                }];
                let set = RuleSet::over(&rules).unwrap();
                let (out, _) = super::$helpers::rewrite_face(&padded, &set);
                assert!(accepts(&out));
                assert!(!closes_canonical(&out), "rewrite rides kept tags verbatim");
            }

            #[test]
            fn edits_over_clean_sources_close_under_canonical_minimal() {
                let clean = h("089601 100A");
                let saved = super::$helpers::patch_face_value_edit(&clean);
                assert!(closes_canonical(&saved), "no padding to survive: the save closes");

                use protobuf_edit::path::Segment;
                use protobuf_edit::rewrite::{Action, Rule, RuleSet, Value};
                let rules = [Rule {
                    path: &[Segment::Field(f(2))],
                    action: Action::Replace(Value::Varint(5)),
                }];
                let set = RuleSet::over(&rules).unwrap();
                let (out, _) = super::$helpers::rewrite_face(&clean, &set);
                assert!(closes_canonical(&out), "replacements re-emit minimally");
            }

            #[test]
            fn draft_saves_reingest_tolerant_and_close_canonical_exactly_when_unpadded() {
                use $draft as Draft;
                use $draft_insert_at as InsertAt;

                // A padded source: fidelity keeps the padding, so
                // every save re-ingests under Tolerant and cannot
                // close under CanonicalMinimal.
                let padded = h("8800 9601 100A");
                let mut d = Draft::open(padded.clone()).unwrap();
                let t: Vec<_> = d.top().collect();
                d.set_varint(t[1], 7).unwrap();
                d.insert_varint(InsertAt::TailOf(None), f(9), u64::MAX).unwrap();
                let saved = d.save().unwrap();
                assert!(accepts(&saved), "padded survivors still re-ingest under Tolerant");
                assert!(
                    !closes_canonical(&saved),
                    "a padded survivor must keep CanonicalMinimal refusing"
                );
                // Reverted, the save is the padded source itself —
                // Tolerant re-ingestion again, canonical refusal
                // again.
                d.revert_all();
                let clean_save = d.save().unwrap();
                assert_eq!(clean_save, padded);
                assert!(accepts(&clean_save));
                assert!(!closes_canonical(&clean_save));

                // An unpadded source: edits re-author minimally, so
                // the save closes under CanonicalMinimal.
                let clean = h("089601 100A");
                let mut d = Draft::open(clean).unwrap();
                let t: Vec<_> = d.top().collect();
                d.set_varint(t[1], 7).unwrap();
                d.insert_varint(InsertAt::TailOf(None), f(9), 1).unwrap();
                let saved = d.save().unwrap();
                assert!(accepts(&saved));
                assert!(closes_canonical(&saved), "no padding to survive: the draft's save closes");
            }
        }
    };
}

use protobuf_edit::inspect::NoAdvice;

mod grouped {
    use super::*;

    pub fn patch_face(doc: &[u8]) -> Vec<u8> {
        use protobuf_edit::patch::grouped::{InsertAt, Patch};
        let mut p = Patch::open(doc, DepthLimit::REFERENCE).unwrap();
        let t: Vec<_> = p.top().collect();
        p.set_varint(t[0], 7).unwrap();
        p.set_payload(t[1], b"world").unwrap();
        p.insert_varint(InsertAt::After(t[0]), f(9), u64::MAX).unwrap();
        p.delete(t[2]).unwrap();
        p.save().unwrap()
    }

    pub fn patch_face_value_edit(doc: &[u8]) -> Vec<u8> {
        use protobuf_edit::patch::grouped::Patch;
        let mut p = Patch::open(doc, DepthLimit::REFERENCE).unwrap();
        let t: Vec<_> = p.top().collect();
        p.set_varint(t[1], 7).unwrap();
        p.save().unwrap()
    }

    pub fn rewrite_face(
        doc: &[u8],
        set: &protobuf_edit::rewrite::RuleSet<'_>,
    ) -> (Vec<u8>, protobuf_edit::rewrite::Stats) {
        protobuf_edit::rewrite::grouped::rewrite(doc, set, DepthLimit::REFERENCE).unwrap()
    }

    pub fn transcode_identity(doc: &[u8]) -> Vec<u8> {
        use protobuf_edit::transcode::grouped::Transcoder;
        use protobuf_edit::transcode::Standard;
        let mut out = Vec::new();
        let mut sink = |chunk: &[u8]| out.extend_from_slice(chunk);
        let mut t = Transcoder::new(Standard::Tolerant, DepthLimit::REFERENCE);
        t.feed(doc, &mut (), &mut sink).unwrap();
        t.finish(&mut (), &mut sink).unwrap();
        out
    }
}

mod groupless {
    use super::*;

    pub fn patch_face(doc: &[u8]) -> Vec<u8> {
        use protobuf_edit::patch::groupless::{InsertAt, Patch};
        let mut p = Patch::open(doc, DepthLimit::REFERENCE).unwrap();
        let t: Vec<_> = p.top().collect();
        p.set_varint(t[0], 7).unwrap();
        p.set_payload(t[1], b"world").unwrap();
        p.insert_varint(InsertAt::After(t[0]), f(9), u64::MAX).unwrap();
        p.delete(t[2]).unwrap();
        p.save().unwrap()
    }

    pub fn patch_face_value_edit(doc: &[u8]) -> Vec<u8> {
        use protobuf_edit::patch::groupless::Patch;
        let mut p = Patch::open(doc, DepthLimit::REFERENCE).unwrap();
        let t: Vec<_> = p.top().collect();
        p.set_varint(t[1], 7).unwrap();
        p.save().unwrap()
    }

    pub fn rewrite_face(
        doc: &[u8],
        set: &protobuf_edit::rewrite::RuleSet<'_>,
    ) -> (Vec<u8>, protobuf_edit::rewrite::Stats) {
        protobuf_edit::rewrite::groupless::rewrite(doc, set, DepthLimit::REFERENCE).unwrap()
    }

    pub fn transcode_identity(doc: &[u8]) -> Vec<u8> {
        use protobuf_edit::transcode::groupless::Transcoder;
        use protobuf_edit::transcode::Standard;
        let mut out = Vec::new();
        let mut sink = |chunk: &[u8]| out.extend_from_slice(chunk);
        let mut t = Transcoder::new(Standard::Tolerant, DepthLimit::REFERENCE);
        t.feed(doc, &mut (), &mut sink).unwrap();
        t.finish(&mut (), &mut sink).unwrap();
        out
    }
}

dialect_reemit!(
    grouped_law,
    grouped,
    protobuf_edit::construct::grouped::Builder,
    protobuf_edit::session::grouped::Session,
    protobuf_edit::session::grouped::InsertAt,
    protobuf_edit::draft::grouped::Draft,
    protobuf_edit::draft::grouped::InsertAt,
    |bytes| {
        use protobuf_edit::scan::grouped::Validator;
        use protobuf_edit::scan::Standard;
        let mut v = Validator::new(Standard::Tolerant, DepthLimit::REFERENCE);
        v.feed(bytes).is_ok() && v.finish().is_ok()
    },
    |bytes| {
        use protobuf_edit::scan::grouped::Validator;
        use protobuf_edit::scan::Standard;
        let mut v = Validator::new(Standard::CanonicalMinimal, DepthLimit::REFERENCE);
        v.feed(bytes).is_ok() && v.finish().is_ok()
    },
    protobuf_edit::inspect::grouped::Tree,
    protobuf_edit::inspect::Admitted
);

dialect_reemit!(
    groupless_law,
    groupless,
    protobuf_edit::construct::groupless::Builder,
    protobuf_edit::session::groupless::Session,
    protobuf_edit::session::groupless::InsertAt,
    protobuf_edit::draft::groupless::Draft,
    protobuf_edit::draft::groupless::InsertAt,
    |bytes| {
        use protobuf_edit::scan::groupless::Validator;
        use protobuf_edit::scan::Standard;
        let mut v = Validator::new(Standard::Tolerant);
        v.feed(bytes).is_ok() && v.finish().is_ok()
    },
    |bytes| {
        use protobuf_edit::scan::groupless::Validator;
        use protobuf_edit::scan::Standard;
        let mut v = Validator::new(Standard::CanonicalMinimal);
        v.feed(bytes).is_ok() && v.finish().is_ok()
    },
    protobuf_edit::inspect::groupless::Tree,
    protobuf_edit::inspect::Admitted
);

/// The markup under the same law as the draft it mirrors: padded
/// sources keep their padding through every save (Tolerant
/// re-ingestion, CanonicalMinimal refusal), unpadded sources
/// re-author minimally.
macro_rules! markup_reemit {
    ($mod_name:ident, $markup:path, $insert_at:path, $validate:expr, $validate_canonical:expr) => {
        mod $mod_name {
            use super::*;

            fn accepts(bytes: &[u8]) -> bool {
                let check: fn(&[u8]) -> bool = $validate;
                check(bytes)
            }

            fn closes_canonical(bytes: &[u8]) -> bool {
                let check: fn(&[u8]) -> bool = $validate_canonical;
                check(bytes)
            }

            #[test]
            fn markup_saves_reingest_tolerant_and_close_canonical_exactly_when_unpadded() {
                use $insert_at as InsertAt;
                use $markup as Markup;

                let padded = h("8800 9601 100A");
                let mut m = Markup::open(&padded).unwrap();
                let t: Vec<_> = m.top().collect();
                m.set_varint(t[1], 7).unwrap();
                m.insert_varint(InsertAt::TailOf(None), f(9), u64::MAX).unwrap();
                let saved = m.save().unwrap();
                assert!(accepts(&saved), "padded survivors still re-ingest under Tolerant");
                assert!(
                    !closes_canonical(&saved),
                    "a padded survivor must keep CanonicalMinimal refusing"
                );
                m.revert_all();
                let clean_save = m.save().unwrap();
                assert_eq!(clean_save, padded);
                assert!(accepts(&clean_save));
                assert!(!closes_canonical(&clean_save));

                let clean = h("089601 100A");
                let mut m = Markup::open(&clean).unwrap();
                let t: Vec<_> = m.top().collect();
                m.set_varint(t[1], 7).unwrap();
                m.insert_varint(InsertAt::TailOf(None), f(9), 1).unwrap();
                let saved = m.save().unwrap();
                assert!(accepts(&saved));
                assert!(
                    closes_canonical(&saved),
                    "no padding to survive: the markup's save closes"
                );
            }
        }
    };
}

/// The intake under its own stronger law: canonical admission plus
/// minimal authoring closes every save under CanonicalMinimal — with
/// the one caller-declared exception, an authored payload's interior
/// rides opaque.
macro_rules! intake_reemit {
    ($mod_name:ident, $intake:path, $insert_at:path, $validate:expr, $validate_canonical:expr) => {
        mod $mod_name {
            use super::*;

            fn accepts(bytes: &[u8]) -> bool {
                let check: fn(&[u8]) -> bool = $validate;
                check(bytes)
            }

            fn closes_canonical(bytes: &[u8]) -> bool {
                let check: fn(&[u8]) -> bool = $validate_canonical;
                check(bytes)
            }

            #[test]
            fn intake_saves_close_under_canonical_minimal() {
                use $insert_at as InsertAt;
                use $intake as Intake;

                // A padded source never opens: the door is the law's
                // first half, so no padded survivor can exist.
                let padded = h("8800 9601 100A");
                assert!(Intake::open(padded, DepthLimit::REFERENCE).is_err());

                let clean = h("089601 12026869 100A");
                let mut i = Intake::open(clean, DepthLimit::REFERENCE).unwrap();
                let t: Vec<_> = i.top().collect();
                i.set_varint(t[0], u64::MAX).unwrap();
                i.set_payload(t[1], b"world").unwrap();
                i.insert_varint(InsertAt::After(t[2]), f(9), 300).unwrap();
                i.delete(t[2]).unwrap();
                let saved = i.save().unwrap();
                assert!(accepts(&saved), "canonical outputs re-ingest under Tolerant too");
                assert!(closes_canonical(&saved), "admission plus minimal authoring closes");
                assert!(
                    Intake::open(saved, DepthLimit::REFERENCE).is_ok(),
                    "the save re-enters the intake's own door"
                );

                // The declared exception: an authored payload's
                // interior is the caller's opaque bytes — padding
                // inside it never touches the document's framing.
                let opaque = h("8800 9601");
                let mut i = Intake::open(h("089601"), DepthLimit::REFERENCE).unwrap();
                i.insert_payload(InsertAt::TailOf(None), f(9), &opaque).unwrap();
                assert!(closes_canonical(i.save().unwrap().as_slice()));
            }
        }
    };
}

macro_rules! amend_reemit {
    ($mod_name:ident, $amend:path, $insert_at:path, $validate:expr, $validate_canonical:expr) => {
        mod $mod_name {
            use super::*;

            fn accepts(bytes: &[u8]) -> bool {
                let check: fn(&[u8]) -> bool = $validate;
                check(bytes)
            }

            fn closes_canonical(bytes: &[u8]) -> bool {
                let check: fn(&[u8]) -> bool = $validate_canonical;
                check(bytes)
            }

            #[test]
            fn amend_saves_close_under_canonical_minimal() {
                use $amend as Amend;
                use $insert_at as InsertAt;

                // A padded source never opens: the door is the law's
                // first half, so no padded survivor can exist.
                let padded = h("8800 9601 100A");
                assert!(Amend::open(&padded, DepthLimit::REFERENCE).is_err());

                let clean = h("089601 12026869 100A");
                let mut a = Amend::open(&clean, DepthLimit::REFERENCE).unwrap();
                let t: Vec<_> = a.top().collect();
                a.set_varint(t[0], u64::MAX).unwrap();
                a.set_payload(t[1], b"world").unwrap();
                a.insert_varint(InsertAt::After(t[2]), f(9), 300).unwrap();
                a.delete(t[2]).unwrap();
                let saved = a.save().unwrap();
                assert!(accepts(&saved), "canonical outputs re-ingest under Tolerant too");
                assert!(closes_canonical(&saved), "admission plus minimal authoring closes");
                assert!(
                    Amend::open(&saved, DepthLimit::REFERENCE).is_ok(),
                    "the save re-enters the amend's own door"
                );

                // The declared exception: an authored payload's
                // interior is the caller's opaque bytes — padding
                // inside it never touches the document's framing.
                let opaque = h("8800 9601");
                let doc = h("089601");
                let mut a = Amend::open(&doc, DepthLimit::REFERENCE).unwrap();
                a.insert_payload(InsertAt::TailOf(None), f(9), &opaque).unwrap();
                assert!(closes_canonical(a.save().unwrap().as_slice()));
            }
        }
    };
}

/// The review under the session's law through the borrowed door:
/// canonical admission plus minimal authoring closes every save
/// under CanonicalMinimal, and the closure holds at every point of
/// the revision log — with the one caller-declared exception, an
/// authored payload's interior rides opaque.
macro_rules! review_reemit {
    ($mod_name:ident, $review:path, $insert_at:path, $validate:expr, $validate_canonical:expr) => {
        mod $mod_name {
            use super::*;

            fn accepts(bytes: &[u8]) -> bool {
                let check: fn(&[u8]) -> bool = $validate;
                check(bytes)
            }

            fn closes_canonical(bytes: &[u8]) -> bool {
                let check: fn(&[u8]) -> bool = $validate_canonical;
                check(bytes)
            }

            #[test]
            fn review_saves_close_under_canonical_minimal_across_revision() {
                use $insert_at as InsertAt;
                use $review as Review;

                // A padded source never opens: the door is the law's
                // first half, so no padded survivor can exist.
                let padded = h("8800 9601 100A");
                assert!(Review::open(&padded).is_err());

                let clean = h("089601 12026869 100A");
                let mut r = Review::open(&clean).unwrap();
                let t: Vec<_> = r.top().collect();
                r.set_varint(t[0], u64::MAX).unwrap();
                r.set_payload(t[1], b"world").unwrap();
                r.insert_varint(InsertAt::After(t[2]), f(9), 300).unwrap();
                r.delete(t[2]).unwrap();
                let saved = r.save().unwrap();
                assert!(accepts(&saved), "canonical outputs re-ingest under Tolerant too");
                assert!(closes_canonical(&saved), "admission plus minimal authoring closes");
                assert!(Review::open(&saved).is_ok(), "the save re-enters the review's own door");

                // The law holds at every log point: each revert's
                // save closes too, down to the source itself.
                while r.revert().is_some() {
                    assert!(closes_canonical(r.save().unwrap().as_slice()));
                }
                assert_eq!(r.save().unwrap(), clean, "the emptied log restores the source");

                // The declared exception: an authored payload's
                // interior is the caller's opaque bytes — padding
                // inside it never touches the document's framing.
                let opaque = h("8800 9601");
                let doc = h("089601");
                let mut r = Review::open(&doc).unwrap();
                r.insert_payload(InsertAt::TailOf(None), f(9), &opaque).unwrap();
                assert!(closes_canonical(r.save().unwrap().as_slice()));
            }
        }
    };
}

amend_reemit!(
    grouped_amend_law,
    protobuf_edit::amend::grouped::Amend,
    protobuf_edit::amend::grouped::InsertAt,
    |bytes| {
        use protobuf_edit::scan::grouped::Validator;
        use protobuf_edit::scan::Standard;
        let mut v = Validator::new(Standard::Tolerant, DepthLimit::REFERENCE);
        v.feed(bytes).is_ok() && v.finish().is_ok()
    },
    |bytes| {
        use protobuf_edit::scan::grouped::Validator;
        use protobuf_edit::scan::Standard;
        let mut v = Validator::new(Standard::CanonicalMinimal, DepthLimit::REFERENCE);
        v.feed(bytes).is_ok() && v.finish().is_ok()
    }
);

amend_reemit!(
    groupless_amend_law,
    protobuf_edit::amend::groupless::Amend,
    protobuf_edit::amend::groupless::InsertAt,
    |bytes| {
        use protobuf_edit::scan::groupless::Validator;
        use protobuf_edit::scan::Standard;
        let mut v = Validator::new(Standard::Tolerant);
        v.feed(bytes).is_ok() && v.finish().is_ok()
    },
    |bytes| {
        use protobuf_edit::scan::groupless::Validator;
        use protobuf_edit::scan::Standard;
        let mut v = Validator::new(Standard::CanonicalMinimal);
        v.feed(bytes).is_ok() && v.finish().is_ok()
    }
);

review_reemit!(
    grouped_review_law,
    protobuf_edit::review::grouped::Review,
    protobuf_edit::review::grouped::InsertAt,
    |bytes| {
        use protobuf_edit::scan::grouped::Validator;
        use protobuf_edit::scan::Standard;
        let mut v = Validator::new(Standard::Tolerant, DepthLimit::REFERENCE);
        v.feed(bytes).is_ok() && v.finish().is_ok()
    },
    |bytes| {
        use protobuf_edit::scan::grouped::Validator;
        use protobuf_edit::scan::Standard;
        let mut v = Validator::new(Standard::CanonicalMinimal, DepthLimit::REFERENCE);
        v.feed(bytes).is_ok() && v.finish().is_ok()
    }
);

review_reemit!(
    groupless_review_law,
    protobuf_edit::review::groupless::Review,
    protobuf_edit::review::groupless::InsertAt,
    |bytes| {
        use protobuf_edit::scan::groupless::Validator;
        use protobuf_edit::scan::Standard;
        let mut v = Validator::new(Standard::Tolerant);
        v.feed(bytes).is_ok() && v.finish().is_ok()
    },
    |bytes| {
        use protobuf_edit::scan::groupless::Validator;
        use protobuf_edit::scan::Standard;
        let mut v = Validator::new(Standard::CanonicalMinimal);
        v.feed(bytes).is_ok() && v.finish().is_ok()
    }
);

intake_reemit!(
    grouped_intake_law,
    protobuf_edit::intake::grouped::Intake,
    protobuf_edit::intake::grouped::InsertAt,
    |bytes| {
        use protobuf_edit::scan::grouped::Validator;
        use protobuf_edit::scan::Standard;
        let mut v = Validator::new(Standard::Tolerant, DepthLimit::REFERENCE);
        v.feed(bytes).is_ok() && v.finish().is_ok()
    },
    |bytes| {
        use protobuf_edit::scan::grouped::Validator;
        use protobuf_edit::scan::Standard;
        let mut v = Validator::new(Standard::CanonicalMinimal, DepthLimit::REFERENCE);
        v.feed(bytes).is_ok() && v.finish().is_ok()
    }
);

intake_reemit!(
    groupless_intake_law,
    protobuf_edit::intake::groupless::Intake,
    protobuf_edit::intake::groupless::InsertAt,
    |bytes| {
        use protobuf_edit::scan::groupless::Validator;
        use protobuf_edit::scan::Standard;
        let mut v = Validator::new(Standard::Tolerant);
        v.feed(bytes).is_ok() && v.finish().is_ok()
    },
    |bytes| {
        use protobuf_edit::scan::groupless::Validator;
        use protobuf_edit::scan::Standard;
        let mut v = Validator::new(Standard::CanonicalMinimal);
        v.feed(bytes).is_ok() && v.finish().is_ok()
    }
);

/// The converters' exact closure biconditionals, both cells and
/// both directions of each iff: canonical-in jobs close
/// canonically by construction, and a tolerant job's output closes
/// canonically exactly when every padded source word was converted
/// framing — each side judged by instantiating a converter and
/// running the OUTPUT dialect's canonical validator over its
/// product.
mod convert_closure {
    use super::*;
    use protobuf_edit::Standard;

    fn grouped_accepts(bytes: &[u8], standard: Standard) -> bool {
        use protobuf_edit::scan::grouped::Validator;
        let mut v = Validator::new(standard, DepthLimit::REFERENCE);
        v.feed(bytes).is_ok() && v.finish().is_ok()
    }

    fn groupless_accepts(bytes: &[u8], standard: Standard) -> bool {
        use protobuf_edit::scan::groupless::Validator;
        let mut v = Validator::new(standard);
        v.feed(bytes).is_ok() && v.finish().is_ok()
    }

    #[test]
    fn groupless_output_closes_canonically_iff_padding_was_framing_or_interior() {
        use protobuf_edit::convert::groupless::Converter;

        // Canonical-in ⇒ canonical-out, by construction.
        let canonical = Converter::new(Standard::CanonicalMinimal, DepthLimit::REFERENCE);
        let minimal = h("13 18 01 14"); // group f2 { varint f3=1 }
        let (out, stats) = canonical.convert(&minimal).unwrap();
        assert_eq!(stats.converted(), 1);
        assert!(groupless_accepts(&out, Standard::CanonicalMinimal));

        // Tolerant, iff ⇐: every padded word is group framing (the
        // open and end tags, both two bytes wide) — the conversion
        // authors minimal framing, so the output closes.
        let tolerant = Converter::new(Standard::Tolerant, DepthLimit::REFERENCE);
        let padded_framing = h("93 00 18 01 94 00");
        let (out, stats) = tolerant.convert(&padded_framing).unwrap();
        assert_eq!(stats.converted(), 1);
        assert_eq!(out, h("12 02 18 01"));
        assert!(groupless_accepts(&out, Standard::CanonicalMinimal));

        // Tolerant, iff ⇐, the opacity clause: a padded word
        // inside a group's body rides verbatim into the authored
        // LEN payload — an opaque declaration the canonical judge
        // does not enter — so the output still closes.
        let padded_interior = h("13 18 81 00 14");
        let (out, stats) = tolerant.convert(&padded_interior).unwrap();
        assert_eq!(stats.converted(), 1);
        assert_eq!(out, h("12 03 18 81 00"));
        assert!(groupless_accepts(&out, Standard::CanonicalMinimal));

        // Tolerant, iff ⇒: a padded word outside every group is
        // neither framing nor enclosed — it rides verbatim where
        // the canonical judge walks, so the output re-ingests
        // tolerantly but does not close.
        let padded_visible = h("13 18 01 14 08 81 00");
        let (out, stats) = tolerant.convert(&padded_visible).unwrap();
        assert_eq!(stats.converted(), 1);
        assert_eq!(out, h("12 02 18 01 08 81 00"));
        assert!(groupless_accepts(&out, Standard::Tolerant));
        assert!(!groupless_accepts(&out, Standard::CanonicalMinimal));
    }

    #[test]
    fn grouped_output_closes_canonically_iff_padding_was_converted_framing() {
        use protobuf_edit::convert::grouped::Converter;
        use protobuf_edit::path::{Program, Segment};

        let paths: [&[Segment<'_>]; 1] = [&[Segment::Field(f(2))]];
        let program = Program::over(&paths).unwrap();

        // Canonical-in ⇒ canonical-out, by construction.
        let canonical = Converter::new(Standard::CanonicalMinimal, DepthLimit::REFERENCE, program);
        let minimal = h("08 96 01 12 02 18 01");
        let (out, stats) = canonical.convert(&minimal).unwrap();
        assert_eq!(stats.converted(), 1);
        assert!(grouped_accepts(&out, Standard::CanonicalMinimal));

        // Tolerant, iff ⇐: every padded word is the designated
        // occurrence's dropped framing (its tag and its length
        // prefix, both two bytes wide) — the conversion authors
        // minimal group framing and the prefix vanishes, so the
        // output closes.
        let tolerant = Converter::new(Standard::Tolerant, DepthLimit::REFERENCE, program);
        let padded_framing = h("92 00 82 00 18 01");
        let (out, stats) = tolerant.convert(&padded_framing).unwrap();
        assert_eq!(stats.converted(), 1);
        assert_eq!(out, h("13 18 01 14"));
        assert!(grouped_accepts(&out, Standard::CanonicalMinimal));

        // Tolerant, iff ⇒: one padded word is NOT converted
        // framing (an undesignated scalar's value) — it rides
        // verbatim, so the output re-ingests tolerantly but does
        // not close.
        let padded_value = h("08 96 81 00 12 02 18 01");
        let (out, stats) = tolerant.convert(&padded_value).unwrap();
        assert_eq!(stats.converted(), 1);
        assert!(grouped_accepts(&out, Standard::Tolerant));
        assert!(!grouped_accepts(&out, Standard::CanonicalMinimal));

        // Tolerant, iff ⇒, inside a designated interior: group
        // bodies are in-band in the output dialect, so a padded
        // word inside the converted occurrence stays visible to
        // the canonical judge and still breaks closure — the
        // asymmetry against the groupless cell's opaque bodies.
        let padded_designated = h("12 03 18 81 00");
        let (out, stats) = tolerant.convert(&padded_designated).unwrap();
        assert_eq!(stats.converted(), 1);
        assert_eq!(out, h("13 18 81 00 14"));
        assert!(grouped_accepts(&out, Standard::Tolerant));
        assert!(!grouped_accepts(&out, Standard::CanonicalMinimal));
    }
}

markup_reemit!(
    grouped_markup_law,
    protobuf_edit::markup::grouped::Markup,
    protobuf_edit::markup::grouped::InsertAt,
    |bytes| {
        use protobuf_edit::scan::grouped::Validator;
        use protobuf_edit::scan::Standard;
        let mut v = Validator::new(Standard::Tolerant, DepthLimit::REFERENCE);
        v.feed(bytes).is_ok() && v.finish().is_ok()
    },
    |bytes| {
        use protobuf_edit::scan::grouped::Validator;
        use protobuf_edit::scan::Standard;
        let mut v = Validator::new(Standard::CanonicalMinimal, DepthLimit::REFERENCE);
        v.feed(bytes).is_ok() && v.finish().is_ok()
    }
);

markup_reemit!(
    groupless_markup_law,
    protobuf_edit::markup::groupless::Markup,
    protobuf_edit::markup::groupless::InsertAt,
    |bytes| {
        use protobuf_edit::scan::groupless::Validator;
        use protobuf_edit::scan::Standard;
        let mut v = Validator::new(Standard::Tolerant);
        v.feed(bytes).is_ok() && v.finish().is_ok()
    },
    |bytes| {
        use protobuf_edit::scan::groupless::Validator;
        use protobuf_edit::scan::Standard;
        let mut v = Validator::new(Standard::CanonicalMinimal);
        v.feed(bytes).is_ok() && v.finish().is_ok()
    }
);

// ─── the canonical-output family ───

/// The three canonical faces on one machine must agree: the fresh
/// buffer, the suffix `_into` appends behind an untouched sentinel
/// prefix, and the concatenation of the non-empty slices `_sink`
/// hands over are byte-identical. Evaluates to the fresh bytes.
macro_rules! assert_canonical_faces_agree {
    ($machine:expr, $expect:expr) => {{
        let machine = &$machine;
        let expect = $expect;
        let fresh = machine.save_canonical().unwrap();
        assert_eq!(fresh[..], expect[..], "the fresh canonical save");
        let mut appended = vec![0xAA, 0xBB];
        machine.save_canonical_into(&mut appended).unwrap();
        assert_eq!(appended[..2], [0xAA, 0xBB], "the sentinel prefix survives");
        assert_eq!(appended[2..], fresh[..], "the into-suffix agrees with the fresh save");
        let mut chunks: Vec<Vec<u8>> = Vec::new();
        machine.save_canonical_sink(|slice| chunks.push(slice.to_vec())).unwrap();
        assert!(chunks.iter().all(|chunk| !chunk.is_empty()), "sink slices are non-empty");
        assert_eq!(chunks.concat(), fresh, "the sink concatenation agrees with the fresh save");
        fresh
    }};
}

/// The canonical-output battery on one tolerant one-shot cell:
/// replacements, insertions, deletion, and a nested edit inside a
/// descended LEN over a padded source; the faces agree, the fidelity
/// reading is untouched around the canonical calls, the output
/// closes under `CanonicalMinimal`, and re-opening it yields the
/// same live fields, kinds, and values in the same order. The
/// `|src| …` argument is a macro binder, not a closure: the open
/// expression inlines where `src` is a live `&[u8]`, so the
/// machine's payload lifetime stays free.
macro_rules! canonical_editor_rows {
    ($mod_name:ident, $insert_at:path, $descent:path, $kind:path,
     open: |$src:ident| $open:expr, validate_canonical: $validate_canonical:expr) => {
        mod $mod_name {
            use super::*;
            use $descent as Descent;
            use $insert_at as InsertAt;
            use $kind as RecordKind;

            fn closes_canonical(bytes: &[u8]) -> bool {
                let check: fn(&[u8]) -> bool = $validate_canonical;
                check(bytes)
            }

            #[test]
            fn canonical_faces_agree_and_reingest_over_edits() {
                // padded tag · padded value · padded-prefix LEN
                // (descended, nested edit) · LEN replaced by an
                // authored payload of padded-looking bytes · I32
                // (deleted) · I64 (untouched).
                let doc = h("8800 01 10 968100 1A 8300 088100 2A 02 6869 25 EFBEADDE \
                     31 0102030405060708");
                let payload = h("8800");
                let $src = &doc[..];
                let mut m = $open;
                let t: Vec<_> = m.top().collect();
                let Descent::Opened { first: Some(inner) } = m.descend(t[2]).unwrap() else {
                    unreachable!()
                };
                m.set_varint(inner, 300).unwrap();
                m.set_varint(t[0], 7).unwrap();
                m.set_payload(t[3], &payload).unwrap();
                m.delete(t[4]).unwrap();
                m.insert_varint(InsertAt::TailOf(None), f(9), 1).unwrap();

                let fidelity = m.save().unwrap();
                let expect = h("08 07 10 9601 1A 03 08 AC02 2A 02 8800 31 0102030405060708 48 01");
                let fresh = assert_canonical_faces_agree!(m, expect);
                assert_eq!(
                    m.save().unwrap(),
                    fidelity,
                    "the fidelity reading is untouched around canonical calls"
                );
                assert!(closes_canonical(&fresh), "the canonical validator accepts");

                // Re-ingestion: the same live records, in order.
                let $src = &fresh[..];
                let mut reopened = $open;
                let t2: Vec<_> = reopened.top().collect();
                let fields: Vec<u32> =
                    t2.iter().map(|&handle| reopened.field(handle).as_inner()).collect();
                assert_eq!(fields, [1, 2, 3, 5, 6, 9], "live fields in live order");
                let kinds: Vec<_> = t2.iter().map(|&handle| reopened.kind(handle)).collect();
                assert_eq!(
                    kinds,
                    [
                        RecordKind::Varint,
                        RecordKind::Varint,
                        RecordKind::Len,
                        RecordKind::Len,
                        RecordKind::I64,
                        RecordKind::Varint
                    ]
                );
                assert_eq!(reopened.varint_word(t2[0]), Some(7));
                assert_eq!(reopened.varint_word(t2[1]), Some(150));
                let Descent::Opened { first: Some(inner) } = reopened.descend(t2[2]).unwrap()
                else {
                    unreachable!()
                };
                assert_eq!(reopened.varint_word(inner), Some(300));
                assert_eq!(reopened.payload_bytes(t2[3]).unwrap(), &payload[..]);
                assert_eq!(reopened.i64_bits(t2[4]), Some(0x0807_0605_0403_0201));
                assert_eq!(reopened.varint_word(t2[5]), Some(1));
            }
        }
    };
}

canonical_editor_rows!(
    groupless_canonical_patch,
    protobuf_edit::patch::groupless::InsertAt,
    protobuf_edit::patch::groupless::Descent,
    protobuf_edit::wire::groupless::RecordKind,
    open: |src| protobuf_edit::patch::groupless::Patch::open(src, DepthLimit::REFERENCE).unwrap(),
    validate_canonical: |bytes| {
        use protobuf_edit::scan::Standard;
        use protobuf_edit::scan::groupless::Validator;
        let mut v = Validator::new(Standard::CanonicalMinimal);
        v.feed(bytes).is_ok() && v.finish().is_ok()
    }
);

canonical_editor_rows!(
    groupless_canonical_adopt,
    protobuf_edit::adopt::groupless::InsertAt,
    protobuf_edit::adopt::groupless::Descent,
    protobuf_edit::wire::groupless::RecordKind,
    open: |src| protobuf_edit::adopt::groupless::Adopt::open(src.to_vec(), DepthLimit::REFERENCE)
        .unwrap(),
    validate_canonical: |bytes| {
        use protobuf_edit::scan::Standard;
        use protobuf_edit::scan::groupless::Validator;
        let mut v = Validator::new(Standard::CanonicalMinimal);
        v.feed(bytes).is_ok() && v.finish().is_ok()
    }
);

canonical_editor_rows!(
    grouped_canonical_patch,
    protobuf_edit::patch::grouped::InsertAt,
    protobuf_edit::patch::grouped::Descent,
    protobuf_edit::wire::grouped::RecordKind,
    open: |src| protobuf_edit::patch::grouped::Patch::open(src, DepthLimit::REFERENCE).unwrap(),
    validate_canonical: |bytes| {
        use protobuf_edit::scan::Standard;
        use protobuf_edit::scan::grouped::Validator;
        let mut v = Validator::new(Standard::CanonicalMinimal, DepthLimit::REFERENCE);
        v.feed(bytes).is_ok() && v.finish().is_ok()
    }
);

canonical_editor_rows!(
    grouped_canonical_adopt,
    protobuf_edit::adopt::grouped::InsertAt,
    protobuf_edit::adopt::grouped::Descent,
    protobuf_edit::wire::grouped::RecordKind,
    open: |src| protobuf_edit::adopt::grouped::Adopt::open(src.to_vec(), DepthLimit::REFERENCE)
        .unwrap(),
    validate_canonical: |bytes| {
        use protobuf_edit::scan::Standard;
        use protobuf_edit::scan::grouped::Validator;
        let mut v = Validator::new(Standard::CanonicalMinimal, DepthLimit::REFERENCE);
        v.feed(bytes).is_ok() && v.finish().is_ok()
    }
);

/// The one-shot host census: every payload-backing sibling carries
/// the three canonical faces, exercised with a live payload from its
/// own store policy — a compile pin and a behavior judge in one. The
/// `|…| …` arguments are macro binders, not closures (see
/// `canonical_editor_rows`).
macro_rules! canonical_census_row {
    ($test_name:ident, open: |$src:ident| $open:expr,
     set: |$m:ident, $t:ident, $payload:ident, $parts:ident| $set:expr) => {
        #[test]
        fn $test_name() {
            // f2 LEN "hi" behind a padded tag; the replacement
            // payload arrives through this form's own supply.
            let doc = h("9200 02 6869");
            let $payload = h("776F");
            let $parts: [&[u8]; 2] = [&$payload[..1], &$payload[1..]];
            let $src = &doc[..];
            let mut $m = $open;
            let $t = $m.top().next().unwrap();
            $set;
            assert_canonical_faces_agree!($m, h("12 02 776F"));
        }
    };
}

mod canonical_host_census {
    use super::*;

    mod groupless_hosts {
        use super::*;

        canonical_census_row!(
            patch_mixed_scatter,
            open: |src| protobuf_edit::patch::groupless::Patch::open(src, DepthLimit::REFERENCE)
                .unwrap(),
            set: |m, t, _payload, parts| m.set_payload_parts(t, &parts).unwrap()
        );
        canonical_census_row!(
            patch_borrowed,
            open: |src| protobuf_edit::patch::groupless::BorrowPatch::open(
                src,
                DepthLimit::REFERENCE
            )
            .unwrap(),
            set: |m, t, payload, _parts| m.set_payload(t, &payload).unwrap()
        );
        canonical_census_row!(
            patch_copied,
            open: |src| protobuf_edit::patch::groupless::CopyPatch::open(
                src,
                DepthLimit::REFERENCE
            )
            .unwrap(),
            set: |m, t, payload, _parts| m.set_payload(t, &payload).unwrap()
        );
        canonical_census_row!(
            adopt_mixed_scatter,
            open: |src| protobuf_edit::adopt::groupless::Adopt::open(
                src.to_vec(),
                DepthLimit::REFERENCE
            )
            .unwrap(),
            set: |m, t, _payload, parts| m.set_payload_parts(t, &parts).unwrap()
        );
        canonical_census_row!(
            adopt_borrowed,
            open: |src| protobuf_edit::adopt::groupless::BorrowAdopt::open(
                src.to_vec(),
                DepthLimit::REFERENCE
            )
            .unwrap(),
            set: |m, t, payload, _parts| m.set_payload(t, &payload).unwrap()
        );
        canonical_census_row!(
            adopt_copied,
            open: |src| protobuf_edit::adopt::groupless::CopyAdopt::open(
                src.to_vec(),
                DepthLimit::REFERENCE
            )
            .unwrap(),
            set: |m, t, payload, _parts| m.set_payload(t, &payload).unwrap()
        );
    }

    mod grouped_hosts {
        use super::*;

        canonical_census_row!(
            patch_mixed_scatter,
            open: |src| protobuf_edit::patch::grouped::Patch::open(src, DepthLimit::REFERENCE)
                .unwrap(),
            set: |m, t, _payload, parts| m.set_payload_parts(t, &parts).unwrap()
        );
        canonical_census_row!(
            patch_borrowed,
            open: |src| protobuf_edit::patch::grouped::BorrowPatch::open(
                src,
                DepthLimit::REFERENCE
            )
            .unwrap(),
            set: |m, t, payload, _parts| m.set_payload(t, &payload).unwrap()
        );
        canonical_census_row!(
            patch_copied,
            open: |src| protobuf_edit::patch::grouped::CopyPatch::open(src, DepthLimit::REFERENCE)
                .unwrap(),
            set: |m, t, payload, _parts| m.set_payload(t, &payload).unwrap()
        );
        canonical_census_row!(
            adopt_mixed_scatter,
            open: |src| protobuf_edit::adopt::grouped::Adopt::open(
                src.to_vec(),
                DepthLimit::REFERENCE
            )
            .unwrap(),
            set: |m, t, _payload, parts| m.set_payload_parts(t, &parts).unwrap()
        );
        canonical_census_row!(
            adopt_borrowed,
            open: |src| protobuf_edit::adopt::grouped::BorrowAdopt::open(
                src.to_vec(),
                DepthLimit::REFERENCE
            )
            .unwrap(),
            set: |m, t, payload, _parts| m.set_payload(t, &payload).unwrap()
        );
        canonical_census_row!(
            adopt_copied,
            open: |src| protobuf_edit::adopt::grouped::CopyAdopt::open(
                src.to_vec(),
                DepthLimit::REFERENCE
            )
            .unwrap(),
            set: |m, t, payload, _parts| m.set_payload(t, &payload).unwrap()
        );
    }
}

/// The groupless opacity witness: payload bytes that happen to parse
/// as padded words are a declaration, not records — the canonical
/// walk neither speculates nor validates there, and only an explicit
/// successful descend moves the boundary.
mod groupless_opacity_witness {
    use super::*;
    use protobuf_edit::patch::groupless::{Descent, InsertAt, Patch};

    fn closes_canonical(bytes: &[u8]) -> bool {
        use protobuf_edit::scan::Standard;
        use protobuf_edit::scan::groupless::Validator;
        let mut v = Validator::new(Standard::CanonicalMinimal);
        v.feed(bytes).is_ok() && v.finish().is_ok()
    }

    #[test]
    fn undescended_payload_bytes_ride_opaque() {
        let doc = h("12 04 8800 8100");
        let patch = Patch::open(&doc, DepthLimit::REFERENCE).unwrap();
        assert_eq!(
            patch.save_canonical().unwrap(),
            doc,
            "minimal outer framing, untouched payload"
        );

        // Padded outer framing re-derives; the interior still does
        // not open.
        let padded_outer = h("9200 04 8800 8100");
        let patch = Patch::open(&padded_outer, DepthLimit::REFERENCE).unwrap();
        assert_eq!(patch.save_canonical().unwrap(), doc);
    }

    #[test]
    fn a_successful_descent_commits_the_payload() {
        let doc = h("12 04 8800 8100");
        let mut patch = Patch::open(&doc, DepthLimit::REFERENCE).unwrap();
        let len = patch.top().next().unwrap();
        assert!(matches!(patch.descend(len).unwrap(), Descent::Opened { .. }));
        let fresh = patch.save_canonical().unwrap();
        assert_eq!(fresh, h("12 02 08 01"));
        assert!(closes_canonical(&fresh));
    }

    #[test]
    fn faulted_and_refused_descents_do_not_move_the_boundary() {
        // The payload cuts a record short: the descend parks a
        // resident fault and the canonical walk stays outside.
        let cut = h("12 01 08");
        let mut patch = Patch::open(&cut, DepthLimit::REFERENCE).unwrap();
        let len = patch.top().next().unwrap();
        assert!(matches!(patch.descend(len).unwrap(), Descent::Faulted(_)));
        assert_eq!(patch.save_canonical().unwrap(), cut);

        // A group code inside: lawful wire outside this dialect —
        // a resident refusal, and the payload rides opaque.
        let group_inside = h("12 02 0B 0C");
        let mut patch = Patch::open(&group_inside, DepthLimit::REFERENCE).unwrap();
        let len = patch.top().next().unwrap();
        assert!(matches!(patch.descend(len).unwrap(), Descent::Refused(_)));
        assert_eq!(patch.save_canonical().unwrap(), group_inside);
    }

    #[test]
    fn authored_payloads_terminate_the_closure() {
        let doc = h("08 01");
        let payload = h("8800 8100");
        let mut patch = Patch::open(&doc, DepthLimit::REFERENCE).unwrap();
        patch.insert_payload(InsertAt::TailOf(None), f(2), &payload).unwrap();
        assert_eq!(patch.save_canonical().unwrap(), h("08 01 12 04 8800 8100"));
    }
}

/// The grouped canonical asymmetry: group interiors are in-band
/// syntax — padded group framing and padded interior records
/// normalize without any descent — while LEN interiors keep the
/// explicit-descent boundary.
mod grouped_canonical_groups {
    use super::*;
    use protobuf_edit::patch::grouped::{Descent, InsertAt, Patch};

    fn closes_canonical(bytes: &[u8]) -> bool {
        use protobuf_edit::scan::Standard;
        use protobuf_edit::scan::grouped::Validator;
        let mut v = Validator::new(Standard::CanonicalMinimal, DepthLimit::REFERENCE);
        v.feed(bytes).is_ok() && v.finish().is_ok()
    }

    #[test]
    fn padded_group_framing_and_interior_normalize_without_descent() {
        // Both framing tags and the interior LEN prefix are padded;
        // the payload is a blob nothing descends.
        let padded = h("8B00 128100 61 8C8000");
        let patch = Patch::open(&padded, DepthLimit::REFERENCE).unwrap();
        let fresh = patch.save_canonical().unwrap();
        assert_eq!(fresh, h("0B 120161 0C"));
        assert!(closes_canonical(&fresh));
    }

    #[test]
    fn opaque_len_inside_a_group_stays_opaque() {
        let doc = h("0B 12 04 8800 8100 0C");
        let patch = Patch::open(&doc, DepthLimit::REFERENCE).unwrap();
        assert_eq!(patch.save_canonical().unwrap(), doc, "the LEN payload is a declaration");

        // The explicit descend commits it; the next canonical save
        // normalizes the committed records.
        let mut patch = Patch::open(&doc, DepthLimit::REFERENCE).unwrap();
        let group = patch.top().next().unwrap();
        let len = patch.children(group).next().unwrap();
        assert!(matches!(patch.descend(len).unwrap(), Descent::Opened { .. }));
        assert_eq!(patch.save_canonical().unwrap(), h("0B 12 02 08 01 0C"));
    }

    #[test]
    fn edited_and_authored_groups_emit_minimal_framing() {
        // Editing inside a padded group: the faces agree and the
        // whole record — framing included — re-emits minimally.
        let padded = h("8B00 18 8100 8C8000");
        let mut patch = Patch::open(&padded, DepthLimit::REFERENCE).unwrap();
        let group = patch.top().next().unwrap();
        let inner = patch.children(group).next().unwrap();
        patch.set_varint(inner, 5).unwrap();
        let fresh = assert_canonical_faces_agree!(patch, h("0B 18 05 0C"));
        assert!(closes_canonical(&fresh));

        // An authored group emits minimal framing on both sides.
        let doc = h("08 01");
        let mut patch = Patch::open(&doc, DepthLimit::REFERENCE).unwrap();
        let group = patch.insert_group(InsertAt::TailOf(None), f(2)).unwrap();
        patch.insert_varint(InsertAt::TailOf(Some(group)), f(3), 5).unwrap();
        assert_eq!(patch.save_canonical().unwrap(), h("08 01 13 18 05 14"));
    }
}

/// The canonical-output battery on one tolerant revisable cell: the
/// same edit script over the same padded source as the one-shot
/// rows, the three faces agreeing, the read-face purity pins
/// (`pending`, statuses, spans, and the fidelity bytes identical
/// around every canonical call), canonical closure, re-ingestion —
/// and the revision leg: `revert_all` restores fidelity to the
/// source byte-exactly while the canonical face keeps normalizing
/// the (still materialized) closure.
macro_rules! canonical_revisable_rows {
    ($mod_name:ident, $insert_at:path, $descent:path, $kind:path,
     open: |$src:ident| $open:expr, validate_canonical: $validate_canonical:expr) => {
        mod $mod_name {
            use super::*;
            use $descent as Descent;
            use $insert_at as InsertAt;
            use $kind as RecordKind;

            fn closes_canonical(bytes: &[u8]) -> bool {
                let check: fn(&[u8]) -> bool = $validate_canonical;
                check(bytes)
            }

            #[test]
            fn canonical_faces_agree_reingest_and_revert() {
                let doc = h("8800 01 10 968100 1A 8300 088100 2A 02 6869 25 EFBEADDE \
                     31 0102030405060708");
                let payload = h("8800");
                let $src = &doc[..];
                let mut m = $open;
                let t: Vec<_> = m.top().collect();
                let Descent::Opened { first: Some(inner) } = m.descend(t[2]).unwrap() else {
                    unreachable!()
                };
                m.set_varint(inner, 300).unwrap();
                m.set_varint(t[0], 7).unwrap();
                m.set_payload(t[3], &payload).unwrap();
                m.delete(t[4]).unwrap();
                m.insert_varint(InsertAt::TailOf(None), f(9), 1).unwrap();

                // The read-face purity fingerprint: undo depth, every
                // status, every source span, the fidelity bytes.
                macro_rules! purity {
                    () => {
                        (
                            m.pending(),
                            t.iter()
                                .map(|&handle| format!("{:?}", m.status(handle)))
                                .collect::<Vec<_>>(),
                            t.iter()
                                .map(|&handle| format!("{:?}", m.span(handle)))
                                .collect::<Vec<_>>(),
                            m.save().unwrap(),
                        )
                    };
                }
                let before = purity!();
                let expect = h("08 07 10 9601 1A 03 08 AC02 2A 02 8800 31 0102030405060708 48 01");
                let fresh = assert_canonical_faces_agree!(m, expect);
                assert_eq!(purity!(), before, "read-face purity around canonical calls");
                assert!(closes_canonical(&fresh), "the canonical validator accepts");

                // Re-ingestion: the same live records, in order.
                let $src = &fresh[..];
                let mut reopened = $open;
                let t2: Vec<_> = reopened.top().collect();
                let fields: Vec<u32> =
                    t2.iter().map(|&handle| reopened.field(handle).unwrap().as_inner()).collect();
                assert_eq!(fields, [1, 2, 3, 5, 6, 9], "live fields in live order");
                let kinds: Vec<_> =
                    t2.iter().map(|&handle| reopened.kind(handle).unwrap()).collect();
                assert_eq!(
                    kinds,
                    [
                        RecordKind::Varint,
                        RecordKind::Varint,
                        RecordKind::Len,
                        RecordKind::Len,
                        RecordKind::I64,
                        RecordKind::Varint
                    ]
                );
                assert_eq!(reopened.varint_word(t2[0]).unwrap(), 7);
                assert_eq!(reopened.varint_word(t2[1]).unwrap(), 150);
                let Descent::Opened { first: Some(inner) } = reopened.descend(t2[2]).unwrap()
                else {
                    unreachable!()
                };
                assert_eq!(reopened.varint_word(inner).unwrap(), 300);
                assert_eq!(reopened.payload_bytes(t2[3]).unwrap(), &payload[..]);
                assert_eq!(reopened.i64_bits(t2[4]).unwrap(), 0x0807_0605_0403_0201);
                assert_eq!(reopened.varint_word(t2[5]).unwrap(), 1);

                // The revision leg: fidelity returns to the source
                // byte-exactly; the canonical face keeps normalizing
                // the still-materialized closure.
                m.revert_all();
                assert_eq!(m.save().unwrap(), doc, "revert_all restores fidelity");
                assert_eq!(
                    m.save_canonical().unwrap(),
                    h("0801 109601 1A020801 2A026869 25EFBEADDE 310102030405060708"),
                    "the reverted closure still normalizes"
                );
            }
        }
    };
}

canonical_revisable_rows!(
    groupless_canonical_draft,
    protobuf_edit::draft::groupless::InsertAt,
    protobuf_edit::draft::groupless::Descent,
    protobuf_edit::wire::groupless::RecordKind,
    open: |src| protobuf_edit::draft::groupless::Draft::open_copy(src).unwrap(),
    validate_canonical: |bytes| {
        use protobuf_edit::scan::Standard;
        use protobuf_edit::scan::groupless::Validator;
        let mut v = Validator::new(Standard::CanonicalMinimal);
        v.feed(bytes).is_ok() && v.finish().is_ok()
    }
);

canonical_revisable_rows!(
    grouped_canonical_draft,
    protobuf_edit::draft::grouped::InsertAt,
    protobuf_edit::draft::grouped::Descent,
    protobuf_edit::wire::grouped::RecordKind,
    open: |src| protobuf_edit::draft::grouped::Draft::open_copy(src).unwrap(),
    validate_canonical: |bytes| {
        use protobuf_edit::scan::Standard;
        use protobuf_edit::scan::grouped::Validator;
        let mut v = Validator::new(Standard::CanonicalMinimal, DepthLimit::REFERENCE);
        v.feed(bytes).is_ok() && v.finish().is_ok()
    }
);

canonical_revisable_rows!(
    groupless_canonical_markup,
    protobuf_edit::markup::groupless::InsertAt,
    protobuf_edit::markup::groupless::Descent,
    protobuf_edit::wire::groupless::RecordKind,
    open: |src| protobuf_edit::markup::groupless::Markup::open(src).unwrap(),
    validate_canonical: |bytes| {
        use protobuf_edit::scan::Standard;
        use protobuf_edit::scan::groupless::Validator;
        let mut v = Validator::new(Standard::CanonicalMinimal);
        v.feed(bytes).is_ok() && v.finish().is_ok()
    }
);

canonical_revisable_rows!(
    grouped_canonical_markup,
    protobuf_edit::markup::grouped::InsertAt,
    protobuf_edit::markup::grouped::Descent,
    protobuf_edit::wire::grouped::RecordKind,
    open: |src| protobuf_edit::markup::grouped::Markup::open(src).unwrap(),
    validate_canonical: |bytes| {
        use protobuf_edit::scan::Standard;
        use protobuf_edit::scan::grouped::Validator;
        let mut v = Validator::new(Standard::CanonicalMinimal, DepthLimit::REFERENCE);
        v.feed(bytes).is_ok() && v.finish().is_ok()
    }
);

/// The revisable host census: both payload-backing siblings of both
/// revisable cells carry the three canonical faces, exercised with a
/// live payload from each form's own store policy.
mod canonical_revisable_census {
    use super::*;

    mod groupless_hosts {
        use super::*;

        canonical_census_row!(
            draft_copied,
            open: |src| protobuf_edit::draft::groupless::Draft::open_copy(src).unwrap(),
            set: |m, t, payload, _parts| m.set_payload(t, &payload).unwrap()
        );
        canonical_census_row!(
            draft_borrowed,
            open: |src| protobuf_edit::draft::groupless::BorrowDraft::open_copy(src).unwrap(),
            set: |m, t, payload, _parts| m.set_payload(t, &payload).unwrap()
        );
        canonical_census_row!(
            markup_copied,
            open: |src| protobuf_edit::markup::groupless::Markup::open(src).unwrap(),
            set: |m, t, payload, _parts| m.set_payload(t, &payload).unwrap()
        );
        canonical_census_row!(
            markup_borrowed,
            open: |src| protobuf_edit::markup::groupless::BorrowMarkup::open(src).unwrap(),
            set: |m, t, payload, _parts| m.set_payload(t, &payload).unwrap()
        );
    }

    mod grouped_hosts {
        use super::*;

        canonical_census_row!(
            draft_copied,
            open: |src| protobuf_edit::draft::grouped::Draft::open_copy(src).unwrap(),
            set: |m, t, payload, _parts| m.set_payload(t, &payload).unwrap()
        );
        canonical_census_row!(
            draft_borrowed,
            open: |src| protobuf_edit::draft::grouped::BorrowDraft::open_copy(src).unwrap(),
            set: |m, t, payload, _parts| m.set_payload(t, &payload).unwrap()
        );
        canonical_census_row!(
            markup_copied,
            open: |src| protobuf_edit::markup::grouped::Markup::open(src).unwrap(),
            set: |m, t, payload, _parts| m.set_payload(t, &payload).unwrap()
        );
        canonical_census_row!(
            markup_borrowed,
            open: |src| protobuf_edit::markup::grouped::BorrowMarkup::open(src).unwrap(),
            set: |m, t, payload, _parts| m.set_payload(t, &payload).unwrap()
        );
    }
}
