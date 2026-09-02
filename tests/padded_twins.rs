//! The tolerant domain's offline value pin: padding changes
//! encoding geometry, never the value reading, so every padded
//! document renders exactly as its canonical twin.
//!
//! Inputs live in `support/padded.rs` — no reference process and
//! no frozen corpus in the loop, so this arm runs everywhere the
//! battery runs (CI included) and under Miri. The live arm
//! (`protoc_live`) reads the same documents against libprotoc.

#![cfg(any(feature = "inspect-grouped", feature = "inspect-groupless"))]

use protobuf_edit::DepthLimit;
use protobuf_edit::inspect::{Admitted, NoAdvice};

#[path = "support/padded.rs"]
mod padded;
#[path = "support/render.rs"]
mod render;

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

#[cfg(feature = "inspect-grouped")]
mod grouped_dialect {
    use protobuf_edit::inspect::NodeId;
    use protobuf_edit::inspect::grouped::Tree;
    use protobuf_edit::wire::grouped::RecordKind;

    use super::padded::LenReading;
    use super::render::grouped::render;
    use super::*;

    /// True when any record in the tree is a group — the byte fact
    /// the padded batch's `groupless` flag claims to track.
    fn contains_group(tree: &Tree<'_>) -> bool {
        tree.top()
            .flat_map(|id| std::iter::once(id).chain(tree.descendants(id)))
            .any(|id| matches!(tree.kind(id), RecordKind::Group))
    }

    /// Collects every LEN's machine reading in parse order — the
    /// renderer's own discriminator (children present = message),
    /// sound here because the pin below refuses empty payloads.
    fn collect_lens(tree: &Tree<'_>, id: NodeId, out: &mut Vec<LenReading>) {
        if matches!(tree.kind(id), RecordKind::Len) {
            assert!(
                !tree.payload_bytes(id).is_empty(),
                "the witness discriminator needs non-empty LEN payloads"
            );
            out.push(if tree.children(id).next().is_some() {
                LenReading::Message
            } else {
                LenReading::Bytes
            });
        }
        for child in tree.children(id) {
            collect_lens(tree, child, out);
        }
    }

    /// Every LEN payload's reading is declared on its document and
    /// judged by the machine on the padded bytes and the twin
    /// alike: a message payload parses completely under
    /// speculation, a blob payload faults it — so the batch stays
    /// out of the guess band by construction, and a drifted case
    /// (a payload wandering into ambiguity) moves a reading and
    /// goes red here instead of silently narrowing the oracle's
    /// range.
    #[test]
    fn len_readings_match_their_declared_witnesses() {
        let docs = padded::DOCS;
        assert_eq!(docs.len(), 12, "padded census drifted");
        let mut lens_seen = 0;
        for doc in docs {
            for (side, hex) in [("padded", doc.padded), ("twin", doc.twin)] {
                let bytes = unhex(hex);
                let tree = Tree::parse(
                    Admitted::new(&bytes).unwrap(),
                    DepthLimit::REFERENCE,
                    &mut NoAdvice,
                );
                assert!(tree.is_complete(), "{}/{side}: parse faulted", doc.name);
                let mut readings = Vec::new();
                for top in tree.top() {
                    collect_lens(&tree, top, &mut readings);
                }
                assert_eq!(
                    readings, doc.lens,
                    "{}/{side}: the machine's LEN readings left the witness",
                    doc.name
                );
                lens_seen += readings.len();
            }
        }
        assert!(lens_seen >= 14, "the witness walk judged only {lens_seen} LENs");
    }

    /// Padding changes encoding geometry, never the value reading:
    /// every padded document renders exactly as its canonical twin.
    #[test]
    fn padded_documents_render_as_their_canonical_twins() {
        let docs = padded::DOCS;
        assert_eq!(docs.len(), 12, "padded census drifted");
        for doc in docs {
            let padded = unhex(doc.padded);
            let twin = unhex(doc.twin);
            assert_ne!(padded, twin, "{}: the pair must differ in geometry", doc.name);
            let padded_tree =
                Tree::parse(Admitted::new(&padded).unwrap(), DepthLimit::REFERENCE, &mut NoAdvice);
            let twin_tree =
                Tree::parse(Admitted::new(&twin).unwrap(), DepthLimit::REFERENCE, &mut NoAdvice);
            assert!(
                padded_tree.is_complete(),
                "{}: padded parse faulted: {:?}",
                doc.name,
                padded_tree.fault()
            );
            assert!(
                twin_tree.is_complete(),
                "{}: twin parse faulted: {:?}",
                doc.name,
                twin_tree.fault()
            );
            // The groupless flag claims a byte fact this dialect can
            // judge: the pair carries group records iff the flag
            // routes it away from the groupless dialect.
            assert_eq!(
                contains_group(&padded_tree),
                !doc.groupless,
                "{}: the groupless flag contradicts the padded bytes",
                doc.name
            );
            assert_eq!(
                contains_group(&twin_tree),
                !doc.groupless,
                "{}: the groupless flag contradicts the twin bytes",
                doc.name
            );
            assert_eq!(
                render(&padded_tree),
                render(&twin_tree),
                "{}: padding moved the value reading",
                doc.name
            );
        }
    }
}

/// The draft's fidelity identity over the curated corpus: every
/// padded document opens under tolerant admission and saves
/// byte-exactly — padding included — through every output face.
#[cfg(all(feature = "draft-grouped", feature = "draft-groupless"))]
mod draft_fidelity {
    use super::*;

    #[test]
    fn padded_documents_ride_draft_saves_verbatim() {
        let docs = padded::DOCS;
        assert_eq!(docs.len(), 12, "padded census drifted");
        for doc in docs {
            for hex in [doc.padded, doc.twin] {
                let bytes = unhex(hex);
                {
                    use protobuf_edit::draft::grouped::Draft;
                    let draft = Draft::open(bytes.clone())
                        .unwrap_or_else(|(_, fault)| panic!("{}: {fault}", doc.name));
                    assert_eq!(draft.save().unwrap(), bytes, "{}: grouped fidelity", doc.name);
                    assert_eq!(draft.save_len().unwrap() as usize, bytes.len());
                    let mut streamed = Vec::new();
                    draft.save_sink(|s| streamed.extend_from_slice(s)).unwrap();
                    assert_eq!(streamed, bytes, "{}: grouped sink fidelity", doc.name);
                }
                if doc.groupless {
                    use protobuf_edit::draft::groupless::Draft;
                    let draft = Draft::open(bytes.clone())
                        .unwrap_or_else(|(_, fault)| panic!("{}: {fault}", doc.name));
                    assert_eq!(draft.save().unwrap(), bytes, "{}: groupless fidelity", doc.name);
                    assert_eq!(draft.into_source(), bytes, "{}: tenure release", doc.name);
                }
            }
        }
    }
}

/// The borrowed-payload draft over the same corpus: padded framing
/// rides saves byte-exactly around borrowed installs — the
/// copy-only draft is the oracle for the edited reading, and
/// reverting every command restores the padded source exactly.
#[cfg(all(feature = "draft-grouped", feature = "draft-groupless"))]
mod borrow_draft_fidelity {
    use super::*;

    #[test]
    fn borrowed_installs_ride_padded_documents_in_lockstep() {
        let docs = padded::DOCS;
        assert_eq!(docs.len(), 12, "padded census drifted");
        let body = [0x08u8, 0x2A];
        for doc in docs {
            for hex in [doc.padded, doc.twin] {
                let bytes = unhex(hex);
                {
                    use protobuf_edit::draft::grouped::{BorrowDraft, Draft, InsertAt};
                    use protobuf_edit::wire::grouped::RecordKind;
                    let mut copy = Draft::open(bytes.clone())
                        .unwrap_or_else(|(_, fault)| panic!("{}: {fault}", doc.name));
                    let mut borrow = BorrowDraft::open(bytes.clone())
                        .unwrap_or_else(|(_, fault)| panic!("{}: {fault}", doc.name));
                    // Replace the first LEN payload, if the
                    // document has one, with a borrowed install.
                    let target =
                        copy.top().find(|handle| copy.kind(*handle) == Ok(RecordKind::Len));
                    if let Some(record) = target {
                        copy.set_payload(record, &body).unwrap();
                        borrow.set_payload(record, &body).unwrap();
                    }
                    // Author one record beside the padded ones.
                    let field = protobuf_edit::FieldNumber::new(9).unwrap();
                    copy.insert_payload(InsertAt::TailOf(None), field, &body).unwrap();
                    borrow.insert_payload(InsertAt::TailOf(None), field, &body).unwrap();
                    assert_eq!(
                        copy.save().unwrap(),
                        borrow.save().unwrap(),
                        "{}: grouped lockstep",
                        doc.name
                    );
                    // Reverting everything restores the padded
                    // source byte-exactly.
                    borrow.revert_all();
                    assert_eq!(borrow.save().unwrap(), bytes, "{}: grouped revert-all", doc.name);
                }
                if doc.groupless {
                    use protobuf_edit::draft::groupless::{BorrowDraft, Draft, InsertAt};
                    use protobuf_edit::wire::groupless::RecordKind;
                    let mut copy = Draft::open(bytes.clone())
                        .unwrap_or_else(|(_, fault)| panic!("{}: {fault}", doc.name));
                    let mut borrow = BorrowDraft::open(bytes.clone())
                        .unwrap_or_else(|(_, fault)| panic!("{}: {fault}", doc.name));
                    let target =
                        copy.top().find(|handle| copy.kind(*handle) == Ok(RecordKind::Len));
                    if let Some(record) = target {
                        copy.set_payload(record, &body).unwrap();
                        borrow.set_payload(record, &body).unwrap();
                    }
                    let field = protobuf_edit::FieldNumber::new(9).unwrap();
                    copy.insert_payload(InsertAt::TailOf(None), field, &body).unwrap();
                    borrow.insert_payload(InsertAt::TailOf(None), field, &body).unwrap();
                    assert_eq!(
                        copy.save().unwrap(),
                        borrow.save().unwrap(),
                        "{}: groupless lockstep",
                        doc.name
                    );
                    borrow.revert_all();
                    assert_eq!(borrow.save().unwrap(), bytes, "{}: groupless revert-all", doc.name);
                }
            }
        }
    }
}

/// The markup's fidelity identity over the same corpus: the
/// borrowed twin of the draft check — every padded document opens
/// with zero copies and saves byte-exactly, padding included.
#[cfg(all(feature = "markup-grouped", feature = "markup-groupless"))]
mod markup_fidelity {
    use super::*;

    #[test]
    fn padded_documents_ride_markup_saves_verbatim() {
        let docs = padded::DOCS;
        assert_eq!(docs.len(), 12, "padded census drifted");
        for doc in docs {
            for hex in [doc.padded, doc.twin] {
                let bytes = unhex(hex);
                {
                    use protobuf_edit::markup::grouped::Markup;
                    let markup = Markup::open(&bytes)
                        .unwrap_or_else(|fault| panic!("{}: {fault}", doc.name));
                    assert_eq!(markup.save().unwrap(), bytes, "{}: grouped fidelity", doc.name);
                    assert_eq!(markup.save_len().unwrap() as usize, bytes.len());
                    let mut streamed = Vec::new();
                    markup.save_sink(|s| streamed.extend_from_slice(s)).unwrap();
                    assert_eq!(streamed, bytes, "{}: grouped sink fidelity", doc.name);
                }
                if doc.groupless {
                    use protobuf_edit::markup::groupless::Markup;
                    let markup = Markup::open(&bytes)
                        .unwrap_or_else(|fault| panic!("{}: {fault}", doc.name));
                    assert_eq!(markup.save().unwrap(), bytes, "{}: groupless fidelity", doc.name);
                    assert_eq!(markup.source(), bytes, "{}: the borrow answers", doc.name);
                }
            }
        }
    }
}

/// The amend's canonical door over the same corpus, borrowed: the
/// refusal is a plain fault (nothing to hand back — the caller
/// never let go of the buffer); padding hidden inside an opaque
/// LEN payload opens, refuses at the descent that first meets it,
/// and the untouched document still saves verbatim. Twins open and
/// ride every save face byte-exactly.
#[cfg(all(feature = "amend-grouped", feature = "amend-groupless"))]
mod amend_fidelity {
    use super::*;

    /// Docs whose padding hides inside an opaque LEN payload: the
    /// door's scan cannot see it, so the open succeeds and the
    /// refusal moves to descent.
    const DOOR_BLIND: &[&str] = &[
        "nested_len_prefix_widened",
        "cascade_len_prefix_two_levels",
        "nested_blob_prefix_widened",
    ];

    macro_rules! canonical_door_pin {
        ($test:ident, $machine:path, $descent:path, $kind:path, $grouped:expr) => {
            #[test]
            fn $test() {
                use $descent as Descent;
                use $kind as RecordKind;
                use $machine as Amend;

                /// Walks LEN payloads depth-first until one descent
                /// meets the hidden padding.
                fn descent_refuses(amend: &mut Amend<'_, '_>) -> bool {
                    let mut stack: Vec<_> = amend.top().collect();
                    while let Some(handle) = stack.pop() {
                        if matches!(amend.kind(handle), RecordKind::Len) {
                            match amend.descend(handle).unwrap() {
                                Descent::Refused(_) => return true,
                                Descent::Faulted(_) => {}
                                Descent::Opened { .. } => stack.extend(amend.children(handle)),
                            }
                        }
                    }
                    false
                }

                let docs = padded::DOCS;
                assert_eq!(docs.len(), 12, "padded census drifted");
                let mut refused = 0;
                for doc in docs {
                    if !$grouped && !doc.groupless {
                        continue;
                    }
                    let padded = unhex(doc.padded);
                    let twin = unhex(doc.twin);
                    let blind = DOOR_BLIND.contains(&doc.name);

                    match Amend::open(&padded, DepthLimit::REFERENCE) {
                        Err(_fault) => {
                            assert!(!blind, "{}: the door saw hidden padding", doc.name);
                            refused += 1;
                        }
                        Ok(mut amend) => {
                            assert!(blind, "{}: scanned padding must refuse at open", doc.name);
                            assert!(
                                descent_refuses(&mut amend),
                                "{}: no descent met the hidden padding",
                                doc.name
                            );
                            assert_eq!(amend.save().unwrap(), padded, "{}: fidelity", doc.name);
                        }
                    }

                    let amend = Amend::open(&twin, DepthLimit::REFERENCE)
                        .unwrap_or_else(|fault| panic!("{}: twin refused: {fault}", doc.name));
                    assert_eq!(amend.save().unwrap(), twin, "{}: twin fidelity", doc.name);
                    assert_eq!(amend.save_len().unwrap() as usize, twin.len());
                    let mut streamed = Vec::new();
                    amend.save_sink(|s| streamed.extend_from_slice(s)).unwrap();
                    assert_eq!(streamed, twin, "{}: twin sink fidelity", doc.name);
                    assert_eq!(amend.source(), twin, "{}: the borrow is the caller's", doc.name);
                }
                assert!(refused >= 7, "the door refused only {refused} padded documents");
            }
        };
    }

    canonical_door_pin!(
        grouped_padded_documents_refuse_the_door_and_twins_ride_verbatim,
        protobuf_edit::amend::grouped::Amend,
        protobuf_edit::amend::grouped::Descent,
        protobuf_edit::wire::grouped::RecordKind,
        true
    );
    canonical_door_pin!(
        groupless_padded_documents_refuse_the_door_and_twins_ride_verbatim,
        protobuf_edit::amend::groupless::Amend,
        protobuf_edit::amend::groupless::Descent,
        protobuf_edit::wire::groupless::RecordKind,
        false
    );
}

/// The review's canonical door over the same corpus, borrowed and
/// revisable: the refusal is a plain fault (nothing to hand back —
/// the caller never let go of the buffer); padding hidden inside
/// an opaque LEN payload opens, refuses at the descent that first
/// meets it, and the untouched document still saves verbatim.
/// Twins open and ride every save face byte-exactly.
#[cfg(all(feature = "review-grouped", feature = "review-groupless"))]
mod review_fidelity {
    use super::*;

    /// Docs whose padding hides inside an opaque LEN payload: the
    /// door's scan cannot see it, so the open succeeds and the
    /// refusal moves to descent.
    const DOOR_BLIND: &[&str] = &[
        "nested_len_prefix_widened",
        "cascade_len_prefix_two_levels",
        "nested_blob_prefix_widened",
    ];

    macro_rules! canonical_door_pin {
        ($test:ident, $machine:path, $descent:path, $kind:path, $grouped:expr) => {
            #[test]
            fn $test() {
                use $descent as Descent;
                use $kind as RecordKind;
                use $machine as Review;

                /// Walks LEN payloads depth-first until one descent
                /// meets the hidden padding.
                fn descent_refuses(review: &mut Review<'_>) -> bool {
                    let mut stack: Vec<_> = review.top().collect();
                    while let Some(handle) = stack.pop() {
                        if matches!(review.kind(handle), Ok(RecordKind::Len)) {
                            match review.descend(handle).unwrap() {
                                Descent::Refused(_) => return true,
                                Descent::Faulted(_) => {}
                                Descent::Opened { .. } => {
                                    stack.extend(review.children(handle).expect("opened"));
                                }
                            }
                        }
                    }
                    false
                }

                let docs = padded::DOCS;
                assert_eq!(docs.len(), 12, "padded census drifted");
                let mut refused = 0;
                for doc in docs {
                    if !$grouped && !doc.groupless {
                        continue;
                    }
                    let padded = unhex(doc.padded);
                    let twin = unhex(doc.twin);
                    let blind = DOOR_BLIND.contains(&doc.name);

                    match Review::open(&padded) {
                        Err(_fault) => {
                            assert!(!blind, "{}: the door saw hidden padding", doc.name);
                            refused += 1;
                        }
                        Ok(mut review) => {
                            assert!(blind, "{}: scanned padding must refuse at open", doc.name);
                            assert!(
                                descent_refuses(&mut review),
                                "{}: no descent met the hidden padding",
                                doc.name
                            );
                            assert_eq!(review.save().unwrap(), padded, "{}: fidelity", doc.name);
                        }
                    }

                    let review = Review::open(&twin)
                        .unwrap_or_else(|fault| panic!("{}: twin refused: {fault}", doc.name));
                    assert_eq!(review.save().unwrap(), twin, "{}: twin fidelity", doc.name);
                    assert_eq!(review.save_len().unwrap() as usize, twin.len());
                    let mut streamed = Vec::new();
                    review.save_sink(|s| streamed.extend_from_slice(s)).unwrap();
                    assert_eq!(streamed, twin, "{}: twin sink fidelity", doc.name);
                    assert_eq!(review.source(), twin, "{}: the borrow is the caller's", doc.name);
                }
                assert!(refused >= 7, "the door refused only {refused} padded documents");
            }
        };
    }

    canonical_door_pin!(
        grouped_padded_documents_refuse_the_door_and_twins_ride_verbatim,
        protobuf_edit::review::grouped::Review,
        protobuf_edit::review::grouped::Descent,
        protobuf_edit::wire::grouped::RecordKind,
        true
    );
    canonical_door_pin!(
        groupless_padded_documents_refuse_the_door_and_twins_ride_verbatim,
        protobuf_edit::review::groupless::Review,
        protobuf_edit::review::groupless::Descent,
        protobuf_edit::wire::groupless::RecordKind,
        false
    );
}

/// The intake's canonical door over the same corpus: padding the
/// scan meets refuses at open with the buffer returned intact;
/// padding hidden inside an opaque LEN payload opens, refuses at
/// the descent that first meets it, and the untouched document
/// still saves verbatim. Twins open and ride every save face
/// byte-exactly.
#[cfg(all(feature = "intake-grouped", feature = "intake-groupless"))]
mod intake_fidelity {
    use super::*;

    /// Docs whose padding hides inside an opaque LEN payload: the
    /// door's scan cannot see it, so the open succeeds and the
    /// refusal moves to descent.
    const DOOR_BLIND: &[&str] = &[
        "nested_len_prefix_widened",
        "cascade_len_prefix_two_levels",
        "nested_blob_prefix_widened",
    ];

    macro_rules! canonical_door_pin {
        ($test:ident, $machine:path, $descent:path, $kind:path, $grouped:expr) => {
            #[test]
            fn $test() {
                use $descent as Descent;
                use $kind as RecordKind;
                use $machine as Intake;

                /// Walks LEN payloads depth-first until one descent
                /// meets the hidden padding.
                fn descent_refuses(intake: &mut Intake<'_>) -> bool {
                    let mut stack: Vec<_> = intake.top().collect();
                    while let Some(handle) = stack.pop() {
                        if matches!(intake.kind(handle), RecordKind::Len) {
                            match intake.descend(handle).unwrap() {
                                Descent::Refused(_) => return true,
                                Descent::Faulted(_) => {}
                                Descent::Opened { .. } => stack.extend(intake.children(handle)),
                            }
                        }
                    }
                    false
                }

                let docs = padded::DOCS;
                assert_eq!(docs.len(), 12, "padded census drifted");
                let mut refused = 0;
                for doc in docs {
                    if !$grouped && !doc.groupless {
                        continue;
                    }
                    let padded = unhex(doc.padded);
                    let twin = unhex(doc.twin);
                    let blind = DOOR_BLIND.contains(&doc.name);

                    match Intake::open(padded.clone(), DepthLimit::REFERENCE) {
                        Err((back, _fault)) => {
                            assert!(!blind, "{}: the door saw hidden padding", doc.name);
                            assert_eq!(back, padded, "{}: the buffer rides back intact", doc.name);
                            refused += 1;
                        }
                        Ok(mut intake) => {
                            assert!(blind, "{}: scanned padding must refuse at open", doc.name);
                            assert!(
                                descent_refuses(&mut intake),
                                "{}: no descent met the hidden padding",
                                doc.name
                            );
                            assert_eq!(intake.save().unwrap(), padded, "{}: fidelity", doc.name);
                        }
                    }

                    let intake = Intake::open(twin.clone(), DepthLimit::REFERENCE)
                        .unwrap_or_else(|(_, fault)| panic!("{}: twin refused: {fault}", doc.name));
                    assert_eq!(intake.save().unwrap(), twin, "{}: twin fidelity", doc.name);
                    assert_eq!(intake.save_len().unwrap() as usize, twin.len());
                    let mut streamed = Vec::new();
                    intake.save_sink(|s| streamed.extend_from_slice(s)).unwrap();
                    assert_eq!(streamed, twin, "{}: twin sink fidelity", doc.name);
                    assert_eq!(intake.into_source(), twin, "{}: tenure release", doc.name);
                }
                assert!(refused >= 7, "the door refused only {refused} padded documents");
            }
        };
    }

    canonical_door_pin!(
        grouped_padded_documents_refuse_the_door_and_twins_ride_verbatim,
        protobuf_edit::intake::grouped::Intake,
        protobuf_edit::intake::grouped::Descent,
        protobuf_edit::wire::grouped::RecordKind,
        true
    );
    canonical_door_pin!(
        groupless_padded_documents_refuse_the_door_and_twins_ride_verbatim,
        protobuf_edit::intake::groupless::Intake,
        protobuf_edit::intake::groupless::Descent,
        protobuf_edit::wire::groupless::RecordKind,
        false
    );
}

#[cfg(feature = "inspect-groupless")]
mod groupless_dialect {
    use protobuf_edit::inspect::NodeId;
    use protobuf_edit::inspect::groupless::{FaultKind, Tree};
    use protobuf_edit::wire::groupless::RecordKind;

    use super::padded::LenReading;
    use super::render::groupless::render;
    use super::*;

    /// The groupless reading of every LEN, parse order — the same
    /// discriminator as the grouped side (children present =
    /// message), sound for the same reason (the pin refuses empty
    /// payloads).
    fn collect_lens(tree: &Tree<'_>, id: NodeId, out: &mut Vec<LenReading>) {
        if matches!(tree.kind(id), RecordKind::Len) {
            assert!(
                !tree.payload_bytes(id).is_empty(),
                "the witness discriminator needs non-empty LEN payloads"
            );
            out.push(if tree.children(id).next().is_some() {
                LenReading::Message
            } else {
                LenReading::Bytes
            });
        }
        for child in tree.children(id) {
            collect_lens(tree, child, out);
        }
    }

    /// The witnesses are a byte fact, not a dialect's opinion: on
    /// the group-free documents the groupless dialect must read
    /// every LEN exactly as declared (and as the grouped side read
    /// it), padded bytes and twin alike.
    #[test]
    fn len_readings_match_their_declared_witnesses() {
        let docs = padded::DOCS;
        assert_eq!(docs.len(), 12, "padded census drifted");
        let mut lens_seen = 0;
        for doc in docs.iter().filter(|d| d.groupless) {
            for (side, hex) in [("padded", doc.padded), ("twin", doc.twin)] {
                let bytes = unhex(hex);
                let tree = Tree::parse(
                    Admitted::new(&bytes).unwrap(),
                    DepthLimit::REFERENCE,
                    &mut NoAdvice,
                );
                assert!(tree.is_complete(), "{}/{side}: parse faulted", doc.name);
                let mut readings = Vec::new();
                for top in tree.top() {
                    collect_lens(&tree, top, &mut readings);
                }
                assert_eq!(
                    readings, doc.lens,
                    "{}/{side}: the machine's LEN readings left the witness",
                    doc.name
                );
                lens_seen += readings.len();
            }
        }
        assert!(lens_seen >= 12, "the witness walk judged only {lens_seen} LENs");
    }

    /// The groupless face of the twin invariance: group-free
    /// documents render as their canonical twins, and group-coded
    /// documents fault as the capability refusal — pinning the
    /// batch's `groupless` flags to the bytes from this side too.
    #[test]
    fn padded_documents_render_as_their_canonical_twins_modulo_groups() {
        let docs = padded::DOCS;
        assert_eq!(docs.len(), 12, "padded census drifted");
        assert_eq!(docs.iter().filter(|d| d.groupless).count(), 10, "groupless census drifted");
        for doc in docs {
            let bytes = unhex(doc.padded);
            let padded_tree =
                Tree::parse(Admitted::new(&bytes).unwrap(), DepthLimit::REFERENCE, &mut NoAdvice);
            if !doc.groupless {
                let fault = padded_tree
                    .fault()
                    .unwrap_or_else(|| panic!("{}: group bytes must fault in p3", doc.name));
                assert!(
                    matches!(fault.kind(), FaultKind::GroupCode { .. }),
                    "{}: expected the capability refusal, got {:?}",
                    doc.name,
                    fault.kind()
                );
                continue;
            }
            let twin = unhex(doc.twin);
            assert_ne!(bytes, twin, "{}: the pair must differ in geometry", doc.name);
            let twin_tree =
                Tree::parse(Admitted::new(&twin).unwrap(), DepthLimit::REFERENCE, &mut NoAdvice);
            assert!(
                padded_tree.is_complete(),
                "{}: padded parse faulted: {:?}",
                doc.name,
                padded_tree.fault()
            );
            assert!(
                twin_tree.is_complete(),
                "{}: twin parse faulted: {:?}",
                doc.name,
                twin_tree.fault()
            );
            assert_eq!(
                render(&padded_tree),
                render(&twin_tree),
                "{}: padding moved the value reading",
                doc.name
            );
        }
    }
}

/// The canonical-output schedule over the curated corpus: descend
/// exactly the `LenReading::Message` witnesses (in preorder, the
/// declared order), leave every `Bytes` payload opaque, and the
/// canonical save of the padded side must equal the canonical twin
/// byte-for-byte. The rows repeat after a nested edit applied to
/// both twins alike, and — on the revisable hosts — after reverting
/// it; idempotence, the reopened fixed point, and the size
/// direction (`canonical_total <= fidelity_total`) ride the same
/// loops.
#[cfg(all(
    feature = "patch-grouped",
    feature = "patch-groupless",
    feature = "draft-grouped",
    feature = "draft-groupless",
    feature = "markup-grouped",
    feature = "markup-groupless"
))]
mod canonical_schedule {
    use protobuf_edit::FieldNumber;

    use super::padded::LenReading;
    use super::*;

    const F15: FieldNumber = match FieldNumber::new(15) {
        Some(field) => field,
        None => panic!("test field in range"),
    };

    /// One machine's schedule battery, shared by the one-shot and
    /// revisable hosts: `$unwrap` adapts the observation faces'
    /// return shape (`|x| x` one-shot, `|x| x.unwrap()` revisable).
    /// The `|…| …` arguments are macro binders, not closures.
    macro_rules! schedule_battery {
        ($mod_name:ident, $insert_at:path, $descent:path, $kind:path,
         open: |$src:ident| $open:expr, unwrap: |$obs:ident| $unwrap:expr,
         revert: [$($revert:ident)?], docs: $selector:expr, lens_floor: $lens_floor:literal) => {
            mod $mod_name {
                use super::*;
                use $descent as Descent;
                use $insert_at as InsertAt;
                use $kind as RecordKind;

                /// Commits exactly the `Message` witnesses: a preorder
                /// walk consuming one declared reading per LEN met —
                /// group interiors are in-band and walk without a
                /// reading. Returns the deepest opened container (the
                /// nested edit's anchor) and asserts the declaration
                /// list is spent exactly.
                macro_rules! commit_witnesses {
                    ($machine:ident, $lens:expr) => {{
                        let lens: &[LenReading] = $lens;
                        let mut cursor = 0;
                        let mut deepest = None;
                        let mut stack: Vec<_> = {
                            let mut tops: Vec<_> = $machine.top().collect();
                            tops.reverse();
                            tops
                        };
                        while let Some(handle) = stack.pop() {
                            let $obs = $machine.kind(handle);
                            if matches!($unwrap, RecordKind::Len) {
                                let reading = lens[cursor];
                                cursor += 1;
                                if matches!(reading, LenReading::Bytes) {
                                    continue;
                                }
                                let Descent::Opened { .. } = $machine.descend(handle).unwrap()
                                else {
                                    panic!("a Message witness must descend");
                                };
                                deepest = Some(handle);
                            }
                            let kids: Vec<_> = {
                                let $obs = $machine.children(handle);
                                let mut kids: Vec<_> = { $unwrap }.collect();
                                kids.reverse();
                                kids
                            };
                            stack.extend(kids);
                        }
                        assert_eq!(cursor, lens.len(), "the witness list is spent exactly");
                        deepest
                    }};
                }

                #[test]
                fn padded_canonical_saves_equal_their_twins_under_the_schedule() {
                    let docs = padded::DOCS;
                    assert_eq!(docs.len(), 12, "padded census drifted");
                    let mut rows = 0;
                    let mut lens_seen = 0;
                    for doc in docs.iter().filter($selector) {
                        rows += 1;
                        lens_seen += doc.lens.len();
                        let padded = unhex(doc.padded);
                        let twin = unhex(doc.twin);

                        let $src = &padded[..];
                        let mut machine = $open;
                        // The unedited row needs the schedule, not
                        // the nested-edit anchor the walk returns.
                        let _ = commit_witnesses!(machine, doc.lens);

                        // The schedule's canonical save is the twin,
                        // and repeating it is byte-identical.
                        let fresh = machine.save_canonical().unwrap();
                        assert_eq!(fresh, twin, "{}: canonical save vs twin", doc.name);
                        assert_eq!(
                            machine.save_canonical().unwrap(),
                            fresh,
                            "{}: idempotence on the unchanged machine",
                            doc.name
                        );

                        // Size direction: the canonical total never
                        // exceeds the fidelity total.
                        let fidelity = machine.save().unwrap();
                        assert!(
                            fresh.len() <= fidelity.len(),
                            "{}: canonical exceeded fidelity",
                            doc.name
                        );
                        assert_eq!(
                            machine.save_len().unwrap() as usize,
                            fidelity.len(),
                            "{}: the priced fidelity total",
                            doc.name
                        );

                        // The reopened fixed point: no new descent, the
                        // prior canonical bytes are already minimal at
                        // every visible site.
                        let $src = &fresh[..];
                        let reopened = $open;
                        assert_eq!(
                            reopened.save_canonical().unwrap(),
                            fresh,
                            "{}: the reopened fixed point",
                            doc.name
                        );

                        // The nested edit, applied to both twins alike:
                        // canonical saves stay byte-identical, and the
                        // direction holds over the edited state too.
                        let $src = &padded[..];
                        let mut edited_padded = $open;
                        let anchor = commit_witnesses!(edited_padded, doc.lens);
                        let $src = &twin[..];
                        let mut edited_twin = $open;
                        let twin_anchor = commit_witnesses!(edited_twin, doc.lens);
                        assert_eq!(anchor.is_some(), twin_anchor.is_some(), "{}", doc.name);
                        edited_padded
                            .insert_varint(InsertAt::TailOf(anchor), F15, 300)
                            .unwrap();
                        edited_twin
                            .insert_varint(InsertAt::TailOf(twin_anchor), F15, 300)
                            .unwrap();
                        let edited = edited_padded.save_canonical().unwrap();
                        assert_eq!(
                            edited,
                            edited_twin.save_canonical().unwrap(),
                            "{}: canonical agreement after the nested edit",
                            doc.name
                        );
                        assert!(
                            edited.len() <= edited_padded.save().unwrap().len(),
                            "{}: direction after the nested edit",
                            doc.name
                        );

                        // The revisable hosts revert the edit: the
                        // canonical save is the twin again.
                        $(
                            edited_padded.$revert();
                            assert_eq!(
                                edited_padded.save_canonical().unwrap(),
                                twin,
                                "{}: the reverted schedule normalizes again",
                                doc.name
                            );
                        )?
                    }
                    assert_eq!(rows, if $lens_floor == 0 { 2 } else { 10 }, "row census");
                    let _ = lens_seen;
                }
            }
        };
    }

    schedule_battery!(
        patch_groupless,
        protobuf_edit::patch::groupless::InsertAt,
        protobuf_edit::patch::groupless::Descent,
        protobuf_edit::wire::groupless::RecordKind,
        open: |src| protobuf_edit::patch::groupless::Patch::open(src, DepthLimit::REFERENCE)
            .unwrap(),
        unwrap: |obs| obs,
        revert: [],
        docs: |doc| doc.groupless,
        lens_floor: 1
    );

    schedule_battery!(
        patch_grouped,
        protobuf_edit::patch::grouped::InsertAt,
        protobuf_edit::patch::grouped::Descent,
        protobuf_edit::wire::grouped::RecordKind,
        open: |src| protobuf_edit::patch::grouped::Patch::open(src, DepthLimit::REFERENCE)
            .unwrap(),
        unwrap: |obs| obs,
        revert: [],
        docs: |doc| !doc.groupless,
        lens_floor: 0
    );

    schedule_battery!(
        draft_groupless,
        protobuf_edit::draft::groupless::InsertAt,
        protobuf_edit::draft::groupless::Descent,
        protobuf_edit::wire::groupless::RecordKind,
        open: |src| protobuf_edit::draft::groupless::Draft::open_copy(src).unwrap(),
        unwrap: |obs| obs.unwrap(),
        revert: [revert_all],
        docs: |doc| doc.groupless,
        lens_floor: 1
    );

    schedule_battery!(
        draft_grouped,
        protobuf_edit::draft::grouped::InsertAt,
        protobuf_edit::draft::grouped::Descent,
        protobuf_edit::wire::grouped::RecordKind,
        open: |src| protobuf_edit::draft::grouped::Draft::open_copy(src).unwrap(),
        unwrap: |obs| obs.unwrap(),
        revert: [revert_all],
        docs: |doc| !doc.groupless,
        lens_floor: 0
    );

    schedule_battery!(
        markup_groupless,
        protobuf_edit::markup::groupless::InsertAt,
        protobuf_edit::markup::groupless::Descent,
        protobuf_edit::wire::groupless::RecordKind,
        open: |src| protobuf_edit::markup::groupless::Markup::open(src).unwrap(),
        unwrap: |obs| obs.unwrap(),
        revert: [revert_all],
        docs: |doc| doc.groupless,
        lens_floor: 1
    );

    schedule_battery!(
        markup_grouped,
        protobuf_edit::markup::grouped::InsertAt,
        protobuf_edit::markup::grouped::Descent,
        protobuf_edit::wire::grouped::RecordKind,
        open: |src| protobuf_edit::markup::grouped::Markup::open(src).unwrap(),
        unwrap: |obs| obs.unwrap(),
        revert: [revert_all],
        docs: |doc| !doc.groupless,
        lens_floor: 0
    );

    /// Scripted edit states over the corpus, beyond the single
    /// nested insert: replacements and deletions drawn from each
    /// document's own record population, with the size direction
    /// judged on every variant.
    #[test]
    fn size_direction_holds_over_scripted_edit_states() {
        use protobuf_edit::patch::groupless::{Descent, Patch};
        let docs = padded::DOCS;
        assert_eq!(docs.len(), 12, "padded census drifted");
        let mut variants = 0;
        for doc in docs.iter().filter(|doc| doc.groupless) {
            let padded = unhex(doc.padded);
            for script in 0..3u8 {
                let mut machine = Patch::open(&padded, DepthLimit::REFERENCE).unwrap();
                // The schedule again: commit every Message witness.
                let mut cursor = 0;
                let mut stack: Vec<_> = {
                    let mut tops: Vec<_> = machine.top().collect();
                    tops.reverse();
                    tops
                };
                while let Some(handle) = stack.pop() {
                    if matches!(
                        machine.kind(handle),
                        protobuf_edit::wire::groupless::RecordKind::Len
                    ) {
                        let reading = doc.lens[cursor];
                        cursor += 1;
                        if matches!(reading, LenReading::Bytes) {
                            continue;
                        }
                        let Descent::Opened { .. } = machine.descend(handle).unwrap() else {
                            panic!("a Message witness must descend");
                        };
                    }
                    let mut kids: Vec<_> = machine.children(handle).collect();
                    kids.reverse();
                    stack.extend(kids);
                }
                // Script 0: replace the first varint (if any); script
                // 1: delete the first top record; script 2: both plus
                // a tail insert.
                let tops: Vec<_> = machine.top().collect();
                let first_varint = tops.iter().copied().find(|&handle| {
                    matches!(
                        machine.kind(handle),
                        protobuf_edit::wire::groupless::RecordKind::Varint
                    )
                });
                match script {
                    0 => {
                        if let Some(target) = first_varint {
                            machine.set_varint(target, u64::MAX).unwrap();
                        }
                    }
                    1 => machine.delete(tops[0]).unwrap(),
                    _ => {
                        if let Some(target) = first_varint {
                            machine.set_varint(target, 1).unwrap();
                        }
                        machine.delete(*tops.last().unwrap()).unwrap();
                        machine
                            .insert_varint(
                                protobuf_edit::patch::groupless::InsertAt::TailOf(None),
                                F15,
                                u64::from(u32::MAX),
                            )
                            .unwrap();
                    }
                }
                let canonical = machine.save_canonical().unwrap();
                let fidelity = machine.save().unwrap();
                assert!(
                    canonical.len() <= fidelity.len(),
                    "{} script {script}: canonical exceeded fidelity",
                    doc.name
                );
                variants += 1;
            }
        }
        assert_eq!(variants, 30, "the scripted population drifted");
    }

    /// The reduced-cap model: the case "fidelity over cap, canonical
    /// in cap" proved on the corpus's own totals under a miniature
    /// cap — no giant fixture. The per-row direction
    /// (`canonical_total <= fidelity_total`) makes the converse
    /// impossible: a cap the canonical total passes while fidelity
    /// exceeds it exists exactly when the totals differ, and no cap
    /// admits fidelity while refusing canonical.
    #[test]
    fn reduced_cap_model_admits_canonical_where_fidelity_overflows() {
        let docs = padded::DOCS;
        assert_eq!(docs.len(), 12, "padded census drifted");
        let mut split_caps = 0;
        for doc in docs {
            let fidelity_total = unhex(doc.padded).len();
            let canonical_total = unhex(doc.twin).len();
            assert!(canonical_total <= fidelity_total, "{}: direction", doc.name);
            // Every cap in the gap admits canonical output and
            // refuses fidelity — the fault-direction consequence.
            for cap in canonical_total..fidelity_total {
                assert!(canonical_total <= cap && fidelity_total > cap);
                split_caps += 1;
            }
            // No cap does the reverse: refusing canonical means the
            // cap sits below both totals.
            for cap in 0..canonical_total {
                assert!(
                    fidelity_total > cap,
                    "{}: a cap refused canonical but not fidelity",
                    doc.name
                );
            }
        }
        assert!(split_caps > 0, "the corpus offers no over-cap split to model");
    }
}

/// The transfer acceptance matrix over one designation corpus: a
/// tolerant destination preserves padded and minimal designations
/// exactly; a canonical destination admits minimal ones through the
/// proof, refuses padded framing at the proof, and accepts padded
/// words behind an opaque LEN interior (the interior is a
/// declaration).
#[cfg(all(
    feature = "inspect-groupless",
    feature = "transfer-patch-groupless",
    feature = "transfer-amend-groupless"
))]
#[test]
fn the_acceptance_matrix_judges_every_source_row() {
    use protobuf_edit::inspect::groupless::Tree;
    use protobuf_edit::inspect::{Admitted, NoAdvice};
    use protobuf_edit::source::groupless::Fault;

    // One designation corpus: a minimal record, a padded-framing
    // twin, and a minimal LEN whose opaque interior carries padded
    // words.
    let corpus = [0x08u8, 0x2A, 0x10, 0x96, 0x81, 0x00, 0x1A, 0x02, 0x88, 0x00];
    let input = Admitted::new(&corpus).unwrap();
    let tree = Tree::parse(input, DepthLimit::REFERENCE, &mut NoAdvice);
    let ids: Vec<_> = tree.top().collect();
    let minimal = tree.record_ref(ids[0]).unwrap();
    let padded = tree.record_ref(ids[1]).unwrap();
    let opaque_interior = tree.record_ref(ids[2]).unwrap();

    // Tolerant destination: padded and minimal both preserve
    // exactly.
    let base = [0x38u8, 0x01];
    let mut tolerant =
        protobuf_edit::patch::groupless::TransferPatch::open(&base, DepthLimit::REFERENCE).unwrap();
    tolerant
        .copy_record_from(minimal, protobuf_edit::patch::groupless::InsertAt::TailOf(None))
        .unwrap();
    tolerant
        .copy_record_from(padded, protobuf_edit::patch::groupless::InsertAt::TailOf(None))
        .unwrap();
    let out = tolerant.save().unwrap();
    assert_eq!(out, [0x38, 0x01, 0x08, 0x2A, 0x10, 0x96, 0x81, 0x00]);
    // Re-ingest under the promised standard: the ordinary save is
    // tolerant wire.
    assert!(protobuf_edit::patch::groupless::Patch::open(&out, DepthLimit::REFERENCE).is_ok());

    // Canonical destination: the tolerant-but-minimal record
    // upgrades through the proof; padded framing refuses at the
    // proof — never re-encoded, and the machine is untouched.
    let mut canonical = protobuf_edit::amend::groupless::transfer::TransferAmend::open(
        &base,
        DepthLimit::REFERENCE,
    )
    .unwrap();
    canonical
        .copy_record_from(
            minimal.try_canonical().unwrap(),
            protobuf_edit::amend::groupless::InsertAt::TailOf(None),
        )
        .unwrap();
    assert!(matches!(padded.try_canonical(), Err(Fault::StandardMismatch { .. })));

    // A padded word inside an opaque LEN interior does not block
    // the canonical proof: the interior is a declaration.
    canonical
        .copy_record_from(
            opaque_interior.try_canonical().unwrap(),
            protobuf_edit::amend::groupless::InsertAt::TailOf(None),
        )
        .unwrap();
    let out = canonical.save().unwrap();
    assert_eq!(out, [0x38, 0x01, 0x08, 0x2A, 0x1A, 0x02, 0x88, 0x00]);
    // Re-ingest under the promised standard: the canonical host's
    // save re-admits canonically.
    assert!(protobuf_edit::amend::groupless::Amend::open(&out, DepthLimit::REFERENCE).is_ok());
}
