//! The groupless splicer's module suite.

use alloc::vec::Vec;

use super::{FaultKind, Rule, WireBreach, splice, splice_into, splice_sink};
use crate::splice::{Len, Scalar};
use crate::wire::FieldNumber;
use crate::{DepthLimit, Standard};

/// The identity rule: keeps and passes everything.
#[derive(Clone)]
struct Identity;
impl Rule for Identity {}

/// The test-local varint encoder — the independent oracle for
/// every expected prefix in this suite.
fn leb(mut value: u64, out: &mut Vec<u8>) {
    while value >= 0x80 {
        out.push((value & 0x7F) as u8 | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

/// All three faces over the same job under `standard`, agreement
/// asserted; the append face also proves its mark discipline.
fn faces<R: Rule + Clone>(input: &[u8], rule: &R, standard: Standard) -> Vec<u8> {
    let vec_face = splice(input, &mut rule.clone(), standard, DepthLimit::REFERENCE).unwrap();
    let mut appended = alloc::vec![0xEE_u8; 3];
    splice_into(input, &mut rule.clone(), standard, DepthLimit::REFERENCE, &mut appended).unwrap();
    assert_eq!(appended[..3], [0xEE; 3], "the append face touched existing content");
    assert_eq!(vec_face, appended[3..], "the append face must agree byte-for-byte");
    let mut sunk = Vec::new();
    splice_sink(input, &mut rule.clone(), standard, DepthLimit::REFERENCE, |window| {
        sunk.extend_from_slice(window);
    })
    .unwrap();
    assert_eq!(vec_face, sunk, "the two faces must agree byte-for-byte");
    vec_face
}

/// Both faces over the same job, agreement asserted.
fn both<R: Rule + Clone>(input: &[u8], rule: &R) -> Vec<u8> {
    faces(input, rule, Standard::Tolerant)
}

#[test]
fn identity_rides_everything_verbatim() {
    let msg = [0x08, 0x96, 0x01, 0x12, 0x03, b'a', b'b', b'c', 0x1D, 1, 2, 3, 4];
    let out = splice(&msg, &mut Identity, Standard::Tolerant, DepthLimit::REFERENCE).unwrap();
    assert_eq!(out, msg);
}

#[test]
fn a_lone_drop_under_a_commit_settles_the_prefix_on_both_faces() {
    // f1 LEN { f2 varint 3 } — commit f1, drop f2: the container
    // empties, its prefix re-authors to zero. The drop is the only
    // interior event, so the overlay face has no authored emission
    // to claim the prefix slot — the drop itself must.
    #[derive(Clone)]
    struct DropInner;
    impl Rule for DropInner {
        fn on_varint(&mut self, _at: u32, _field: FieldNumber, _value: u64) -> Scalar<'_, u64> {
            Scalar::Drop
        }
        fn on_len(&mut self, _at: u32, _field: FieldNumber, _payload: &[u8]) -> Len<'_> {
            Len::Commit { tail: None }
        }
    }
    let msg = [0x0A, 0x02, 0x10, 0x03];
    assert_eq!(both(&msg, &DropInner), [0x0A, 0x00]);
}

// ─── the worked example (derivation §3): 3-deep growth ───

/// f1 LEN { f2 LEN { f3 LEN { f4 LEN <116 bytes> } } } — 124 bytes,
/// canonical.
fn worked_input() -> Vec<u8> {
    let mut doc = alloc::vec![0x0A, 0x7A, 0x12, 0x78, 0x1A, 0x76, 0x22, 0x74];
    doc.extend_from_slice(&[0xAB; 116]);
    assert_eq!(doc.len(), 124);
    doc
}

/// Commits every container on the way down, answers at f4.
#[derive(Clone)]
struct CommitToF4<'r>(Len<'r>);
impl Rule for CommitToF4<'_> {
    fn on_len(&mut self, _at: u32, field: FieldNumber, _payload: &[u8]) -> Len<'_> {
        if field.as_inner() == 4 { self.0 } else { Len::Commit { tail: None } }
    }
}

#[test]
fn the_worked_example_grows_to_142_bytes_exactly() {
    // Replace(130 B) at f4: every prefix on the chain widens 1 → 2.
    let replacement = [0xCD_u8; 130];
    let out =
        faces(&worked_input(), &CommitToF4(Len::Replace(&replacement)), Standard::CanonicalMinimal);
    let mut want =
        alloc::vec![0x0A, 0x8B, 0x01, 0x12, 0x88, 0x01, 0x1A, 0x85, 0x01, 0x22, 0x82, 0x01];
    want.extend_from_slice(&replacement);
    assert_eq!(want.len(), 142);
    assert_eq!(out, want);
}

#[test]
fn the_worked_example_shrink_twin_backpatches_every_prefix() {
    // Drop at f4: interiors 0/2/4, every width already met — the
    // zero-move twin (movement is unobservable here; the bytes are).
    let out = faces(&worked_input(), &CommitToF4(Len::Drop), Standard::CanonicalMinimal);
    assert_eq!(out, [0x0A, 0x04, 0x12, 0x02, 0x1A, 0x00]);
}

// ─── the one-ask pin ───

/// Logs every ask's head offset and answers from mutating state:
/// each varint rewrites to the running ask count, so a re-asked
/// record would double-count visibly in the output bytes.
#[derive(Clone, Default)]
struct Counter {
    asked: Vec<u32>,
}
impl Rule for Counter {
    fn on_varint(&mut self, at: u32, _field: FieldNumber, _value: u64) -> Scalar<'_, u64> {
        self.asked.push(at);
        Scalar::Rewrite(self.asked.len() as u64 - 1)
    }
    fn on_i32(&mut self, at: u32, _field: FieldNumber, _bits: u32) -> Scalar<'_, u32> {
        self.asked.push(at);
        Scalar::Keep
    }
    fn on_i64(&mut self, at: u32, _field: FieldNumber, _bits: u64) -> Scalar<'_, u64> {
        self.asked.push(at);
        Scalar::Keep
    }
    fn on_len(&mut self, at: u32, _field: FieldNumber, _payload: &[u8]) -> Len<'_> {
        self.asked.push(at);
        Len::Commit { tail: None }
    }
}

#[test]
fn one_ask_per_delivered_record_with_mutating_state() {
    // f1 varint · f2 LEN { f3 varint · f4 i32 } · f6 i64 · f6 varint
    let msg = [
        0x08, 0x2A, // f1 varint 42                     head 0
        0x12, 0x07, // f2 LEN, interior 7               head 2
        0x18, 0x07, // f3 varint 7                      head 4
        0x25, 1, 2, 3, 4, // f4 i32                     head 6
        0x31, 8, 7, 6, 5, 4, 3, 2, 1, // f6 i64         head 11
        0x30, 0x63, // f6 varint 99                     head 20
    ];
    let mut rule = Counter::default();
    let out = splice(&msg, &mut rule, Standard::Tolerant, DepthLimit::REFERENCE).unwrap();
    // Asks: every delivered record exactly once, delivery order.
    assert_eq!(rule.asked, [0, 2, 4, 6, 11, 20]);
    // The mutating rewrites landed in ask order: f1 → 0 (ask #0),
    // f3 → 2 (ask #2), f6 → 5 (ask #5).
    let mut want = msg;
    want[1] = 0x00;
    want[5] = 0x02;
    want[21] = 0x05;
    assert_eq!(out, want);

    // The sink face fires the identical ask sequence (the fold
    // carries no rule: a second ask has nowhere to come from).
    let mut sink_rule = Counter::default();
    splice_sink(&msg, &mut sink_rule, Standard::Tolerant, DepthLimit::REFERENCE, |_| {}).unwrap();
    assert_eq!(sink_rule.asked, [0, 2, 4, 6, 11, 20]);
}

// ─── the commit tail (the must-decide) ───

#[test]
fn a_commit_tail_lands_after_the_last_interior_record() {
    // Commit f1 with a tail; the interior record also grows: the
    // tail rides after it, inside the settled prefix.
    #[derive(Clone)]
    struct Tail;
    impl Rule for Tail {
        fn on_len(&mut self, _at: u32, field: FieldNumber, _payload: &[u8]) -> Len<'_> {
            match field.as_inner() {
                1 => Len::Commit { tail: Some(&[0x18, 0x2A]) },
                _ => Len::Replace(b"grown"),
            }
        }
    }
    // f1 LEN { f2 LEN "hi" }
    let msg = [0x0A, 0x04, 0x12, 0x02, 0x68, 0x69];
    let out = both(&msg, &Tail);
    assert_eq!(out, [0x0A, 0x09, 0x12, 0x05, b'g', b'r', b'o', b'w', b'n', 0x18, 0x2A]);
}

#[test]
fn a_commit_tail_dirties_an_otherwise_clean_interior() {
    // The tail is the only change: the interior rides verbatim and
    // the prefix still re-authors — the overlay face must claim the
    // slot from the tail alone.
    #[derive(Clone)]
    struct TailOnly;
    impl Rule for TailOnly {
        fn on_len(&mut self, _at: u32, field: FieldNumber, _payload: &[u8]) -> Len<'_> {
            if field.as_inner() == 1 {
                Len::Commit { tail: Some(&[0x18, 0x2A]) }
            } else {
                Len::Pass
            }
        }
    }
    let msg = [0x0A, 0x04, 0x12, 0x02, 0x68, 0x69];
    let out = both(&msg, &TailOnly);
    assert_eq!(out, [0x0A, 0x06, 0x12, 0x02, 0x68, 0x69, 0x18, 0x2A]);
}

// ─── the rewrite differential ───

/// The buffered path-driven rewriter is the independent oracle on
/// edits both machines spell: drops, minimal varint rewrites, and
/// whole-payload LEN replacement at the top level.
#[cfg(feature = "rewrite-groupless")]
#[test]
fn the_path_driven_rewriter_agrees_on_shared_edits() {
    use crate::path::Segment;
    use crate::rewrite::{self, RuleSet};

    // f1 varint · f2 varint · f7 LEN "abc" · f9 i32
    let msg = [0x08, 0x01, 0x10, 0x05, 0x3A, 0x03, b'a', b'b', b'c', 0x4D, 9, 9, 9, 9];

    #[derive(Clone)]
    struct Edits;
    impl Rule for Edits {
        fn on_varint(&mut self, _at: u32, field: FieldNumber, _value: u64) -> Scalar<'_, u64> {
            match field.as_inner() {
                1 => Scalar::Drop,
                _ => Scalar::Rewrite(260),
            }
        }
        fn on_len(&mut self, _at: u32, _field: FieldNumber, _payload: &[u8]) -> Len<'_> {
            Len::Replace(b"xyzzy")
        }
    }
    let spliced = both(&msg, &Edits);

    let f = |n: u32| FieldNumber::new(n).unwrap();
    let (p1, p2, p7): ([Segment<'_>; 1], [Segment<'_>; 1], [Segment<'_>; 1]) =
        ([Segment::Field(f(1))], [Segment::Field(f(2))], [Segment::Field(f(7))]);
    let rules = [
        rewrite::Rule { path: &p1, action: rewrite::Action::Delete },
        rewrite::Rule { path: &p2, action: rewrite::Action::Replace(rewrite::Value::Varint(260)) },
        rewrite::Rule {
            path: &p7,
            action: rewrite::Action::Replace(rewrite::Value::Len(b"xyzzy")),
        },
    ];
    let set = RuleSet::over(&rules).unwrap();
    let (rewritten, _) = rewrite::groupless::rewrite(&msg, &set, DepthLimit::REFERENCE).unwrap();
    assert_eq!(spliced, rewritten);
}

// ─── the patch differential ───

/// The handle-driven one-shot patch is the independent oracle on
/// every online arc both machines spell: scalar rewrites, drops,
/// and inserts; opaque LEN replacement, drop, and insertion; and
/// committed nested edits whose length cascades settle at depth —
/// the family's minimal-re-author law, pinned across machines.
#[cfg(feature = "patch-groupless")]
#[test]
fn the_handle_driven_patch_agrees_on_online_arcs() {
    use crate::patch::groupless::{Descent, InsertAt, Patch};

    // f1 varint · f2 varint · f3 i32 · f4 i64 · f5 LEN "abc" ·
    // f6 LEN "hi" · f7 LEN { f9 varint 1 · f12 LEN "xy" } ·
    // f8 varint 150 (value padded to three bytes; both machines
    // ride it untouched).
    let msg = [
        0x08, 0x2A, // f1 varint 42                    head 0
        0x10, 0x05, // f2 varint 5                     head 2
        0x1D, 0x01, 0x02, 0x03, 0x04, // f3 i32        head 4
        0x21, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, // f4 i64  head 9
        0x2A, 0x03, b'a', b'b', b'c', // f5 LEN        head 18
        0x32, 0x02, b'h', b'i', // f6 LEN              head 23
        0x3A, 0x06, 0x48, 0x01, 0x62, 0x02, b'x', b'y', // f7 LEN  head 28
        0x40, 0x96, 0x81, 0x00, // f8 varint padded    head 36
    ];
    let f13 = FieldNumber::new(13).unwrap();

    // The growth arc: an insert before the first record, a grown
    // varint, an inserted LEN, scalar and LEN drops, an opaque
    // replacement, and a committed interior whose replacement
    // grows the container.
    #[derive(Clone)]
    struct Grow;
    impl Rule for Grow {
        fn on_varint(&mut self, _at: u32, field: FieldNumber, _value: u64) -> Scalar<'_, u64> {
            match field.as_inner() {
                1 => Scalar::Insert(&[0x68, 0x07]), // f13 varint 7
                2 => Scalar::Rewrite(300),
                9 => Scalar::Drop,
                _ => Scalar::Keep,
            }
        }
        fn on_i32(&mut self, _at: u32, field: FieldNumber, _bits: u32) -> Scalar<'_, u32> {
            match field.as_inner() {
                // f13 LEN "hi", landing before f3.
                3 => Scalar::Insert(&[0x6A, 0x02, b'h', b'i']),
                _ => Scalar::Keep,
            }
        }
        fn on_i64(&mut self, _at: u32, _field: FieldNumber, _bits: u64) -> Scalar<'_, u64> {
            Scalar::Drop
        }
        fn on_len(&mut self, _at: u32, field: FieldNumber, _payload: &[u8]) -> Len<'_> {
            match field.as_inner() {
                5 => Len::Replace(b"xyzzy"),
                6 => Len::Drop,
                7 => Len::Commit { tail: None },
                12 => Len::Replace(b"longer!"),
                _ => Len::Pass,
            }
        }
    }
    let spliced = both(&msg, &Grow);

    let mut patch = Patch::open(&msg, DepthLimit::REFERENCE).unwrap();
    let tops: Vec<_> = patch.top().collect();
    patch.insert_varint(InsertAt::HeadOf(None), f13, 7).unwrap();
    patch.set_varint(tops[1], 300).unwrap();
    patch.insert_payload(InsertAt::After(tops[1]), f13, b"hi").unwrap();
    patch.delete(tops[3]).unwrap();
    patch.set_payload(tops[4], b"xyzzy").unwrap();
    patch.delete(tops[5]).unwrap();
    let Descent::Opened { first: Some(_) } = patch.descend(tops[6]).unwrap() else {
        unreachable!()
    };
    let kids: Vec<_> = patch.children(tops[6]).collect();
    patch.delete(kids[0]).unwrap();
    patch.set_payload(kids[1], b"longer!").unwrap();
    assert_eq!(spliced, patch.save().unwrap());

    // The shrink twin: the committed interior's replacement
    // shrinks the container, and everything else rides verbatim.
    #[derive(Clone)]
    struct Shrink;
    impl Rule for Shrink {
        fn on_len(&mut self, _at: u32, field: FieldNumber, _payload: &[u8]) -> Len<'_> {
            match field.as_inner() {
                7 => Len::Commit { tail: None },
                12 => Len::Replace(b"z"),
                _ => Len::Pass,
            }
        }
    }
    let spliced = both(&msg, &Shrink);

    let mut patch = Patch::open(&msg, DepthLimit::REFERENCE).unwrap();
    let tops: Vec<_> = patch.top().collect();
    let Descent::Opened { first: Some(_) } = patch.descend(tops[6]).unwrap() else {
        unreachable!()
    };
    let kids: Vec<_> = patch.children(tops[6]).collect();
    patch.set_payload(kids[1], b"z").unwrap();
    assert_eq!(spliced, patch.save().unwrap());
}

// ─── the transcode differential ───

/// The streaming transcoder fed whole is the independent oracle on
/// the zero-cascade subset: keeps and passes (padding included),
/// equal-length rewrites and replacements under a committed LEN,
/// and free drops and inserts at the root.
#[cfg(feature = "transcode-groupless")]
#[test]
fn the_streaming_transcoder_agrees_on_zero_cascade_verdicts() {
    use crate::transcode::groupless::{Rule as TRule, Transcoder};
    use crate::transcode::{FreeLen, FreeScalar, LockedScalar};

    // f1 varint · f2 varint 150 (padded value) · f3 LEN "abc" ·
    // f4 LEN { f9 varint 5 } · f5 i32 · f6 varint · f7 LEN "hi"
    let msg = [
        0x08, 0x2A, // f1 varint 42                    head 0
        0x10, 0x96, 0x81, 0x00, // f2 varint padded    head 2
        0x1A, 0x03, b'a', b'b', b'c', // f3 LEN        head 6
        0x22, 0x02, 0x48, 0x05, // f4 LEN { f9 }       head 11
        0x2D, 0xDD, 0xCC, 0xBB, 0xAA, // f5 i32        head 15
        0x30, 0x01, // f6 varint 1                     head 20
        0x3A, 0x02, b'h', b'i', // f7 LEN              head 22
    ];

    #[derive(Clone)]
    struct Verdicts;
    impl Rule for Verdicts {
        fn on_varint(&mut self, _at: u32, field: FieldNumber, _value: u64) -> Scalar<'_, u64> {
            match field.as_inner() {
                1 => Scalar::Drop,
                9 => Scalar::Rewrite(7), // equal width under the committed f4
                6 => Scalar::Insert(&[0x40, 0x2A]), // f8 varint 42, before f6
                _ => Scalar::Keep,
            }
        }
        fn on_i32(&mut self, _at: u32, _field: FieldNumber, _bits: u32) -> Scalar<'_, u32> {
            Scalar::Rewrite(0x1122_3344)
        }
        fn on_len(&mut self, _at: u32, field: FieldNumber, _payload: &[u8]) -> Len<'_> {
            match field.as_inner() {
                3 => Len::Replace(b"xyz"), // equal length
                4 => Len::Commit { tail: None },
                _ => Len::Pass,
            }
        }
    }
    let spliced = both(&msg, &Verdicts);

    /// The same verdict stream in the transcoder's vocabulary; the
    /// insert flag answers the transcoder's re-ask with `Keep`,
    /// composing the splicer's terminal insert-before.
    struct TVerdicts {
        inserted: bool,
    }
    impl TRule for TVerdicts {
        fn on_varint(
            &mut self,
            _at: u64,
            field: FieldNumber,
            _value: u64,
            _width: u8,
        ) -> FreeScalar<'_, u64> {
            match field.as_inner() {
                1 => FreeScalar::Drop,
                6 if !self.inserted => {
                    self.inserted = true;
                    FreeScalar::Insert(&[0x40, 0x2A])
                }
                _ => FreeScalar::Keep,
            }
        }
        fn on_i32(&mut self, _at: u64, _field: FieldNumber, _bits: u32) -> FreeScalar<'_, u32> {
            FreeScalar::Rewrite(0x1122_3344)
        }
        fn on_len(&mut self, _at: u64, field: FieldNumber, _len: crate::PayloadLen) -> FreeLen<'_> {
            match field.as_inner() {
                3 => FreeLen::Replace(b"xyz"),
                4 => FreeLen::Commit,
                _ => FreeLen::Pass,
            }
        }
        fn on_varint_locked(
            &mut self,
            _at: u64,
            _field: FieldNumber,
            _value: u64,
            _width: u8,
        ) -> LockedScalar<u64> {
            LockedScalar::Rewrite(7)
        }
    }
    let mut transcoded = Vec::new();
    let mut sink = |bytes: &[u8]| transcoded.extend_from_slice(bytes);
    let mut rule = TVerdicts { inserted: false };
    let mut t = Transcoder::new(Standard::Tolerant, DepthLimit::REFERENCE);
    t.feed(&msg, &mut rule, &mut sink).unwrap();
    t.finish(&mut rule, &mut sink).unwrap();
    assert_eq!(spliced, transcoded);
}

// ─── the threshold corpus: prefix width boundaries ───

/// Commits f1, replaces the inner f15 payload with its own bytes.
#[derive(Clone)]
struct GrowTo(Vec<u8>);
impl Rule for GrowTo {
    fn on_len(&mut self, _at: u32, field: FieldNumber, _payload: &[u8]) -> Len<'_> {
        if field.as_inner() == 1 { Len::Commit { tail: None } } else { Len::Replace(&self.0) }
    }
}

fn threshold_case(payload_len: usize, want_interior: u64) {
    // f1 LEN { f15 LEN <1 byte> }
    let msg = [0x0A, 0x03, 0x7A, 0x01, 0xAA];
    let rule = GrowTo(alloc::vec![0xAB; payload_len]);
    let out = faces(&msg, &rule, Standard::CanonicalMinimal);
    let mut want = alloc::vec![0x0A];
    leb(want_interior, &mut want);
    want.push(0x7A);
    leb(payload_len as u64, &mut want);
    want.extend_from_slice(&rule.0);
    assert_eq!(out, want, "payload {payload_len} → interior {want_interior}");
}

#[test]
fn prefix_widths_settle_exactly_at_every_boundary() {
    // Interior = 1 (tag) + prefix(payload) + payload; the pairs sit
    // astride each width step of the settled f1 prefix.
    threshold_case(125, 127);
    threshold_case(126, 128);
    threshold_case(16380, 16383);
    threshold_case(16381, 16384);
    threshold_case((1 << 21) - 5, (1 << 21) - 1);
    threshold_case((1 << 21) - 4, 1 << 21);
}

// The 2^28 boundary stages quarter-GiB buffers: byte bulk with no
// provenance value under Miri, no host on 32-bit targets. The
// settle arithmetic is target-independent.
#[cfg(all(not(target_family = "wasm"), not(miri)))]
#[test]
fn the_quarter_gibibyte_boundary_settles_exactly() {
    struct GrowBig;
    impl Rule for GrowBig {
        fn on_len<'a>(&'a mut self, _at: u32, field: FieldNumber, payload: &'a [u8]) -> Len<'a> {
            if field.as_inner() == 1 { Len::Commit { tail: None } } else { Len::Replace(payload) }
        }
    }
    for (payload_len, want_interior) in
        [((1 << 28) - 6, (1_u64 << 28) - 1), ((1 << 28) - 5, 1_u64 << 28)]
    {
        // The inner record already carries the boundary payload; the
        // rule re-authors it verbatim through the Replace arm, which
        // still forces the settle path (an authored emission).
        let mut msg = alloc::vec![0x0A];
        let mut inner = alloc::vec![0x7A];
        leb(payload_len as u64, &mut inner);
        inner.extend(core::iter::repeat_n(0xAB_u8, payload_len));
        leb(inner.len() as u64, &mut msg);
        msg.extend_from_slice(&inner);
        let out = splice(&msg, &mut GrowBig, Standard::Tolerant, DepthLimit::REFERENCE).unwrap();
        let mut want = alloc::vec![0x0A];
        leb(want_interior, &mut want);
        want.extend_from_slice(&inner);
        assert_eq!(out, want, "payload {payload_len} → interior {want_interior}");
    }
}

// ─── re-ingestion, both standards ───

#[test]
fn edited_output_re_ingests_under_both_standards() {
    use crate::cursor::groupless::{Cursor, EntryKind};

    // 65 canonical varint records — the replacement stays a lawful
    // message, so the gate below may descend into it.
    let replacement: Vec<u8> = core::iter::repeat_n([0x08, 0x01], 65).flatten().collect();
    for standard in [Standard::Tolerant, Standard::CanonicalMinimal] {
        let out = faces(&worked_input(), &CommitToF4(Len::Replace(&replacement)), standard);
        // The full traversal is the independent gate: every record
        // (at every depth the edit touched) must parse lawfully,
        // minimally encoded.
        let mut stack = alloc::vec![Cursor::over(&out).unwrap()];
        while let Some(cursor) = stack.last_mut() {
            match cursor.step::<true>() {
                Some(Ok(entry)) => {
                    if let EntryKind::Len(payload) = entry.kind() {
                        stack.push(Cursor::within(payload));
                    }
                }
                Some(Err(fault)) => panic!("re-ingestion refused: {fault:?}"),
                None => {
                    stack.pop();
                }
            }
        }
    }
}

// ─── the depth wall ───

#[test]
fn only_the_entering_verdict_spends_the_budget() {
    #[derive(Clone)]
    struct CommitAll;
    impl Rule for CommitAll {
        fn on_len(&mut self, _at: u32, _field: FieldNumber, _payload: &[u8]) -> Len<'_> {
            Len::Commit { tail: None }
        }
    }
    // f1 LEN { f1 LEN { f2 varint } }
    let msg = [0x0A, 0x04, 0x0A, 0x02, 0x10, 0x07];
    let limit = DepthLimit::new(1).unwrap();
    let fault = splice(&msg, &mut CommitAll, Standard::Tolerant, limit).unwrap_err();
    assert_eq!(fault.at(), 2);
    assert!(matches!(fault.kind(), FaultKind::Wire(WireBreach::Depth)));
    assert_eq!(fault.trail().len(), 1);

    // A Pass at the wall is lawful — only entering costs.
    #[derive(Clone)]
    struct CommitOuterPassInner;
    impl Rule for CommitOuterPassInner {
        fn on_len(&mut self, at: u32, _field: FieldNumber, _payload: &[u8]) -> Len<'_> {
            if at == 0 { Len::Commit { tail: None } } else { Len::Pass }
        }
    }
    let out = splice(&msg, &mut CommitOuterPassInner, Standard::Tolerant, limit).unwrap();
    assert_eq!(out, msg);
}

// ─── fault contracts on the fallible faces ───

#[test]
fn the_append_face_truncates_to_its_mark_on_err() {
    #[derive(Clone)]
    struct FaultyLate;
    impl Rule for FaultyLate {}
    // Lawful head, torn tail: some records emit before the fault.
    let msg = [0x08, 0x2A, 0x10, 0x05, 0xFF];
    let mut out = alloc::vec![1, 2, 3];
    let fault =
        splice_into(&msg, &mut FaultyLate, Standard::Tolerant, DepthLimit::REFERENCE, &mut out)
            .unwrap_err();
    assert!(matches!(fault.kind(), FaultKind::Wire(WireBreach::Varint)));
    assert_eq!(out, [1, 2, 3], "the buffer must restore byte-identically");

    let mut handed = 0_usize;
    let sink_fault =
        splice_sink(&msg, &mut FaultyLate, Standard::Tolerant, DepthLimit::REFERENCE, |w| {
            handed += w.len();
        })
        .unwrap_err();
    assert_eq!(sink_fault, fault);
    assert_eq!(handed, 0, "the sink must be handed nothing on Err");
}

// The fixture stages answer slices beyond the LEN class (> 2 GiB):
// 32-bit targets cannot host them, and under Miri they are byte
// bulk without provenance value. The refusal arithmetic itself is
// target-independent.
#[cfg(all(not(target_family = "wasm"), not(miri)))]
#[test]
fn oversize_answers_and_outputs_refuse_eagerly() {
    use crate::admission;

    struct Big<'r>(&'r [u8]);
    impl Rule for Big<'_> {
        fn on_len(&mut self, _at: u32, _field: FieldNumber, _payload: &[u8]) -> Len<'_> {
            Len::Replace(self.0)
        }
    }
    let big = alloc::vec![0u8; admission::MAX + 1];
    // Growth: judged at the ask, before any byte is copied.
    let msg = [0x0A, 0x00, 0x12, 0x00];
    let fault =
        splice(&msg, &mut Big(&big), Standard::Tolerant, DepthLimit::REFERENCE).unwrap_err();
    assert_eq!(fault.at(), 0);
    assert!(
        matches!(fault.kind(), FaultKind::Growth { len } if len == (admission::MAX + 1) as u64)
    );

    // Output: two lawful answers whose sum breaches the cap, judged
    // at the second append.
    let half = &big[..(admission::MAX / 2) + 1];
    let fault =
        splice(&msg, &mut Big(half), Standard::Tolerant, DepthLimit::REFERENCE).unwrap_err();
    assert_eq!(fault.at(), 2);
    assert!(matches!(fault.kind(), FaultKind::Output { .. }));
}

// ─── the fault type's public face ───

#[test]
fn faults_render_and_chain() {
    use alloc::string::ToString;

    let fault =
        splice(&[0xFF], &mut Identity, Standard::Tolerant, DepthLimit::REFERENCE).unwrap_err();
    assert_eq!(fault.at(), 0);
    assert!(core::error::Error::source(&fault).is_some());
    assert!(!fault.to_string().is_empty());
}
