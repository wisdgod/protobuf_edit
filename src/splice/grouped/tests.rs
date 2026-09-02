//! The grouped splicer's module suite.

use alloc::vec::Vec;

use super::{FaultKind, Group, Rule, WireBreach, splice, splice_into, splice_sink};
use crate::splice::{Len, Scalar};
use crate::wire::FieldNumber;
use crate::{DepthLimit, Standard};

/// The identity rule: keeps and passes everything.
#[derive(Clone)]
struct Identity;
impl Rule for Identity {}

/// Both faces over the same job under `standard`, agreement
/// asserted.
fn faces_std<R: Rule + Clone>(input: &[u8], rule: &R, standard: Standard) -> Vec<u8> {
    let vec_face = splice(input, &mut rule.clone(), standard, DepthLimit::REFERENCE).unwrap();
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
    faces_std(input, rule, Standard::Tolerant)
}

// group f1 { varint f2 = 150, group f3 { i32 f4 } }, varint f5 = 7
const NESTED: [u8; 14] = [0x0B, 0x10, 0x96, 0x01, 0x1B, 0x25, 1, 2, 3, 4, 0x1C, 0x0C, 0x28, 0x07];

fn nested() -> &'static [u8] {
    &NESTED
}

#[test]
fn identity_rides_groups_verbatim() {
    assert_eq!(both(nested(), &Identity), nested());
}

#[test]
fn a_passed_group_silences_interior_asks() {
    // Pass the group whole; the rewrite rule must never be asked
    // about the varint inside it — the sibling outside rewrites.
    #[derive(Clone)]
    struct RewriteOutside;
    impl Rule for RewriteOutside {
        fn on_varint(&mut self, at: u32, _field: FieldNumber, _value: u64) -> Scalar<'_, u64> {
            assert!(at == 12, "asked inside a passed group");
            Scalar::Rewrite(9)
        }
    }
    let out = both(nested(), &RewriteOutside);
    let mut want = nested().to_vec();
    want[13] = 0x09;
    assert_eq!(out, want);
}

#[test]
fn an_edit_inside_a_committed_group_cascades_nothing() {
    // Enter both groups, grow the varint inside: group framing has
    // no length prefix, so the group bytes shift with no settle.
    #[derive(Clone)]
    struct Grow;
    impl Rule for Grow {
        fn on_group_enter(&mut self, _at: u32, _field: FieldNumber) -> Group<'_> {
            Group::Commit
        }
        fn on_varint(&mut self, at: u32, _field: FieldNumber, value: u64) -> Scalar<'_, u64> {
            if at == 1 { Scalar::Rewrite(value + 128) } else { Scalar::Keep }
        }
    }
    let out = both(nested(), &Grow);
    let want = [0x0B, 0x10, 0x96, 0x02, 0x1B, 0x25, 1, 2, 3, 4, 0x1C, 0x0C, 0x28, 0x07];
    assert_eq!(out, want);
}

#[test]
fn a_dropped_group_under_a_commit_settles_the_prefix() {
    // f1 LEN { group f2 { varint f3 = 1 } } — commit the LEN, drop
    // the group: the container empties and its prefix re-authors,
    // with the drop as the only interior event (the overlay face's
    // claim must come from the drop itself).
    #[derive(Clone)]
    struct DropGroup;
    impl Rule for DropGroup {
        fn on_len(&mut self, _at: u32, _field: FieldNumber, _payload: &[u8]) -> Len<'_> {
            Len::Commit { tail: None }
        }
        fn on_group_enter(&mut self, _at: u32, _field: FieldNumber) -> Group<'_> {
            Group::Drop
        }
    }
    let msg = [0x0A, 0x04, 0x13, 0x18, 0x01, 0x14];
    assert_eq!(both(&msg, &DropGroup), [0x0A, 0x00]);
}

#[test]
fn a_grown_len_inside_a_committed_group_cascades_through_it() {
    // f1 LEN { group f2 { f3 LEN "hi" } } — commit the LEN and the
    // group, grow the inner LEN: the group is length-transparent,
    // so only f1's prefix settles (4 → 7).
    #[derive(Clone)]
    struct GrowInner;
    impl Rule for GrowInner {
        fn on_len<'a>(&'a mut self, at: u32, _field: FieldNumber, _payload: &'a [u8]) -> Len<'a> {
            if at == 0 { Len::Commit { tail: None } } else { Len::Replace(b"grown") }
        }
        fn on_group_enter(&mut self, _at: u32, _field: FieldNumber) -> Group<'_> {
            Group::Commit
        }
    }
    let msg = [0x0A, 0x06, 0x13, 0x1A, 0x02, 0x68, 0x69, 0x14];
    let out = both(&msg, &GrowInner);
    assert_eq!(out, [0x0A, 0x09, 0x13, 0x1A, 0x05, b'g', b'r', b'o', b'w', b'n', 0x14]);
}

#[test]
fn groups_and_commits_spend_one_depth_account() {
    // Budget 1: a committed group exhausts it, so a LEN commit
    // inside the group hits the wall — and vice versa. Passing at
    // the wall stays lawful (only entering costs).
    #[derive(Clone)]
    struct CommitEverything;
    impl Rule for CommitEverything {
        fn on_len<'a>(&'a mut self, _at: u32, _field: FieldNumber, _payload: &'a [u8]) -> Len<'a> {
            Len::Commit { tail: None }
        }
        fn on_group_enter(&mut self, _at: u32, _field: FieldNumber) -> Group<'_> {
            Group::Commit
        }
    }
    let limit = DepthLimit::new(1).unwrap();

    // group f1 { f2 LEN {} }: the group spends the budget, the
    // commit ask at byte 1 refuses.
    let group_first = [0x0B, 0x12, 0x00, 0x0C];
    let fault =
        splice(&group_first, &mut CommitEverything.clone(), Standard::Tolerant, limit).unwrap_err();
    assert_eq!(fault.at(), 1);
    assert!(matches!(fault.kind(), FaultKind::Wire(WireBreach::Depth)));

    // f1 LEN { group f2 {} }: the commit spends the budget, the
    // group enter at byte 2 refuses.
    let len_first = [0x0A, 0x02, 0x13, 0x14];
    let fault = splice(&len_first, &mut CommitEverything, Standard::Tolerant, limit).unwrap_err();
    assert_eq!(fault.at(), 2);
    assert!(matches!(fault.kind(), FaultKind::Wire(WireBreach::Depth)));

    // The same documents ride whole under the identity (Pass at
    // the wall is lawful).
    assert_eq!(both(&group_first, &Identity), group_first);
    let mut pass_inner = CommitOuterPassRest;
    let out = splice(&len_first, &mut pass_inner, Standard::Tolerant, limit).unwrap();
    assert_eq!(out, len_first);
}

/// Commits the record at byte 0, passes everything deeper.
#[derive(Clone)]
struct CommitOuterPassRest;
impl Rule for CommitOuterPassRest {
    fn on_len<'a>(&'a mut self, at: u32, _field: FieldNumber, _payload: &'a [u8]) -> Len<'a> {
        if at == 0 { Len::Commit { tail: None } } else { Len::Pass }
    }
}

#[test]
fn one_ask_per_record_and_exits_are_punctuation() {
    // Logs (offset, kind letter) for every ask; group exits must
    // never appear.
    #[derive(Clone, Default)]
    struct Log(Vec<(u32, u8)>);
    impl Rule for Log {
        fn on_varint(&mut self, at: u32, _field: FieldNumber, _value: u64) -> Scalar<'_, u64> {
            self.0.push((at, b'v'));
            Scalar::Keep
        }
        fn on_i32(&mut self, at: u32, _field: FieldNumber, _bits: u32) -> Scalar<'_, u32> {
            self.0.push((at, b'f'));
            Scalar::Keep
        }
        fn on_len<'a>(&'a mut self, at: u32, _field: FieldNumber, _payload: &'a [u8]) -> Len<'a> {
            self.0.push((at, b'l'));
            Len::Commit { tail: None }
        }
        fn on_group_enter(&mut self, at: u32, _field: FieldNumber) -> Group<'_> {
            self.0.push((at, b'g'));
            Group::Commit
        }
    }
    // f1 LEN { group f2 { f3 varint 1 } } · f4 i32
    let msg = [0x0A, 0x04, 0x13, 0x18, 0x01, 0x14, 0x25, 1, 2, 3, 4];
    let mut rule = Log::default();
    let out = splice(&msg, &mut rule, Standard::Tolerant, DepthLimit::REFERENCE).unwrap();
    assert_eq!(out, msg);
    assert_eq!(rule.0, [(0, b'l'), (2, b'g'), (3, b'v'), (6, b'f')]);

    let mut sink_rule = Log::default();
    splice_sink(&msg, &mut sink_rule, Standard::Tolerant, DepthLimit::REFERENCE, |_| {}).unwrap();
    assert_eq!(sink_rule.0, rule.0);
}

/// The buffered path-driven rewriter is the independent oracle on
/// edits both machines spell: a group delete and a varint rewrite
/// through a pure group chain.
#[cfg(feature = "rewrite-grouped")]
#[test]
fn the_path_driven_rewriter_agrees_on_group_edits() {
    use crate::path::Segment;
    use crate::rewrite::{self, RuleSet};

    let f = |n: u32| FieldNumber::new(n).unwrap();

    #[derive(Clone)]
    struct Edits;
    impl Rule for Edits {
        fn on_group_enter(&mut self, _at: u32, field: FieldNumber) -> Group<'_> {
            match field.as_inner() {
                3 => Group::Drop,
                _ => Group::Commit,
            }
        }
        fn on_varint(&mut self, _at: u32, field: FieldNumber, _value: u64) -> Scalar<'_, u64> {
            if field.as_inner() == 2 { Scalar::Rewrite(300) } else { Scalar::Keep }
        }
    }
    let spliced = both(nested(), &Edits);

    let p2: [Segment<'_>; 2] = [Segment::Field(f(1)), Segment::Field(f(2))];
    let p3: [Segment<'_>; 2] = [Segment::Field(f(1)), Segment::Field(f(3))];
    let rules = [
        rewrite::Rule { path: &p2, action: rewrite::Action::Replace(rewrite::Value::Varint(300)) },
        rewrite::Rule { path: &p3, action: rewrite::Action::Delete },
    ];
    let set = RuleSet::over(&rules).unwrap();
    let (rewritten, _) = rewrite::grouped::rewrite(nested(), &set, DepthLimit::REFERENCE).unwrap();
    assert_eq!(spliced, rewritten);
}

/// The handle-driven one-shot patch is the independent oracle on
/// every online arc both machines spell, groups included: edits
/// inside a committed group, whole-group drops and insertions, and
/// a cascade that flows through a group into its LEN ancestor —
/// the family's minimal-re-author law, pinned across machines.
#[cfg(feature = "patch-grouped")]
#[test]
fn the_handle_driven_patch_agrees_on_online_arcs() {
    use crate::patch::grouped::{Descent, InsertAt, Patch};

    // group f1 { f2 varint 150 · group f3 { f4 i32 } } · f5 varint ·
    // f6 LEN "abc" · group f7 { f2 varint 1 } · f8 varint ·
    // f10 LEN { group f11 { f2 varint 150 } }
    let msg = [
        0x0B, // group f1 start                        head 0
        0x10, 0x96, 0x01, // f2 varint 150             head 1
        0x1B, 0x25, 0x01, 0x02, 0x03, 0x04, 0x1C, // group f3 { f4 i32 }  head 4
        0x0C, // group f1 end                          11
        0x28, 0x05, // f5 varint 5                     head 12
        0x32, 0x03, b'a', b'b', b'c', // f6 LEN        head 14
        0x3B, 0x10, 0x01, 0x3C, // group f7 { f2 }     head 19
        0x40, 0x2A, // f8 varint 42                    head 23
        0x52, 0x05, 0x5B, 0x10, 0x96, 0x01, 0x5C, // f10 LEN { group f11 { f2 } }  head 25
    ];
    let (f2, f9) = (FieldNumber::new(2).unwrap(), FieldNumber::new(9).unwrap());

    #[derive(Clone)]
    struct Edits;
    impl Rule for Edits {
        fn on_group_enter(&mut self, _at: u32, field: FieldNumber) -> Group<'_> {
            match field.as_inner() {
                1 | 11 => Group::Commit,
                _ => Group::Drop, // f3 inside the commit, f7 whole
            }
        }
        fn on_varint(&mut self, _at: u32, field: FieldNumber, _value: u64) -> Scalar<'_, u64> {
            match field.as_inner() {
                2 => Scalar::Rewrite(7),   // shrinks: free under group framing
                5 => Scalar::Rewrite(300), // grows at the root
                8 => Scalar::Insert(&[0x4B, 0x10, 0x07, 0x4C]), // group f9 { f2 varint 7 }
                _ => Scalar::Keep,
            }
        }
        fn on_len(&mut self, _at: u32, field: FieldNumber, _payload: &[u8]) -> Len<'_> {
            match field.as_inner() {
                6 => Len::Replace(b"xyzzy"),
                10 => Len::Commit { tail: None },
                _ => Len::Pass,
            }
        }
    }
    let spliced = both(&msg, &Edits);

    let mut patch = Patch::open(&msg, DepthLimit::REFERENCE).unwrap();
    let tops: Vec<_> = patch.top().collect();
    // Groups materialize eagerly: group f1's interior is addressable
    // without a descend.
    let f1_kids: Vec<_> = patch.children(tops[0]).collect();
    patch.set_varint(f1_kids[0], 7).unwrap();
    patch.delete(f1_kids[1]).unwrap();
    patch.set_varint(tops[1], 300).unwrap();
    patch.set_payload(tops[2], b"xyzzy").unwrap();
    patch.delete(tops[3]).unwrap();
    let group = patch.insert_group(InsertAt::After(tops[3]), f9).unwrap();
    patch.insert_varint(InsertAt::TailOf(Some(group)), f2, 7).unwrap();
    let Descent::Opened { first: Some(f11) } = patch.descend(tops[5]).unwrap() else {
        unreachable!()
    };
    let f11_kids: Vec<_> = patch.children(f11).collect();
    patch.set_varint(f11_kids[0], 7).unwrap();
    assert_eq!(spliced, patch.save().unwrap());
}

/// The streaming transcoder fed whole is the independent oracle on
/// the zero-cascade subset, groups included: group framing carries
/// no length, so whole-tree edits along pure group chains — drops,
/// variable-length rewrites, insertions — cascade nothing in either
/// machine.
#[cfg(feature = "transcode-grouped")]
#[test]
fn the_streaming_transcoder_agrees_on_zero_cascade_verdicts() {
    use crate::transcode::grouped::{FreeGroup, Rule as TRule, Transcoder};
    use crate::transcode::{FreeLen, FreeScalar, LockedScalar};

    // group f1 { f2 varint 150 · group f3 { f4 i32 } } · f5 varint ·
    // f6 LEN "abc" · f7 LEN { f9 varint 5 }
    let msg = [
        0x0B, // group f1 start                        head 0
        0x10, 0x96, 0x01, // f2 varint 150             head 1
        0x1B, 0x25, 0x01, 0x02, 0x03, 0x04, 0x1C, // group f3 { f4 i32 }  head 4
        0x0C, // group f1 end                          11
        0x28, 0x05, // f5 varint 5                     head 12
        0x32, 0x03, b'a', b'b', b'c', // f6 LEN        head 14
        0x3A, 0x02, 0x48, 0x05, // f7 LEN { f9 }       head 19
    ];

    #[derive(Clone)]
    struct Verdicts;
    impl Rule for Verdicts {
        fn on_group_enter(&mut self, _at: u32, field: FieldNumber) -> Group<'_> {
            if field.as_inner() == 3 { Group::Drop } else { Group::Commit }
        }
        fn on_varint(&mut self, _at: u32, field: FieldNumber, _value: u64) -> Scalar<'_, u64> {
            match field.as_inner() {
                2 => Scalar::Rewrite(7),            // shrinks: free under group framing
                5 => Scalar::Insert(&[0x40, 0x2A]), // f8 varint 42, before f5
                9 => Scalar::Rewrite(9),            // equal width under the committed f7
                _ => Scalar::Keep,
            }
        }
        fn on_len(&mut self, _at: u32, field: FieldNumber, _payload: &[u8]) -> Len<'_> {
            match field.as_inner() {
                6 => Len::Replace(b"xyz"), // equal length
                7 => Len::Commit { tail: None },
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
        fn on_group(&mut self, _at: u64, field: FieldNumber) -> FreeGroup<'_> {
            if field.as_inner() == 3 { FreeGroup::Drop } else { FreeGroup::Keep }
        }
        fn on_varint(
            &mut self,
            _at: u64,
            field: FieldNumber,
            _value: u64,
            _width: u8,
        ) -> FreeScalar<'_, u64> {
            match field.as_inner() {
                2 => FreeScalar::Rewrite(7),
                5 if !self.inserted => {
                    self.inserted = true;
                    FreeScalar::Insert(&[0x40, 0x2A])
                }
                _ => FreeScalar::Keep,
            }
        }
        fn on_len(&mut self, _at: u64, field: FieldNumber, _len: crate::PayloadLen) -> FreeLen<'_> {
            match field.as_inner() {
                6 => FreeLen::Replace(b"xyz"),
                7 => FreeLen::Commit,
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
            LockedScalar::Rewrite(9)
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

#[test]
fn edited_output_re_ingests_under_both_standards() {
    use crate::cursor::GroupDepth;
    use crate::cursor::grouped::{Cursor, EntryKind};

    #[derive(Clone)]
    struct Edits;
    impl Rule for Edits {
        fn on_group_enter(&mut self, at: u32, _field: FieldNumber) -> Group<'_> {
            if at == 4 { Group::Drop } else { Group::Commit }
        }
        fn on_varint(&mut self, at: u32, _field: FieldNumber, value: u64) -> Scalar<'_, u64> {
            if at == 1 { Scalar::Rewrite(value + 200) } else { Scalar::Keep }
        }
    }
    // The reference bound through the union-gated conversion: the
    // named constant is the traverse cell's own face.
    let depth = GroupDepth::from(DepthLimit::REFERENCE);
    for standard in [Standard::Tolerant, Standard::CanonicalMinimal] {
        let out = faces_std(nested(), &Edits, standard);
        let mut stack = alloc::vec![Cursor::over(&out, depth).unwrap()];
        while let Some(cursor) = stack.last_mut() {
            match cursor.step::<true>() {
                Some(Ok(entry)) => {
                    if let EntryKind::Len(payload) = entry.kind() {
                        stack.push(Cursor::within(payload, depth));
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

#[test]
fn a_commit_tail_lands_inside_a_group_bearing_container() {
    // Commit the LEN with a tail; its interior is a passed group —
    // the tail lands after the group's exit, inside the container.
    #[derive(Clone)]
    struct Tail;
    impl Rule for Tail {
        fn on_len<'a>(&'a mut self, _at: u32, _field: FieldNumber, _payload: &'a [u8]) -> Len<'a> {
            Len::Commit { tail: Some(&[0x18, 0x2A]) }
        }
    }
    // f1 LEN { group f2 { } }
    let msg = [0x0A, 0x02, 0x13, 0x14];
    let out = both(&msg, &Tail);
    assert_eq!(out, [0x0A, 0x04, 0x13, 0x14, 0x18, 0x2A]);
}

// ─── fault contracts on the fallible faces ───

#[test]
fn the_append_face_truncates_to_its_mark_and_the_sink_receives_nothing_on_err() {
    #[derive(Clone)]
    struct FaultyLate;
    impl Rule for FaultyLate {}
    // A lawful group rides first, then a torn varint: records emit
    // into the plan before the fault, so the rollback and the
    // preflight both have something to discard.
    let msg = [0x13, 0x18, 0x2A, 0x14, 0x10, 0x05, 0xFF];
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

#[test]
fn an_inserted_group_rides_verbatim_after_the_bytes() {
    // Insert a scalar before the group; the group then rides whole
    // with asks silenced.
    #[derive(Clone)]
    struct InsertBefore;
    impl Rule for InsertBefore {
        fn on_group_enter(&mut self, at: u32, _field: FieldNumber) -> Group<'_> {
            if at == 0 { Group::Insert(&[0x30, 0x2A]) } else { Group::Pass }
        }
        fn on_varint(&mut self, at: u32, _field: FieldNumber, _value: u64) -> Scalar<'_, u64> {
            assert!(at == 12, "asked inside an inserted group's verbatim ride");
            Scalar::Keep
        }
    }
    let out = both(nested(), &InsertBefore);
    let mut want = alloc::vec![0x30, 0x2A];
    want.extend_from_slice(nested());
    assert_eq!(out, want);
}
