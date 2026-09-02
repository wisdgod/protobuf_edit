//! The groupless rewirer's module suite: admission judgments,
//! action semantics per record kind, the zero-cascade runtime
//! fault, chunk-split invariance, re-ingestion of the product, and
//! the buffered-rewriter differential on zero-cascade programs.

use alloc::vec::Vec;

use super::{Actions, Fault, Rewirer, RuleFaultKind, WireBreach};
use crate::path::{Program, Segment};
use crate::rewire::{Action, ActionError, Value};
use crate::Standard;
use crate::{DepthLimit, FieldNumber};

fn f(n: u32) -> FieldNumber {
    FieldNumber::new(n).expect("test fields are in class")
}

/// Runs one whole-fed job, collecting the product.
fn rewire(actions: &Actions<'_>, standard: Standard, input: &[u8]) -> Result<Vec<u8>, Fault> {
    let mut out = Vec::new();
    let mut sink = |bytes: &[u8]| out.extend_from_slice(bytes);
    let mut machine = Rewirer::new(actions, standard, DepthLimit::REFERENCE);
    machine.feed(input, &mut sink)?;
    machine.finish()?;
    Ok(out)
}

/// Runs one job split at `at`, collecting the product.
fn rewire_split(
    actions: &Actions<'_>,
    standard: Standard,
    input: &[u8],
    at: usize,
) -> Result<Vec<u8>, Fault> {
    let mut out = Vec::new();
    let mut sink = |bytes: &[u8]| out.extend_from_slice(bytes);
    let mut machine = Rewirer::new(actions, standard, DepthLimit::REFERENCE);
    machine.feed(&input[..at], &mut sink)?;
    machine.feed(&input[at..], &mut sink)?;
    machine.finish()?;
    Ok(out)
}

/// The editing corpus (canonical): varint f1=150 · LEN f2 { varint
/// f3=300 · LEN f4 "hi" } · i32 f5 · i64 f6 · LEN f7 "abc".
const DOC: &[u8] = &[
    0x08, 0x96, 0x01, // f1 varint 150
    0x12, 0x07, 0x18, 0xAC, 0x02, 0x22, 0x02, 0x68, 0x69, // f2 { f3=300 · f4 "hi" }
    0x2D, 0x01, 0x02, 0x03, 0x04, // f5 i32
    0x31, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // f6 i64
    0x3A, 0x03, 0x61, 0x62, 0x63, // f7 LEN "abc"
];

#[test]
fn identity_program_rides_everything_verbatim() {
    // A program targeting an absent field edits nothing.
    let path: [Segment<'_>; 1] = [Segment::Field(f(15))];
    let paths: [&[Segment<'_>]; 1] = [&path];
    let program = Program::over(&paths).unwrap();
    let table = [Action::Delete];
    let actions = Actions::over(&program, &table).unwrap();
    assert_eq!(rewire(&actions, Standard::Tolerant, DOC).unwrap(), DOC);
}

#[test]
fn admission_judges_counts_and_the_groupless_cascade_shape() {
    let single: [Segment<'_>; 1] = [Segment::Field(f(1))];
    let paths: [&[Segment<'_>]; 1] = [&single];
    let program = Program::over(&paths).unwrap();

    // Count equation: one action per path, by index.
    let two = [Action::Delete, Action::Delete];
    assert_eq!(
        Actions::over(&program, &two).err(),
        Some(ActionError::CountMismatch { paths: 1, actions: 2 })
    );

    // A Field-prefixed path puts every match under an entered LEN:
    // structural actions are dead there, refused at authoring.
    let nested: [Segment<'_>; 2] = [Segment::Field(f(2)), Segment::Field(f(3))];
    let nested_paths: [&[Segment<'_>]; 1] = [&nested];
    let nested_program = Program::over(&nested_paths).unwrap();
    for action in [Action::Delete, Action::Insert(&[0x40, 0x01])] {
        assert_eq!(
            Actions::over(&nested_program, &[action]).err(),
            Some(ActionError::CascadeUnsound { path: 0 })
        );
    }
    // The same shape carrying an equal-length action is lawful.
    assert!(Actions::over(&nested_program, &[Action::Rewrite(Value::Varint(7))]).is_ok());

    // A wildcard prefix can match at zero crossings: structural
    // actions keep their root usage, admitted.
    let route = [f(2)];
    let wild: [Segment<'_>; 2] = [Segment::AnyDepth { descend: &route }, Segment::Field(f(3))];
    let wild_paths: [&[Segment<'_>]; 1] = [&wild];
    let wild_program = Program::over(&wild_paths).unwrap();
    assert!(Actions::over(&wild_program, &[Action::Delete]).is_ok());
}

#[test]
fn root_delete_removes_every_record_kind() {
    let p1: [Segment<'_>; 1] = [Segment::Field(f(1))];
    let p5: [Segment<'_>; 1] = [Segment::Field(f(5))];
    let p6: [Segment<'_>; 1] = [Segment::Field(f(6))];
    let p7: [Segment<'_>; 1] = [Segment::Field(f(7))];
    let paths: [&[Segment<'_>]; 4] = [&p1, &p5, &p6, &p7];
    let program = Program::over(&paths).unwrap();
    let table = [Action::Delete; 4];
    let actions = Actions::over(&program, &table).unwrap();
    // Only the untargeted f2 subtree remains.
    assert_eq!(rewire(&actions, Standard::Tolerant, DOC).unwrap(), &DOC[3..12]);
}

#[test]
fn root_insert_is_terminal_bytes_before_a_preserved_record() {
    let path: [Segment<'_>; 1] = [Segment::Field(f(1))];
    let paths: [&[Segment<'_>]; 1] = [&path];
    let program = Program::over(&paths).unwrap();
    let injected = [0x40, 0x01]; // varint f8=1, the caller's declaration
    let table = [Action::Insert(&injected)];
    let actions = Actions::over(&program, &table).unwrap();
    let mut expect = Vec::new();
    expect.extend_from_slice(&injected);
    expect.extend_from_slice(DOC);
    assert_eq!(rewire(&actions, Standard::Tolerant, DOC).unwrap(), expect);
}

#[test]
fn free_rewrites_reemit_minimally_and_locked_rewrites_hold_width() {
    // Free (root): 150 (two bytes) rewrites to 5 at minimal width.
    let root: [Segment<'_>; 1] = [Segment::Field(f(1))];
    let paths: [&[Segment<'_>]; 1] = [&root];
    let program = Program::over(&paths).unwrap();
    let table = [Action::Rewrite(Value::Varint(5))];
    let actions = Actions::over(&program, &table).unwrap();
    let product = rewire(&actions, Standard::Tolerant, DOC).unwrap();
    assert_eq!(&product[..2], &[0x08, 0x05]);
    assert_eq!(&product[2..], &DOC[3..]);

    // Locked (inside the committed f2): the source width holds —
    // 300 (two bytes) rewrites to 5 padded under Tolerant.
    let nested: [Segment<'_>; 2] = [Segment::Field(f(2)), Segment::Field(f(3))];
    let nested_paths: [&[Segment<'_>]; 1] = [&nested];
    let nested_program = Program::over(&nested_paths).unwrap();
    let nested_table = [Action::Rewrite(Value::Varint(5))];
    let nested_actions = Actions::over(&nested_program, &nested_table).unwrap();
    let padded = rewire(&nested_actions, Standard::Tolerant, DOC).unwrap();
    assert_eq!(&padded[5..8], &[0x18, 0x85, 0x00]);
    assert_eq!(padded.len(), DOC.len());

    // The same rewrite under the strict standard is a width
    // mismatch; a three-byte value under Tolerant is an overflow.
    let strict = rewire(&nested_actions, Standard::CanonicalMinimal, DOC).unwrap_err();
    let Fault::Rule(fault) = strict else { panic!("a rule breach, not wire") };
    assert!(matches!(
        fault.kind(),
        RuleFaultKind::RewriteWidthMismatch { path: 0, width: 2, need: 1 }
    ));
    let wide_table = [Action::Rewrite(Value::Varint(100_000))];
    let wide_actions = Actions::over(&nested_program, &wide_table).unwrap();
    let overflow = rewire(&wide_actions, Standard::Tolerant, DOC).unwrap_err();
    let Fault::Rule(fault) = overflow else { panic!("a rule breach, not wire") };
    assert!(matches!(fault.kind(), RuleFaultKind::RewriteOverflow { path: 0, width: 2, need: 3 }));
}

#[test]
fn fixed_rewrites_swap_bits_at_their_one_width() {
    let p5: [Segment<'_>; 1] = [Segment::Field(f(5))];
    let p6: [Segment<'_>; 1] = [Segment::Field(f(6))];
    let paths: [&[Segment<'_>]; 2] = [&p5, &p6];
    let program = Program::over(&paths).unwrap();
    let table =
        [Action::Rewrite(Value::I32(0xAABB_CCDD)), Action::Rewrite(Value::I64(0x1122_3344))];
    let actions = Actions::over(&program, &table).unwrap();
    let product = rewire(&actions, Standard::Tolerant, DOC).unwrap();
    assert_eq!(&product[13..17], &0xAABB_CCDD_u32.to_le_bytes());
    assert_eq!(&product[18..26], &0x1122_3344_u64.to_le_bytes());
    assert_eq!(product.len(), DOC.len());
}

#[test]
fn len_replacement_is_equal_length_at_any_depth() {
    // Root f7 and the locked f4 both take equal-length payloads.
    let p7: [Segment<'_>; 1] = [Segment::Field(f(7))];
    let p24: [Segment<'_>; 2] = [Segment::Field(f(2)), Segment::Field(f(4))];
    let paths: [&[Segment<'_>]; 2] = [&p24, &p7];
    let program = Program::over(&paths).unwrap();
    let table = [Action::Rewrite(Value::Len(b"YO")), Action::Rewrite(Value::Len(b"xyz"))];
    let actions = Actions::over(&program, &table).unwrap();
    let product = rewire(&actions, Standard::Tolerant, DOC).unwrap();
    assert_eq!(&product[10..12], b"YO");
    assert_eq!(&product[28..31], b"xyz");
    assert_eq!(product.len(), DOC.len());

    // A length mismatch is the rule's breach at the record head.
    let short = [Action::Rewrite(Value::Len(b"Y")), Action::Rewrite(Value::Len(b"xyz"))];
    let short_actions = Actions::over(&program, &short).unwrap();
    let fault = rewire(&short_actions, Standard::Tolerant, DOC).unwrap_err();
    let Fault::Rule(fault) = fault else { panic!("a rule breach, not wire") };
    assert_eq!(fault.at(), 8);
    assert!(matches!(fault.kind(), RuleFaultKind::ReplaceLenMismatch { path: 0, got: 1, .. }));
}

#[test]
fn value_kinds_are_judged_at_the_match() {
    // An I32 value bound onto a varint record.
    let p1: [Segment<'_>; 1] = [Segment::Field(f(1))];
    let paths: [&[Segment<'_>]; 1] = [&p1];
    let program = Program::over(&paths).unwrap();
    let table = [Action::Rewrite(Value::I32(7))];
    let actions = Actions::over(&program, &table).unwrap();
    let fault = rewire(&actions, Standard::Tolerant, DOC).unwrap_err();
    let Fault::Rule(fault) = fault else { panic!("a rule breach, not wire") };
    assert_eq!(fault.at(), 0);
    assert!(matches!(fault.kind(), RuleFaultKind::KindMismatch { path: 0 }));

    // A varint value bound onto a LEN record.
    let p7: [Segment<'_>; 1] = [Segment::Field(f(7))];
    let len_paths: [&[Segment<'_>]; 1] = [&p7];
    let len_program = Program::over(&len_paths).unwrap();
    let len_table = [Action::Rewrite(Value::Varint(7))];
    let len_actions = Actions::over(&len_program, &len_table).unwrap();
    let fault = rewire(&len_actions, Standard::Tolerant, DOC).unwrap_err();
    let Fault::Rule(fault) = fault else { panic!("a rule breach, not wire") };
    assert!(matches!(fault.kind(), RuleFaultKind::KindMismatch { path: 0 }));
}

#[test]
fn a_wildcard_structural_action_is_free_at_root_and_faults_descended() {
    let route = [f(2)];
    let wild: [Segment<'_>; 2] = [Segment::AnyDepth { descend: &route }, Segment::Field(f(3))];
    let paths: [&[Segment<'_>]; 1] = [&wild];
    let program = Program::over(&paths).unwrap();
    let table = [Action::Delete];
    let actions = Actions::over(&program, &table).unwrap();

    // A zero-crossing match at the root: the delete is lawful.
    let flat = [0x18, 0x05, 0x20, 0x01]; // varint f3=5 · varint f4=1
    assert_eq!(rewire(&actions, Standard::Tolerant, &flat).unwrap(), [0x20, 0x01]);

    // The same program descended into the committed f2: the match
    // sits under an entered LEN — the declaration breaks there.
    let fault = rewire(&actions, Standard::Tolerant, DOC).unwrap_err();
    let Fault::Rule(fault) = fault else { panic!("a rule breach, not wire") };
    assert_eq!(fault.at(), 5);
    assert!(matches!(fault.kind(), RuleFaultKind::Cascade { path: 0 }));
}

#[test]
fn a_targeted_len_is_opaque_to_deeper_paths() {
    // Path 0 targets f2 whole; path 1 would continue into it. The
    // action covers the record — nothing descends, so the deeper
    // path never fires and no conflict exists.
    let p2: [Segment<'_>; 1] = [Segment::Field(f(2))];
    let p23: [Segment<'_>; 2] = [Segment::Field(f(2)), Segment::Field(f(3))];
    let paths: [&[Segment<'_>]; 2] = [&p2, &p23];
    let program = Program::over(&paths).unwrap();
    let replacement = [0xAA_u8; 7]; // equal to the announced 7
    let table = [Action::Rewrite(Value::Len(&replacement)), Action::Rewrite(Value::Varint(1))];
    let actions = Actions::over(&program, &table).unwrap();
    let product = rewire(&actions, Standard::Tolerant, DOC).unwrap();
    assert_eq!(&product[5..12], &replacement);
    assert_eq!(product.len(), DOC.len());
}

/// The editing program of the sweep and differential judges:
/// delete f1, rewrite the locked f3 equal-width, replace f7.
fn sweep_paths() -> ([Segment<'static>; 1], [Segment<'static>; 2], [Segment<'static>; 1]) {
    ([Segment::Field(f(1))], [Segment::Field(f(2)), Segment::Field(f(3))], [Segment::Field(f(7))])
}

const SWEEP_TABLE: [Action<'static>; 3] = [
    Action::Delete,
    Action::Rewrite(Value::Varint(260)), // two bytes, equal width
    Action::Rewrite(Value::Len(b"xyz")),
];

#[test]
fn chunk_splits_never_move_the_product_or_the_verdict() {
    let (p1, p23, p7) = sweep_paths();
    let paths: [&[Segment<'_>]; 3] = [&p1, &p23, &p7];
    let program = Program::over(&paths).unwrap();
    let actions = Actions::over(&program, &SWEEP_TABLE).unwrap();
    let whole = rewire(&actions, Standard::Tolerant, DOC);
    assert!(whole.is_ok());
    for at in 0..=DOC.len() {
        assert_eq!(
            rewire_split(&actions, Standard::Tolerant, DOC, at),
            whole,
            "split at {at} moved the product"
        );
    }

    // The faulting walk agrees across splits too: a wildcard
    // delete descended under the committed f2.
    let route = [f(2)];
    let wild: [Segment<'_>; 2] = [Segment::AnyDepth { descend: &route }, Segment::Field(f(3))];
    let wild_paths: [&[Segment<'_>]; 1] = [&wild];
    let wild_program = Program::over(&wild_paths).unwrap();
    let wild_actions = Actions::over(&wild_program, &[Action::Delete]).unwrap();
    let whole = rewire(&wild_actions, Standard::Tolerant, DOC);
    assert!(whole.is_err());
    for at in 0..=DOC.len() {
        assert_eq!(
            rewire_split(&wild_actions, Standard::Tolerant, DOC, at),
            whole,
            "split at {at} moved the verdict"
        );
    }
}

#[cfg(feature = "scan-groupless")]
#[test]
fn the_product_reingests_under_the_declared_standard() {
    use crate::scan::groupless::Validator;

    let (p1, p23, p7) = sweep_paths();
    let paths: [&[Segment<'_>]; 3] = [&p1, &p23, &p7];
    let program = Program::over(&paths).unwrap();
    let actions = Actions::over(&program, &SWEEP_TABLE).unwrap();
    for standard in [Standard::Tolerant, Standard::CanonicalMinimal] {
        let product = rewire(&actions, standard, DOC).unwrap();
        let mut gate = Validator::new(standard);
        gate.feed(&product).unwrap();
        gate.finish().unwrap();
    }
}

/// The buffered rewriter is the independent oracle on zero-cascade
/// programs fed whole: equal-width rewrites and root deletes leave
/// every container length unchanged, so the streaming machine and
/// the two-pass machine must emit identical bytes.
#[cfg(feature = "rewrite-groupless")]
#[test]
fn the_buffered_rewriter_agrees_on_zero_cascade_programs() {
    use crate::rewrite::{self, Rule, RuleSet};

    let (p1, p23, p7) = sweep_paths();
    let paths: [&[Segment<'_>]; 3] = [&p1, &p23, &p7];
    let program = Program::over(&paths).unwrap();
    let actions = Actions::over(&program, &SWEEP_TABLE).unwrap();
    let streamed = rewire(&actions, Standard::Tolerant, DOC).unwrap();

    let rules = [
        Rule { path: &p1, action: rewrite::Action::Delete },
        Rule { path: &p23, action: rewrite::Action::Replace(rewrite::Value::Varint(260)) },
        Rule { path: &p7, action: rewrite::Action::Replace(rewrite::Value::Len(b"xyz")) },
    ];
    let set = RuleSet::over(&rules).unwrap();
    let (buffered, _) = rewrite::groupless::rewrite(DOC, &set, DepthLimit::REFERENCE).unwrap();
    assert_eq!(streamed, buffered);
}

// The fixture stages a real 2 GiB replacement: 32-bit targets
// cannot host it, and under Miri it is byte-bulk without
// provenance value. The refusal arithmetic itself is
// target-independent.
#[cfg(all(not(target_family = "wasm"), not(miri)))]
#[test]
fn admission_refuses_replacements_outside_the_len_class() {
    use crate::wire::PayloadLen;

    let path: [Segment<'_>; 1] = [Segment::Field(f(7))];
    let paths: [&[Segment<'_>]; 1] = [&path];
    let program = Program::over(&paths).unwrap();
    let big = alloc::vec![0u8; usize::try_from(PayloadLen::MAX.as_inner()).unwrap() + 1];
    let table = [Action::Rewrite(Value::Len(&big))];
    assert_eq!(
        Actions::over(&program, &table).err(),
        Some(ActionError::OversizeReplacement { path: 0 })
    );
}

#[test]
fn group_codes_are_a_capability_refusal() {
    let path: [Segment<'_>; 1] = [Segment::Field(f(1))];
    let paths: [&[Segment<'_>]; 1] = [&path];
    let program = Program::over(&paths).unwrap();
    let actions = Actions::over(&program, &[Action::Delete]).unwrap();
    let fault = rewire(&actions, Standard::Tolerant, &[0x0B, 0x0C]).unwrap_err();
    assert!(matches!(fault, Fault::Wire { at: 0, breach: WireBreach::GroupCode }));
    assert_eq!(WireBreach::GroupCode.class(), crate::FaultClass::Capability);
}

#[test]
fn the_rewirer_holds_no_stream_content() {
    // The zero-buffering claim's layout half: the machine is the
    // pump, the resume mode, the LEN frame stack, the bound, the
    // matcher, the action table, and the six-byte staged head —
    // no content buffer field exists to grow with the stream.
    // (The allocation half — feeds of content-heavy streams grow
    // nothing — is the integration probe under the counting
    // allocator.)
    #[cfg(target_pointer_width = "64")]
    assert_eq!(core::mem::size_of::<Rewirer<'_>>(), 264);
    #[cfg(not(target_pointer_width = "64"))]
    assert!(core::mem::size_of::<Rewirer<'_>>() <= 264);
}
