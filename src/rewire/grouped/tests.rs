//! The grouped rewirer's module suite: group-tree actions, the
//! free layer through pure group chains, the cascade fault under
//! entered LENs, chunk-split invariance, re-ingestion, and the
//! buffered-rewriter differential on zero-cascade programs.

use alloc::vec::Vec;

use super::{Actions, Fault, Rewirer, RuleFaultKind, WireBreach};
use crate::path::{Program, Segment};
use crate::rewire::{Action, Value};
use crate::Standard;
use crate::{DepthLimit, FieldNumber};

fn f(n: u32) -> FieldNumber {
    FieldNumber::new(n).expect("test fields are in class")
}

/// Runs one whole-fed job, collecting the product.
fn rewire(actions: &Actions<'_>, standard: Standard, input: &[u8]) -> Result<Vec<u8>, Fault> {
    rewire_bounded(actions, standard, input, DepthLimit::REFERENCE)
}

fn rewire_bounded(
    actions: &Actions<'_>,
    standard: Standard,
    input: &[u8],
    limit: DepthLimit,
) -> Result<Vec<u8>, Fault> {
    let mut out = Vec::new();
    let mut sink = |bytes: &[u8]| out.extend_from_slice(bytes);
    let mut machine = Rewirer::new(actions, standard, limit);
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

/// The editing corpus (canonical): group f1 { varint f2=150 ·
/// group f3 { varint f2=7 } } · varint f4=5 · LEN f5 "hi".
const DOC: &[u8] = &[
    0x0B, // group f1 open
    0x10, 0x96, 0x01, // varint f2=150
    0x1B, 0x10, 0x07, 0x1C, // group f3 { varint f2=7 }
    0x0C, // group f1 close
    0x20, 0x05, // varint f4=5
    0x2A, 0x02, 0x68, 0x69, // LEN f5 "hi"
];

#[test]
fn identity_program_rides_group_framing_verbatim() {
    let path: [Segment<'_>; 1] = [Segment::Field(f(15))];
    let paths: [&[Segment<'_>]; 1] = [&path];
    let program = Program::over(&paths).unwrap();
    let table = [Action::Delete];
    let actions = Actions::over(&program, &table).unwrap();
    assert_eq!(rewire(&actions, Standard::Tolerant, DOC).unwrap(), DOC);
}

#[test]
fn admission_admits_every_shape_for_structural_actions() {
    // A Field-prefixed path may cross groups here: variable-length
    // actions are admitted, the judgment moves to the match.
    let nested: [Segment<'_>; 2] = [Segment::Field(f(1)), Segment::Field(f(2))];
    let paths: [&[Segment<'_>]; 1] = [&nested];
    let program = Program::over(&paths).unwrap();
    assert!(Actions::over(&program, &[Action::Delete]).is_ok());
    assert!(Actions::over(&program, &[Action::Insert(&[0x20, 0x01])]).is_ok());
}

#[test]
fn deleting_a_group_removes_its_whole_tree() {
    let path: [Segment<'_>; 1] = [Segment::Field(f(1))];
    let paths: [&[Segment<'_>]; 1] = [&path];
    let program = Program::over(&paths).unwrap();
    let table = [Action::Delete];
    let actions = Actions::over(&program, &table).unwrap();
    assert_eq!(rewire(&actions, Standard::Tolerant, DOC).unwrap(), &DOC[9..]);
}

#[test]
fn structural_edits_are_free_through_pure_group_chains() {
    // Delete f2 everywhere under the group chain: both the direct
    // child and the doubly-nested one vanish, framing stays.
    let direct: [Segment<'_>; 2] = [Segment::Field(f(1)), Segment::Field(f(2))];
    let deep: [Segment<'_>; 3] = [Segment::Field(f(1)), Segment::Field(f(3)), Segment::Field(f(2))];
    let paths: [&[Segment<'_>]; 2] = [&direct, &deep];
    let program = Program::over(&paths).unwrap();
    let table = [Action::Delete, Action::Delete];
    let actions = Actions::over(&program, &table).unwrap();
    assert_eq!(
        rewire(&actions, Standard::Tolerant, DOC).unwrap(),
        [0x0B, 0x1B, 0x1C, 0x0C, 0x20, 0x05, 0x2A, 0x02, 0x68, 0x69]
    );
}

#[test]
fn group_insertion_is_terminal_and_the_tree_still_walks() {
    // Insert before the group; a second path edits inside it — the
    // tree rides as if unmatched, so the interior rule still fires.
    let group: [Segment<'_>; 1] = [Segment::Field(f(1))];
    let inner: [Segment<'_>; 2] = [Segment::Field(f(1)), Segment::Field(f(2))];
    let paths: [&[Segment<'_>]; 2] = [&group, &inner];
    let program = Program::over(&paths).unwrap();
    let injected = [0x20, 0x2A]; // varint f4=42
    let table = [Action::Insert(&injected), Action::Rewrite(Value::Varint(9))];
    let actions = Actions::over(&program, &table).unwrap();
    let product = rewire(&actions, Standard::Tolerant, DOC).unwrap();
    let mut expect = Vec::new();
    expect.extend_from_slice(&injected);
    expect.extend_from_slice(DOC);
    // The interior f2 rewrote minimally at its free (group) layer:
    // 150 (two bytes) became 9 (one byte), two bytes after the
    // injected pair and the open tag.
    expect.splice(4..6, [0x09]);
    assert_eq!(product, expect);
}

#[test]
fn a_rewrite_bound_onto_a_group_is_a_kind_mismatch() {
    let path: [Segment<'_>; 1] = [Segment::Field(f(1))];
    let paths: [&[Segment<'_>]; 1] = [&path];
    let program = Program::over(&paths).unwrap();
    let table = [Action::Rewrite(Value::Varint(1))];
    let actions = Actions::over(&program, &table).unwrap();
    let fault = rewire(&actions, Standard::Tolerant, DOC).unwrap_err();
    let Fault::Rule(fault) = fault else { panic!("a rule breach, not wire") };
    assert_eq!(fault.at(), 0);
    assert!(matches!(fault.kind(), RuleFaultKind::KindMismatch { path: 0 }));
}

#[test]
fn structural_actions_fault_under_an_entered_len() {
    // "f1 is a group" declared by the path; the document spells f1
    // as a LEN — the free-ancestry declaration breaks at the match.
    let path: [Segment<'_>; 2] = [Segment::Field(f(1)), Segment::Field(f(2))];
    let paths: [&[Segment<'_>]; 1] = [&path];
    let program = Program::over(&paths).unwrap();
    let table = [Action::Delete];
    let actions = Actions::over(&program, &table).unwrap();
    let msg = [0x0A, 0x02, 0x10, 0x07]; // LEN f1 { varint f2=7 }
    let fault = rewire(&actions, Standard::Tolerant, &msg).unwrap_err();
    let Fault::Rule(fault) = fault else { panic!("a rule breach, not wire") };
    assert_eq!(fault.at(), 2);
    assert!(matches!(fault.kind(), RuleFaultKind::Cascade { path: 0 }));

    // A group under an entered LEN is equally sealed: deleting it
    // would move the announced length.
    let group_under_len: [Segment<'_>; 2] = [Segment::Field(f(1)), Segment::Field(f(3))];
    let gl_paths: [&[Segment<'_>]; 1] = [&group_under_len];
    let gl_program = Program::over(&gl_paths).unwrap();
    let gl_actions = Actions::over(&gl_program, &[Action::Delete]).unwrap();
    let msg = [0x0A, 0x02, 0x1B, 0x1C]; // LEN f1 { group f3 {} }
    let fault = rewire(&gl_actions, Standard::Tolerant, &msg).unwrap_err();
    let Fault::Rule(fault) = fault else { panic!("a rule breach, not wire") };
    assert!(matches!(fault.kind(), RuleFaultKind::Cascade { path: 0 }));
}

#[test]
fn equal_length_rewrites_stay_lawful_under_entered_lens() {
    // Committed LEN f1 { varint f2=300 }: an equal-width rewrite
    // holds the record's width, padded under Tolerant.
    let path: [Segment<'_>; 2] = [Segment::Field(f(1)), Segment::Field(f(2))];
    let paths: [&[Segment<'_>]; 1] = [&path];
    let program = Program::over(&paths).unwrap();
    let table = [Action::Rewrite(Value::Varint(5))];
    let actions = Actions::over(&program, &table).unwrap();
    let msg = [0x0A, 0x03, 0x10, 0xAC, 0x02]; // LEN f1 { varint f2=300 }
    let product = rewire(&actions, Standard::Tolerant, &msg).unwrap();
    assert_eq!(product, [0x0A, 0x03, 0x10, 0x85, 0x00]);
}

#[test]
fn an_unclosed_group_faults_at_the_len_endpoint() {
    // A path routes into the LEN, so the machine enters it and
    // owns the endpoint judgment: a group still open there is the
    // grouping breach.
    let path: [Segment<'_>; 2] = [Segment::Field(f(1)), Segment::Field(f(9))];
    let paths: [&[Segment<'_>]; 1] = [&path];
    let program = Program::over(&paths).unwrap();
    let actions = Actions::over(&program, &[Action::Rewrite(Value::Varint(1))]).unwrap();
    let msg = [0x0A, 0x01, 0x1B]; // LEN f1 { group f3 open, never closed }
    let fault = rewire(&actions, Standard::Tolerant, &msg).unwrap_err();
    assert!(matches!(fault, Fault::Wire { at: 3, breach: WireBreach::Grouping }));
}

#[test]
fn nesting_spends_the_one_depth_budget() {
    let path: [Segment<'_>; 1] = [Segment::Field(f(15))];
    let paths: [&[Segment<'_>]; 1] = [&path];
    let program = Program::over(&paths).unwrap();
    let actions = Actions::over(&program, &[Action::Delete]).unwrap();
    // group f1 { group f3 {} }: two levels against a bound of one.
    let msg = [0x0B, 0x1B, 0x1C, 0x0C];
    let fault = rewire_bounded(&actions, Standard::Tolerant, &msg, DepthLimit::MIN).unwrap_err();
    assert!(matches!(fault, Fault::Wire { at: 1, breach: WireBreach::Depth }));
}

/// The editing program of the sweep and differential judges:
/// rewrite the group-nested f2 minimally, delete the root f4,
/// replace f5 equal-length.
fn sweep_paths() -> ([Segment<'static>; 2], [Segment<'static>; 1], [Segment<'static>; 1]) {
    ([Segment::Field(f(1)), Segment::Field(f(2))], [Segment::Field(f(4))], [Segment::Field(f(5))])
}

const SWEEP_TABLE: [Action<'static>; 3] =
    [Action::Rewrite(Value::Varint(9)), Action::Delete, Action::Rewrite(Value::Len(b"YO"))];

#[test]
fn chunk_splits_never_move_the_product_or_the_verdict() {
    let (p12, p4, p5) = sweep_paths();
    let paths: [&[Segment<'_>]; 3] = [&p12, &p4, &p5];
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

    // The faulting walk agrees across splits too.
    let cascade: [Segment<'_>; 2] = [Segment::Field(f(1)), Segment::Field(f(2))];
    let c_paths: [&[Segment<'_>]; 1] = [&cascade];
    let c_program = Program::over(&c_paths).unwrap();
    let c_actions = Actions::over(&c_program, &[Action::Delete]).unwrap();
    let msg = [0x0A, 0x02, 0x10, 0x07];
    let whole = rewire(&c_actions, Standard::Tolerant, &msg);
    assert!(whole.is_err());
    for at in 0..=msg.len() {
        assert_eq!(
            rewire_split(&c_actions, Standard::Tolerant, &msg, at),
            whole,
            "split at {at} moved the verdict"
        );
    }
}

#[cfg(feature = "scan-grouped")]
#[test]
fn the_product_reingests_under_the_declared_standard() {
    use crate::scan::grouped::Validator;

    let (p12, p4, p5) = sweep_paths();
    let paths: [&[Segment<'_>]; 3] = [&p12, &p4, &p5];
    let program = Program::over(&paths).unwrap();
    let actions = Actions::over(&program, &SWEEP_TABLE).unwrap();
    for standard in [Standard::Tolerant, Standard::CanonicalMinimal] {
        let product = rewire(&actions, standard, DOC).unwrap();
        let mut gate = Validator::new(standard, DepthLimit::REFERENCE);
        gate.feed(&product).unwrap();
        gate.finish().unwrap();
    }
}

/// The buffered rewriter is the independent oracle on zero-cascade
/// programs fed whole: free-layer edits through group chains and
/// root deletes leave every announced length unchanged, so the
/// streaming machine and the two-pass machine must emit identical
/// bytes.
#[cfg(feature = "rewrite-grouped")]
#[test]
fn the_buffered_rewriter_agrees_on_zero_cascade_programs() {
    use crate::rewrite::{self, Rule, RuleSet};

    let (p12, p4, p5) = sweep_paths();
    let paths: [&[Segment<'_>]; 3] = [&p12, &p4, &p5];
    let program = Program::over(&paths).unwrap();
    let actions = Actions::over(&program, &SWEEP_TABLE).unwrap();
    let streamed = rewire(&actions, Standard::Tolerant, DOC).unwrap();

    let rules = [
        Rule { path: &p12, action: rewrite::Action::Replace(rewrite::Value::Varint(9)) },
        Rule { path: &p4, action: rewrite::Action::Delete },
        Rule { path: &p5, action: rewrite::Action::Replace(rewrite::Value::Len(b"YO")) },
    ];
    let set = RuleSet::over(&rules).unwrap();
    let (buffered, _) = rewrite::grouped::rewrite(DOC, &set, DepthLimit::REFERENCE).unwrap();
    assert_eq!(streamed, buffered);
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
    assert_eq!(core::mem::size_of::<Rewirer<'_>>(), 280);
    #[cfg(not(target_pointer_width = "64"))]
    assert!(core::mem::size_of::<Rewirer<'_>>() <= 280);
}
