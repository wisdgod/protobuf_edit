//! Contract pins for the groupless traversal: exhaustive on the
//! dialect-specific clauses (capability refusal, groupless
//! vocabulary), representative on shared semantics.

use alloc::vec::Vec;

use super::*;

#[track_caller]
fn h(s: &str) -> Vec<u8> {
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
fn f(n: u32) -> FieldNumber {
    FieldNumber::new(n).expect("test field in range")
}

#[track_caller]
fn walk(data: &[u8]) -> (Vec<Entry<'_>>, Option<Fault>) {
    let mut entries = Vec::new();
    let mut fault = None;
    for item in Cursor::over(data).expect("test input admitted") {
        match item {
            Ok(entry) => entries.push(entry),
            Err(e) => fault = Some(e),
        }
    }
    (entries, fault)
}

#[track_caller]
fn fault_of(data: &[u8]) -> Fault {
    walk(data).1.expect("expected a fault")
}

// ─── capability refusal (the dialect's own clause) ───

#[test]
fn group_codes_are_refused_as_capability_not_noise() {
    assert_eq!(
        fault_of(&h("0B")),
        Fault { at: 0, kind: FaultKind::GroupCode { field: f(1), code: Low3::new(3).unwrap() } }
    );
    assert_eq!(
        fault_of(&h("0C")),
        Fault { at: 0, kind: FaultKind::GroupCode { field: f(1), code: Low3::new(4).unwrap() } }
    );
    // Distinct from format-unassigned codes.
    assert_eq!(
        fault_of(&h("0E")),
        Fault { at: 0, kind: FaultKind::Unassigned { field: f(1), code: Low3::new(6).unwrap() } }
    );
}

#[test]
fn field_zero_is_judged_before_the_group_code() {
    // 0x04 = field 0 + code 4: FieldZero, not GroupCode.
    assert_eq!(fault_of(&h("04")), Fault { at: 0, kind: FaultKind::FieldZero { word: 4 } });
}

// ─── shared semantics, representative ───

#[test]
fn the_walk_delivers_each_record_once_with_decoded_words() {
    let data = h("08 9601
                  11 0807060504030201
                  1A 05 68656C6C6F
                  45 AABBCCDD
                  32 00");
    let (entries, fault) = walk(&data);
    assert_eq!(fault, None);
    assert_eq!(
        entries,
        [
            Entry { field: f(1), kind: EntryKind::Varint(150) },
            Entry { field: f(2), kind: EntryKind::I64(0x0102_0304_0506_0708) },
            Entry { field: f(3), kind: EntryKind::Len(b"hello") },
            Entry { field: f(8), kind: EntryKind::I32(0xDDCC_BBAA) },
            Entry { field: f(6), kind: EntryKind::Len(b"") },
        ]
    );
}

#[test]
fn len_payloads_are_opaque_and_descent_is_the_consumers_cursor() {
    let data = h("12 02 0801");
    let (entries, fault) = walk(&data);
    assert_eq!(fault, None);
    let EntryKind::Len(payload) = entries[0].kind else { panic!("expected Len") };
    let inner: Vec<_> = Cursor::within(payload).map(|r| r.unwrap()).collect();
    assert_eq!(inner, [Entry { field: f(1), kind: EntryKind::Varint(1) }]);
}

#[test]
fn faults_pin_stage_cause_and_payload_bounds() {
    assert_eq!(
        fault_of(&h("08")),
        Fault {
            at: 1,
            kind: FaultKind::Read {
                stage: Stage::Value { field: f(1) },
                cause: ReadFault::Truncated
            }
        }
    );
    assert_eq!(
        fault_of(&h("08 FFFFFFFFFFFFFFFFFF02")),
        Fault {
            at: 1,
            kind: FaultKind::Read {
                stage: Stage::Value { field: f(1) },
                cause: ReadFault::OutOfClass
            }
        }
    );
    assert_eq!(
        fault_of(&h("0D 0000")),
        Fault { at: 1, kind: FaultKind::FixedTruncated { field: f(1) } }
    );
    assert_eq!(
        fault_of(&h("0A 05 6161")),
        Fault {
            at: 2,
            kind: FaultKind::LenOverrun { field: f(1), len: PayloadLen::new(5).unwrap() }
        }
    );
}

#[test]
fn padded_widths_are_accepted_with_identical_words() {
    let padded = h("88 8000 81 8000");
    let minimal = h("08 01");
    let (a, fa) = walk(&padded);
    let (b, fb) = walk(&minimal);
    assert_eq!((fa, fb), (None, None));
    assert_eq!(a, b);
}

#[test]
fn the_first_fault_fuses_the_iterator() {
    let data = h("0B 0801");
    let mut cursor = Cursor::over(&data).unwrap();
    assert!(matches!(cursor.next(), Some(Err(_))));
    assert_eq!(cursor.next(), None);
    assert_eq!(cursor.next(), None);
}

#[test]
fn empty_input_is_a_lawful_empty_message() {
    let (entries, fault) = walk(&[]);
    assert_eq!((entries.len(), fault), (0, None));
}

// ─── the canonical twin (the traverse cell's own face) ───

#[cfg(feature = "traverse-groupless")]
#[test]
fn the_canonical_cursor_delivers_minimal_wire_identically() {
    // varint · I32 · LEN · I64: every kind, minimal widths — the
    // twins must agree on entries and geometry step for step.
    let data = h("08 96 01 15 01020304 12 02 6869 19 0102030405060708");
    let mut tolerant = Cursor::over(&data).unwrap();
    let mut canonical = CanonicalCursor::over(&data).unwrap();
    loop {
        let (a, b) = (tolerant.next(), canonical.next());
        assert_eq!(a, b, "the twins diverged");
        assert_eq!(tolerant.pos(), canonical.pos());
        assert_eq!(tolerant.tag_width(), canonical.tag_width());
        assert_eq!(tolerant.prefix_width(), canonical.prefix_width());
        if a.is_none() {
            break;
        }
    }
}

#[cfg(feature = "traverse-groupless")]
#[test]
fn the_canonical_cursor_refuses_each_padded_construct_at_its_head() {
    let f = |n: u32| FieldNumber::new(n).unwrap();
    // A padded tag, judged ahead of field zero and classification.
    let fault = CanonicalCursor::over(&h("88 80 80 00 01")).unwrap().next().unwrap().unwrap_err();
    assert_eq!((fault.at(), fault.kind()), (0, FaultKind::NonMinimalTag));
    // A padded value, at the value's first byte.
    let fault = CanonicalCursor::over(&h("08 96 81 00")).unwrap().next().unwrap().unwrap_err();
    assert_eq!((fault.at(), fault.kind()), (1, FaultKind::NonMinimalValue { field: f(1) }));
    // A padded length prefix, at the prefix's first byte.
    let fault =
        CanonicalCursor::over(&h("12 82 80 00 61 62")).unwrap().next().unwrap().unwrap_err();
    assert_eq!((fault.at(), fault.kind()), (1, FaultKind::NonMinimalLen { field: f(2) }));
    // The refusals are policy: the declared standard's section.
    assert_eq!(FaultKind::NonMinimalTag.class(), FaultClass::Policy);
}

#[cfg(feature = "traverse-groupless")]
#[test]
fn a_padded_group_code_is_width_before_capability() {
    // 0x0B group tag padded to two bytes: the minimality gate sits
    // before classification, so the canonical twin says width while
    // the tolerant one says capability — the scan validator's
    // judgment order.
    let padded_group = h("8B 00");
    let fault = CanonicalCursor::over(&padded_group).unwrap().next().unwrap().unwrap_err();
    assert_eq!((fault.at(), fault.kind()), (0, FaultKind::NonMinimalTag));
    let fault = Cursor::over(&padded_group).unwrap().next().unwrap().unwrap_err();
    assert!(matches!(fault.kind(), FaultKind::GroupCode { .. }));
}
