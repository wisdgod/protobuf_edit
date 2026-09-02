//! Contract pins: each test states one clause of the machine's
//! contract (judgment order, faithfulness, group pairing, the
//! depth bound, fusing, LEN opacity, pos differencing).

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

// The reference bound (100), minted through the raw face:
// `GroupDepth::REFERENCE` is the traverse cell's own door, and
// these pins run under every cell that compiles the engine.
// SAFETY: 100 lies inside the declared 1..=10_000 range.
const D: GroupDepth = unsafe { GroupDepth::new_unchecked(100) };

#[track_caller]
fn walk(data: &[u8]) -> (Vec<Entry<'_>>, Option<Fault>) {
    let mut cursor = Cursor::over(data, D).expect("test input admitted");
    let mut entries = Vec::new();
    let mut fault = None;
    for item in &mut cursor {
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

// ─── the composite walk ───

#[test]
fn the_walk_delivers_each_record_once_with_decoded_words() {
    // f1 varint 150 · f2 i64 · f3 len "hello" · group f7 { f5
    // varint 1 } · f8 i32 · f6 len=0.
    let data = h("08 9601
                  11 0807060504030201
                  1A 05 68656C6C6F
                  3B 2801 3C
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
            Entry { field: f(7), kind: EntryKind::GroupEnter },
            Entry { field: f(5), kind: EntryKind::Varint(1) },
            Entry { field: f(7), kind: EntryKind::GroupExit },
            Entry { field: f(8), kind: EntryKind::I32(0xDDCC_BBAA) },
            Entry { field: f(6), kind: EntryKind::Len(b"") },
        ]
    );
}

#[test]
fn len_payloads_are_opaque_even_when_they_look_like_records() {
    // Payload bytes `08 01` parse as a varint record, but the
    // cursor never descends: one Len entry, nothing else.
    let data = h("12 02 0801");
    let (entries, fault) = walk(&data);
    assert_eq!(fault, None);
    assert_eq!(entries, [Entry { field: f(2), kind: EntryKind::Len(&[0x08, 0x01]) }]);
}

// Descent is the consumer's own cursor over the slice, through the
// `within` door — compiled with that door's descending consumers.
#[cfg(any(
    feature = "select-grouped",
    feature = "rewrite-grouped",
    feature = "inplace-grouped",
    feature = "splice-grouped",
    feature = "traverse-grouped"
))]
#[test]
fn descent_is_the_consumers_cursor_within_the_payload() {
    let data = h("12 02 0801");
    let (entries, fault) = walk(&data);
    assert_eq!(fault, None);
    let EntryKind::Len(payload) = entries[0].kind else { unreachable!() };
    let inner: Vec<_> = Cursor::within(payload, D).map(|r| r.unwrap()).collect();
    assert_eq!(inner, [Entry { field: f(1), kind: EntryKind::Varint(1) }]);
}

// ─── faithfulness: lawful widths in, forged values out ───

#[test]
fn padded_widths_are_accepted_with_identical_words() {
    // Tag for field 1 varint padded to two bytes, value 1 padded
    // to three; then the minimal spelling of the same record.
    let padded = h("88 8000 81 8000");
    let minimal = h("08 01");
    let (a, fa) = walk(&padded);
    let (b, fb) = walk(&minimal);
    assert_eq!((fa, fb), (None, None));
    assert_eq!(a, b, "padding must not change the delivered word");
}

#[test]
fn class_forgery_is_refused_at_every_stage() {
    // Tag whose fifth byte exceeds 0x0F.
    assert_eq!(
        fault_of(&h("FF FF FF FF 1F")),
        Fault { at: 0, kind: FaultKind::Read { stage: Stage::Tag, cause: ReadFault::OutOfClass } }
    );
    // Length prefix whose fifth byte exceeds 0x07.
    assert_eq!(
        fault_of(&h("0A FFFFFFFF08")),
        Fault {
            at: 1,
            kind: FaultKind::Read {
                stage: Stage::LenPrefix { field: f(1) },
                cause: ReadFault::OutOfClass
            }
        }
    );
    // Value whose tenth byte exceeds 0x01.
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
}

#[test]
fn window_overruns_and_truncations_name_the_construct() {
    assert_eq!(
        fault_of(&h("80 80 80 80 80")),
        Fault { at: 0, kind: FaultKind::Read { stage: Stage::Tag, cause: ReadFault::TooWide } }
    );
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
        fault_of(&h("0A 80")),
        Fault {
            at: 1,
            kind: FaultKind::Read {
                stage: Stage::LenPrefix { field: f(1) },
                cause: ReadFault::Truncated
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

// ─── judgment order ───

#[test]
fn field_zero_is_judged_before_the_code_class() {
    // 0x04 = field 0 + code 4 (group end): FieldZero, not an
    // orphan end tag. 0x00 and 0x06 likewise.
    for (hex, word) in [("04", 4_u32), ("00", 0), ("06", 6)] {
        assert_eq!(
            fault_of(&h(hex)),
            Fault { at: 0, kind: FaultKind::FieldZero { word } },
            "word {word:#x}"
        );
    }
}

#[test]
fn unassigned_codes_quote_field_and_code() {
    assert_eq!(
        fault_of(&h("0E")),
        Fault { at: 0, kind: FaultKind::Unassigned { field: f(1), code: Low3::new(6).unwrap() } }
    );
}

// ─── group pairing ───

#[test]
fn group_pairing_faults_quote_both_sides_and_the_open_site() {
    assert_eq!(
        fault_of(&h("0C")),
        Fault { at: 0, kind: FaultKind::GroupEndOrphan { found: f(1) } }
    );
    // Group f1 opens at 0; end tag names f2.
    assert_eq!(
        fault_of(&h("0B 14")),
        Fault {
            at: 1,
            kind: FaultKind::GroupEndMismatch { open: f(1), opened_at: 0, found: f(2) }
        }
    );
    // Input ends with f1 (opened at 2) still open.
    assert_eq!(
        fault_of(&h("0801 0B")),
        Fault { at: 3, kind: FaultKind::GroupUnclosed { open: f(1), opened_at: 2 } }
    );
}

#[test]
fn nested_groups_match_per_level() {
    let data = h("0B 13 14 0C");
    let (entries, fault) = walk(&data);
    assert_eq!(fault, None);
    assert_eq!(
        entries,
        [
            Entry { field: f(1), kind: EntryKind::GroupEnter },
            Entry { field: f(2), kind: EntryKind::GroupEnter },
            Entry { field: f(2), kind: EntryKind::GroupExit },
            Entry { field: f(1), kind: EntryKind::GroupExit },
        ]
    );
}

// ─── the depth bound ───

#[test]
fn the_reference_depth_walks_a_hundred_and_refuses_the_next() {
    let mut deep = alloc::vec![0x0B_u8; 100];
    deep.extend_from_slice(&alloc::vec![0x0C_u8; 100]);
    let (entries, fault) = walk(&deep);
    assert_eq!(fault, None);
    assert_eq!(entries.len(), 200);

    let over = alloc::vec![0x0B_u8; 101];
    let fault = fault_of(&over);
    assert_eq!(fault, Fault { at: 100, kind: FaultKind::DepthExceeded { field: f(1), limit: D } });
}

// ─── iteration contract ───

#[test]
fn the_first_fault_fuses_the_iterator() {
    let data = h("00 0801");
    let mut cursor = Cursor::over(&data, D).unwrap();
    assert!(matches!(cursor.next(), Some(Err(_))));
    assert_eq!(cursor.next(), None);
    assert_eq!(cursor.next(), None);
}

#[test]
fn a_clean_end_is_none_and_stays_none() {
    let data = h("08 01");
    let mut cursor = Cursor::over(&data, D).unwrap();
    assert!(matches!(cursor.next(), Some(Ok(_))));
    assert_eq!(cursor.next(), None);
    assert_eq!(cursor.next(), None);
}

#[test]
fn empty_input_is_a_lawful_empty_message() {
    let (entries, fault) = walk(&[]);
    assert_eq!((entries.len(), fault), (0, None));
}

// ─── pos ───

#[test]
fn pos_differences_measure_whole_records() {
    let data = h("08 9601 1A 05 68656C6C6F");
    let mut cursor = Cursor::over(&data, D).unwrap();
    assert_eq!(cursor.pos(), 0);
    let mut sizes = Vec::new();
    let mut last = 0;
    while let Some(item) = cursor.next() {
        item.unwrap();
        let end = cursor.pos();
        sizes.push(end - last);
        last = end;
    }
    assert_eq!(sizes, [3, 7], "tag+value, tag+prefix+payload");
}

#[test]
fn pos_freezes_at_the_faulted_records_head() {
    let data = h("08 01 00");
    let mut cursor = Cursor::over(&data, D).unwrap();
    assert!(matches!(cursor.next(), Some(Ok(_))));
    assert!(matches!(cursor.next(), Some(Err(_))));
    assert_eq!(cursor.pos(), 2, "frozen at the bad head, not past it");
}

// ─── admission ───

#[test]
fn admission_is_the_constructors_judgment() {
    assert!(Cursor::over(&[], D).is_ok());
    // The refusing branch needs a >2 GiB allocation; the bound
    // itself is pinned by the constructor's comparison constant
    // (admission::MAX == PayloadLen::MAX).
}

// ─── the canonical twin (the traverse cell's own face) ───

#[cfg(feature = "traverse-grouped")]
#[test]
fn the_canonical_cursor_walks_minimal_groups_identically() {
    // group f1 { varint f2 · LEN f2 } · I32 f2: framing tags,
    // scalars, and a payload — the twins must agree on entries and
    // geometry step for step.
    let data = h("0B 10 96 01 12 02 6869 0C 15 01020304");
    let mut tolerant = Cursor::over(&data, D).unwrap();
    let mut canonical = CanonicalCursor::over(&data, D).unwrap();
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

#[cfg(feature = "traverse-grouped")]
#[test]
fn the_canonical_cursor_refuses_padded_widths_at_their_heads() {
    // A padded value inside a group: the group walk reaches it.
    let padded_value = h("0B 10 96 81 00 0C");
    let fault = {
        let mut cursor = CanonicalCursor::over(&padded_value, D).unwrap();
        assert!(cursor.next().unwrap().is_ok()); // GroupEnter
        cursor.next().unwrap().unwrap_err()
    };
    assert_eq!((fault.at(), fault.kind()), (2, FaultKind::NonMinimalValue { field: f(2) }));
    // A padded length prefix.
    let fault =
        CanonicalCursor::over(&h("12 82 80 00 61 62"), D).unwrap().next().unwrap().unwrap_err();
    assert_eq!((fault.at(), fault.kind()), (1, FaultKind::NonMinimalLen { field: f(2) }));
    // A padded start tag: width ahead of pairing bookkeeping.
    let fault = CanonicalCursor::over(&h("8B 00"), D).unwrap().next().unwrap().unwrap_err();
    assert_eq!((fault.at(), fault.kind()), (0, FaultKind::NonMinimalTag));
    // The refusals are policy: the declared standard's section.
    assert_eq!(FaultKind::NonMinimalTag.class(), FaultClass::Policy);
}

#[cfg(feature = "traverse-grouped")]
#[test]
fn a_padded_end_tag_is_width_before_pairing() {
    // group f1 open, then its end tag padded to two bytes: the
    // canonical twin refuses the width where the tolerant one
    // verifies the pairing and closes.
    let data = h("0B 8C 80 00");
    let mut canonical = CanonicalCursor::over(&data, D).unwrap();
    assert!(canonical.next().unwrap().is_ok()); // GroupEnter
    let fault = canonical.next().unwrap().unwrap_err();
    assert_eq!((fault.at(), fault.kind()), (1, FaultKind::NonMinimalTag));

    let mut tolerant = Cursor::over(&data, D).unwrap();
    assert!(tolerant.next().unwrap().is_ok());
    assert!(matches!(tolerant.next().unwrap().unwrap().kind(), EntryKind::GroupExit));
}
