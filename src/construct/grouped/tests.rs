//! Contract pins: hand-computed bytes for every scalar shape,
//! frame arithmetic, packed and raw faces, misuse panics and the
//! poison discipline.

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

// ─── the grouped compositions of the chunked and sink faces ───

#[test]
fn bytes_frame_and_the_sink_finish_compose_with_groups() {
    let build = || {
        let mut b = Builder::new();
        b.group(f(2), |g| {
            g.bytes_frame(f(1), |frame| {
                frame.write(&[0x08]);
                frame.write_borrowed(&[0x2A]);
            });
        });
        b
    };
    let expected = build().finish().unwrap();
    assert_eq!(expected, h("13 0A 02 08 2A 14"));
    assert_eq!(build().planned_len(), Ok(6));

    let mut streamed = Vec::new();
    build().finish_sink(|chunk| streamed.extend_from_slice(chunk)).unwrap();
    assert_eq!(streamed, expected);
}

// ─── scalar shapes, hand-computed ───

#[test]
fn every_scalar_shape_emits_its_pinned_bytes() {
    let mut b = Builder::new();
    b.push_varint(f(1), 150);
    b.push_int32(f(1), -1);
    b.push_sint32(f(1), -3);
    b.push_bool(f(1), true);
    b.push_i32(f(1), 1);
    b.push_float(f(1), 1.0);
    b.push_i64(f(1), 1);
    b.push_double(f(1), 1.0);
    b.push_string(f(1), "a");
    b.push_len(f(1), &[0xAB]);
    let out = b.finish().unwrap();
    let expected = h("08 9601
                      08 FFFFFFFFFFFFFFFFFF01
                      08 05
                      08 01
                      0D 01000000
                      0D 0000803F
                      09 0100000000000000
                      09 000000000000F03F
                      0A 01 61
                      0A 01 AB");
    assert_eq!(out, expected);
}

#[test]
fn varint_width_boundaries_are_minimal() {
    let mut b = Builder::new();
    b.push_varint(f(1), 127);
    b.push_varint(f(1), 128);
    b.push_varint(f(1), 16383);
    b.push_varint(f(1), 16384);
    b.push_varint(f(1), u64::MAX);
    let out = b.finish().unwrap();
    assert_eq!(out, h("08 7F 08 8001 08 FF7F 08 808001 08 FFFFFFFFFFFFFFFFFF01"));
}

// ─── frames ───

#[test]
fn nested_messages_close_bottom_up_with_minimal_prefixes() {
    let mut b = Builder::new();
    b.message(f(1), |m| {
        m.push_varint(f(2), 1);
        m.message(f(3), |inner| inner.push_varint(f(1), 7));
    });
    let out = b.finish().unwrap();
    assert_eq!(out, h("0A 06 10 01 1A 02 08 07"));
}

#[test]
fn an_empty_message_is_a_zero_length_frame() {
    let mut b = Builder::new();
    b.message(f(1), |_| {});
    let out = b.finish().unwrap();
    assert_eq!(out, h("0A 00"));
}

#[test]
fn a_two_byte_prefix_crosses_the_128_boundary() {
    let payload = [0xAA_u8; 126];
    let mut b = Builder::new();
    b.message(f(1), |m| m.push_len(f(2), &payload));
    let out = b.finish().unwrap();
    // Interior: tag(1) + prefix(1) + 126 = 128 → outer prefix 8001.
    assert_eq!(out.len(), 1 + 2 + 128);
    assert_eq!(&out[..3], &h("0A 80 01")[..]);
    assert_eq!(&out[3..5], &h("12 7E")[..]);
}

#[test]
fn groups_frame_without_length_work() {
    let mut b = Builder::new();
    b.group(f(3), |g| {
        g.push_varint(f(1), 1);
        g.group(f(2), |inner| inner.push_varint(f(1), 2));
    });
    let out = b.finish().unwrap();
    assert_eq!(out, h("1B 08 01 13 08 02 14 1C"));
}

// ─── packed and raw ───

#[test]
fn packed_families_budget_and_emit() {
    let mut b = Builder::new();
    b.push_packed_uint32(f(1), &[1, 150]);
    b.push_packed_sint32(f(1), &[-1, 1]);
    b.push_packed_fixed32(f(1), &[1, 2]);
    b.push_packed_bool(f(1), &[true, false]);
    let out = b.finish().unwrap();
    assert_eq!(
        out,
        h("0A 03 01 9601
           0A 02 01 02
           0A 08 01000000 02000000
           0A 02 01 00")
    );
}

#[test]
fn a_streamed_packed_body_via_raw_equals_the_slice_sugar() {
    let mut s = Builder::new();
    s.push_packed_uint32(f(1), &[1, 150]);
    let sugar = s.finish().unwrap();
    let mut b = Builder::new();
    b.message(f(1), |m| {
        m.raw_varint(1);
        m.raw_varint(150);
    });
    let streamed = b.finish().unwrap();
    assert_eq!(streamed, sugar);
}

// ─── the borrowed payload channel ───

/// Deterministic payloads crossing the one/two-byte prefix
/// boundary: empties, short runs, and runs just past 127 —
/// generated up front so a borrowed builder can hold every slice
/// until its finish.
fn payloads() -> Vec<Vec<u8>> {
    let mut state = 0x9E37_79B9_7F4A_7C15_u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    (0..48u64)
        .map(|i| {
            let len = match i % 4 {
                0 => 0,
                1 => next() % 24,
                2 => 120 + next() % 16,
                _ => next() % 300,
            };
            (0..len).map(|_| u8::try_from(next() & 0xFF).expect("masked to a byte")).collect()
        })
        .collect()
}

#[test]
fn the_copy_twins_emit_the_borrowed_bytes() {
    let payloads = payloads();
    let mut borrowed = Builder::new();
    let mut copied = Builder::new();
    for (i, p) in payloads.iter().enumerate() {
        let field = f(u32::try_from(i % 7).expect("small") + 1);
        match i % 4 {
            0 => {
                borrowed.push_len(field, p);
                copied.push_len_copy(field, p);
            }
            1 => {
                borrowed.message(field, |m| m.raw_bytes(p));
                copied.message(field, |m| m.raw_bytes_copy(p));
            }
            2 => {
                borrowed.group(field, |g| g.push_len(field, p));
                copied.group(field, |g| g.push_len_copy(field, p));
            }
            _ => {
                borrowed.push_string(field, "twin oracle");
                copied.push_string_copy(field, "twin oracle");
                borrowed.push_len(field, p);
                copied.push_len_copy(field, p);
            }
        }
    }
    assert_eq!(borrowed.finish().unwrap(), copied.finish().unwrap());
}

#[test]
fn a_borrowed_payload_stages_only_its_framing() {
    let payload = [0xA5u8; 4096];
    let mut b = Builder::new();
    b.push_len(f(1), &payload);
    // Staged bytes: one-byte head + two-byte prefix. The payload
    // never enters the store — its single copy happens at the
    // finish.
    assert_eq!(b.core.owned.len(), 3);
    assert_eq!(b.core.borrows.len(), 1);
    let out = b.finish().unwrap();
    assert_eq!(out.len(), 3 + 4096);
    assert_eq!(&out[3..], &payload[..]);
}

#[test]
fn a_borrowed_raw_append_stages_nothing() {
    let bytes = [0x5Au8; 300];
    let mut b = Builder::new();
    b.message(f(1), |m| m.raw_bytes(&bytes));
    // Staged bytes: the outer head only — the LEN prefix lives in
    // its patched event and the payload in the borrow table.
    assert_eq!(b.core.owned.len(), 1);
    assert_eq!(b.core.borrows.len(), 1);
    let out = b.finish().unwrap();
    assert_eq!(out.len(), 1 + 2 + 300);
    assert_eq!(&out[3..], &bytes[..]);
}

#[test]
fn an_empty_borrowed_payload_is_framing_only() {
    let mut b = Builder::new();
    b.push_len(f(1), &[]);
    b.message(f(2), |m| m.raw_bytes(&[]));
    assert_eq!(b.core.borrows.len(), 0, "empty payloads mint no borrow");
    assert_eq!(b.finish().unwrap(), h("0A 00 12 00"));
}

// ─── the cap machine ───

#[test]
fn the_poisoned_builder_keeps_balance_and_reports_at_finish() {
    let mut b = Builder::new();
    // Poison set by hand mid-frame (the cap needs 2 GiB to break
    // naturally); the balance axis must keep running so a
    // well-paired caller is not mis-panicked.
    b.message(f(1), |m| {
        m.core.force_poison_for_test();
        m.push_varint(f(2), 1);
    });
    assert!(b.poisoned().is_some());
    let err = b.finish().unwrap_err();
    assert!(err.len > 0);
}

// ─── outputs ───

#[test]
fn finish_into_appends_without_touching_the_prefix() {
    let mut out = h("DE AD");
    let mut b = Builder::new();
    b.push_varint(f(1), 1);
    b.finish_into(&mut out).unwrap();
    assert_eq!(out, h("DE AD 08 01"));
}

// ─── the copy-only sibling ───

/// Drives one copy-only arc against both machines, face for face:
/// the mixed builder through its `_copy` twins, the copy builder
/// through its unsuffixed doors — group framing included.
fn copy_arc(payloads: &[Vec<u8>]) -> (Builder<'_>, CopyBuilder) {
    let mut mixed = Builder::new();
    let mut copy = CopyBuilder::new();
    for (i, p) in payloads.iter().enumerate() {
        let field = f(u32::try_from(i % 7).expect("small") + 1);
        match i % 6 {
            0 => {
                mixed.push_len_copy(field, p);
                copy.push_len(field, p);
            }
            1 => {
                mixed.group(field, |g| {
                    g.push_string_copy(field, "copy oracle");
                    g.raw_bytes_copy(p);
                });
                copy.group(field, |g| {
                    g.push_string(field, "copy oracle");
                    g.raw_bytes(p);
                });
            }
            2 => {
                mixed.message(field, |m| {
                    m.raw_bytes_copy(p);
                    m.raw_varint(7);
                    m.group(field, |g| g.push_varint(field, 1));
                });
                copy.message(field, |m| {
                    m.raw_bytes(p);
                    m.raw_varint(7);
                    m.group(field, |g| g.push_varint(field, 1));
                });
            }
            3 => {
                mixed.bytes_frame(field, |frame| {
                    for chunk in p.chunks(5) {
                        frame.write(chunk);
                    }
                    frame.write(&[]);
                });
                copy.bytes_frame(field, |frame| {
                    for chunk in p.chunks(5) {
                        frame.write(chunk);
                    }
                    frame.write(&[]);
                });
            }
            4 => {
                mixed.push_varint(field, 150);
                mixed.push_packed_sint32(field, &[-1, 2, -3]);
                copy.push_varint(field, 150);
                copy.push_packed_sint32(field, &[-1, 2, -3]);
            }
            _ => {
                mixed.push_i32(field, 0xAB);
                mixed.push_i64(field, 0xCD);
                mixed.push_double(field, 1.5);
                copy.push_i32(field, 0xAB);
                copy.push_i64(field, 0xCD);
                copy.push_double(field, 1.5);
            }
        }
    }
    (mixed, copy)
}

#[test]
fn the_copy_builder_is_byte_identical_to_the_mixed_builder() {
    let payloads = payloads();

    let (mixed, copy) = copy_arc(&payloads);
    assert_eq!(mixed.planned_len().unwrap(), copy.planned_len().unwrap());
    let expected = mixed.finish().unwrap();
    assert_eq!(copy.finish().unwrap(), expected);

    let (mixed, copy) = copy_arc(&payloads);
    let mut mixed_out = h("DE AD");
    let mut copy_out = h("DE AD");
    mixed.finish_into(&mut mixed_out).unwrap();
    copy.finish_into(&mut copy_out).unwrap();
    assert_eq!(copy_out, mixed_out);

    let (mixed, copy) = copy_arc(&payloads);
    let mut mixed_sink = Vec::new();
    mixed.finish_sink(|chunk| mixed_sink.extend_from_slice(chunk)).unwrap();
    let mut copy_sink = Vec::new();
    let mut slices = 0usize;
    copy.finish_sink(|chunk| {
        assert!(!chunk.is_empty(), "sink slices are non-empty");
        slices += 1;
        copy_sink.extend_from_slice(chunk);
    })
    .unwrap();
    assert_eq!(copy_sink, mixed_sink);
    assert_eq!(copy_sink, expected);
    assert!(slices > 1, "owned runs and prefixes hand out separately");
}

#[test]
fn a_poisoned_copy_build_keeps_balance_and_refuses_every_output_face() {
    let mut b = CopyBuilder::new();
    // Poison set by hand mid-frame (the cap needs 2 GiB to break
    // naturally); the balance axis must keep running so a
    // well-paired caller is not mis-panicked.
    b.group(f(1), |g| {
        g.core.force_poison_for_test();
        g.push_varint(f(2), 1);
    });
    let over = b.poisoned().expect("poisoned");
    assert_eq!(b.planned_len(), Err(over));
    let mut calls = 0usize;
    let err = b.finish_sink(|_| calls += 1).unwrap_err();
    assert_eq!((err, calls), (over, 0), "Err hands the sink nothing");
}

// ─── round trip (when the read pair is also enabled) ───

#[cfg(feature = "traverse-grouped")]
#[test]
fn constructed_bytes_read_back_through_the_traversal_cursor() {
    use crate::traverse::grouped::{Cursor, EntryKind};

    let mut b = Builder::new();
    b.push_varint(f(1), 150);
    b.message(f(2), |m| m.push_string(f(1), "hi"));
    b.group(f(3), |g| g.push_varint(f(1), 1));
    let out = b.finish().unwrap();
    let entries: Vec<_> = Cursor::over(&out, crate::traverse::GroupDepth::REFERENCE)
        .unwrap()
        .map(|r| r.expect("constructed bytes are lawful"))
        .collect();
    assert_eq!(entries.len(), 5);
    assert!(matches!(entries[0].kind(), EntryKind::Varint(150)));
    assert!(matches!(entries[1].kind(), EntryKind::Len(&[0x0A, 0x02, 0x68, 0x69])));
    assert!(matches!(entries[2].kind(), EntryKind::GroupEnter));
}
