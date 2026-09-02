//! Contract pins for the groupless constructor: the vocabulary
//! absence is compile-level (no group methods exist to test);
//! shared semantics are pinned representatively.

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

#[test]
fn scalars_frames_and_packed_emit_pinned_bytes() {
    let mut b = Builder::new();
    b.push_sint64(f(1), -2);
    b.message(f(2), |m| {
        m.push_string(f(1), "x");
        m.message(f(2), |inner| inner.push_bool(f(1), true));
    });
    b.push_packed_double(f(3), &[1.0]);
    let out = b.finish().unwrap();
    assert_eq!(
        out,
        h("08 03
           12 07 0A 01 78 12 02 08 01
           1A 08 000000000000F03F")
    );
}

#[test]
fn every_message_node_pays_its_prefix() {
    // Three nested empties: each level pays tag + zero prefix.
    let mut b = Builder::new();
    b.message(f(1), |m| m.message(f(1), |inner| inner.message(f(1), |_| {})));
    let out = b.finish().unwrap();
    assert_eq!(out, h("0A 04 0A 02 0A 00"));
}

// ─── the borrowed payload channel ───

/// Deterministic payloads crossing the one/two-byte prefix
/// boundary: empties, short runs, and runs just past 127 —
/// generated up front so a borrowed builder can hold every slice
/// until its finish.
fn payloads() -> Vec<Vec<u8>> {
    let mut state = 0x6A09_E667_F3BC_C909_u64;
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
        match i % 3 {
            0 => {
                borrowed.push_len(field, p);
                copied.push_len_copy(field, p);
            }
            1 => {
                borrowed.message(field, |m| m.raw_bytes(p));
                copied.message(field, |m| m.raw_bytes_copy(p));
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
fn an_empty_borrowed_payload_is_framing_only() {
    let mut b = Builder::new();
    b.push_len(f(1), &[]);
    b.message(f(2), |m| m.raw_bytes(&[]));
    assert_eq!(b.core.borrows.len(), 0, "empty payloads mint no borrow");
    assert_eq!(b.finish().unwrap(), h("0A 00 12 00"));
}

#[test]
fn finish_into_appends_without_touching_the_prefix() {
    let mut out = h("BE EF");
    let mut b = Builder::new();
    b.push_varint(f(1), 7);
    b.finish_into(&mut out).unwrap();
    assert_eq!(out, h("BE EF 08 07"));
}

// ─── the chunked LEN frame ───

#[test]
fn bytes_frame_chunking_matches_the_whole_slice_push() {
    let payload: Vec<u8> = (0..=255u8).cycle().take(300).collect();
    let mut whole = Builder::new();
    whole.push_len(f(1), &payload);
    let expected = whole.finish().unwrap();

    for split in [1usize, 2, 7, 128, 299, 300] {
        let mut chunked = Builder::new();
        chunked.bytes_frame(f(1), |frame| {
            for (i, chunk) in payload.chunks(split).enumerate() {
                if i % 2 == 0 {
                    frame.write(chunk);
                } else {
                    frame.write_borrowed(chunk);
                }
            }
            // Empty chunks are no-ops in either spelling.
            frame.write(&[]);
            frame.write_borrowed(&[]);
        });
        assert_eq!(chunked.finish().unwrap(), expected, "split {split}");
    }
}

#[test]
fn an_untouched_bytes_frame_is_an_empty_len_record() {
    let mut b = Builder::new();
    b.bytes_frame(f(1), |_| {});
    assert_eq!(b.finish().unwrap(), h("0A 00"));
}

#[test]
fn borrowed_chunks_never_enter_the_staging_store() {
    let chunk = [0xA5u8; 1024];
    let mut b = Builder::new();
    b.bytes_frame(f(1), |frame| {
        frame.write_borrowed(&chunk);
        frame.write_borrowed(&chunk);
    });
    // The store holds the one-byte head only: the prefix is a
    // patched event, the chunks are borrows.
    assert_eq!(b.core.owned.len(), 1);
    assert_eq!(b.core.borrows.len(), 2);
    let out = b.finish().unwrap();
    assert_eq!(out.len(), 1 + 2 + 2048);
    assert_eq!(out[3..1027], chunk);
    assert_eq!(out[1027..], chunk);
}

#[test]
fn a_body_builder_bytes_frame_nests_inside_message() {
    let mut b = Builder::new();
    b.message(f(2), |m| {
        m.bytes_frame(f(1), |frame| frame.write(&[0x08, 0x01]));
    });
    assert_eq!(b.finish().unwrap(), h("12 04 0A 02 08 01"));
}

// ─── the account queries and the sink finish ───

#[test]
fn planned_len_prices_the_finish_exactly() {
    let mut b = Builder::new();
    assert_eq!(b.planned_len(), Ok(0));
    b.push_varint(f(1), 150);
    b.message(f(2), |m| m.push_string(f(1), "hi"));
    b.bytes_frame(f(3), |frame| {
        frame.write(&[1, 2, 3]);
        frame.write_borrowed(b"chunk");
    });
    let priced = b.planned_len().unwrap();
    let out = b.finish().unwrap();
    assert_eq!(priced, u64::try_from(out.len()).unwrap());
}

#[test]
fn a_poisoned_build_prices_nothing() {
    let mut b = Builder::new();
    b.push_varint(f(1), 1);
    b.core.force_poison_for_test();
    let over = b.poisoned().expect("poisoned");
    assert_eq!(b.planned_len(), Err(over));
}

#[test]
fn the_sink_finish_concatenation_is_the_vec_finish() {
    fn build<'p>(payloads: &'p [Vec<u8>]) -> Builder<'p> {
        let mut b = Builder::new();
        b.push_varint(f(1), 150);
        b.push_len(f(2), &payloads[1]);
        b.message(f(3), |m| {
            m.push_string(f(1), "sink");
            m.raw_bytes(&payloads[5]);
            m.message(f(2), |inner| inner.push_packed_uint32(f(1), &[1, 150, 3]));
        });
        b.push_len_copy(f(4), &payloads[9]);
        b.push_i64(f(5), 0x0102_0304_0506_0708);
        b
    }
    let payloads = payloads();
    let expected = build(&payloads).finish().unwrap();
    let mut streamed = Vec::new();
    let mut slices = 0usize;
    build(&payloads)
        .finish_sink(|chunk| {
            assert!(!chunk.is_empty(), "sink slices are non-empty");
            slices += 1;
            streamed.extend_from_slice(chunk);
        })
        .unwrap();
    assert_eq!(streamed, expected);
    assert!(slices > 3, "owned runs, borrows, and prefixes hand out separately");
}

#[test]
fn a_refused_sink_finish_hands_the_sink_nothing() {
    let mut b = Builder::new();
    b.push_varint(f(1), 1);
    b.core.force_poison_for_test();
    let over = b.poisoned().expect("poisoned");
    let mut calls = 0usize;
    let err = b.finish_sink(|_| calls += 1).unwrap_err();
    assert_eq!((err, calls), (over, 0), "Err hands the sink nothing");
}

// ─── the copy-only sibling ───

/// Drives one copy-only arc against both machines, face for face:
/// the mixed builder through its `_copy` twins, the copy builder
/// through its unsuffixed doors.
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
                mixed.push_string_copy(field, "copy oracle");
                copy.push_string(field, "copy oracle");
            }
            2 => {
                mixed.message(field, |m| {
                    m.raw_bytes_copy(p);
                    m.raw_varint(7);
                    m.push_len_copy(field, p);
                });
                copy.message(field, |m| {
                    m.raw_bytes(p);
                    m.raw_varint(7);
                    m.push_len(field, p);
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
    let mut mixed_out = h("BE EF");
    let mut copy_out = h("BE EF");
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
fn a_seeded_copy_builder_emits_the_same_bytes() {
    let mut seeded = CopyBuilder::with_capacity(64);
    let mut plain = CopyBuilder::new();
    for b in [&mut seeded, &mut plain] {
        b.push_string(f(1), "seeded");
        b.message(f(2), |m| m.push_varint(f(1), 1));
    }
    assert_eq!(seeded.finish().unwrap(), plain.finish().unwrap());
}

#[test]
fn a_poisoned_copy_build_refuses_every_output_face() {
    let mut b = CopyBuilder::new();
    b.push_varint(f(1), 1);
    b.core.force_poison_for_test();
    let over = b.poisoned().expect("poisoned");
    assert_eq!(b.planned_len(), Err(over));
    let mut calls = 0usize;
    let err = b.finish_sink(|_| calls += 1).unwrap_err();
    assert_eq!((err, calls), (over, 0), "Err hands the sink nothing");
}

#[cfg(feature = "traverse-groupless")]
#[test]
fn constructed_bytes_read_back_through_the_traversal_cursor() {
    use crate::traverse::groupless::{Cursor, EntryKind};

    let mut b = Builder::new();
    b.push_varint(f(1), 1);
    b.message(f(2), |m| m.push_len(f(1), &[0xFF]));
    let out = b.finish().unwrap();
    let entries: Vec<_> =
        Cursor::over(&out).unwrap().map(|r| r.expect("constructed bytes are lawful")).collect();
    assert_eq!(entries.len(), 2);
    assert!(matches!(entries[1].kind(), EntryKind::Len(&[0x0A, 0x01, 0xFF])));
}
