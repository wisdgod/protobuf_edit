//! Dependency-free micro-benchmarks: `cargo bench`.
//!
//! Each benchmark reports the median of timed batches after a warmup, as
//! ns/iter plus MiB/s over the input size. Inputs are deterministic, so
//! numbers are comparable across runs on the same machine.

use std::hint::black_box;
use std::time::Instant;

use protobuf_edit::encode::{self, Field, Value};
use protobuf_edit::wire::{FieldCursor, WireValue};
use protobuf_edit::{field_number, Buf, BorrowedDocument, BorrowedPatch, Document, FieldNumber};

const SAMPLES: usize = 25;
const MIN_SAMPLE_NANOS: u128 = 2_000_000;

/// Deterministic xorshift for payload sizes; no external RNG dependency.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

fn fnn(n: u32) -> FieldNumber {
    FieldNumber::new(n).expect("bench field numbers are static")
}

/// Builds a mixed-field message of at least `target_len` bytes.
fn build_message(target_len: usize) -> Vec<u8> {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let mut doc = Document::new();
    let mut nested_seed = Document::new();
    let _ = nested_seed.push_varint(fnn(1), 42).unwrap();
    let _ = nested_seed.push_length_delimited(fnn(2), Buf::from_static(b"nested")).unwrap();
    let nested = nested_seed.to_buf().unwrap();

    let mut approx = 0usize;
    let mut i = 0u64;
    while approx < target_len {
        let _ = doc.push_varint(fnn(1), rng.next()).unwrap();
        approx += 8;
        if i.is_multiple_of(3) {
            let _ = doc.push_fixed32(fnn(2), rng.next() as u32).unwrap();
            approx += 5;
        }
        if i.is_multiple_of(2) {
            let len = 16 + (rng.next() % 48) as usize;
            let payload = vec![0xA5u8; len];
            let _ = doc.push_length_delimited(fnn(3), Buf::from_vec(payload)).unwrap();
            approx += len + 2;
        }
        if i.is_multiple_of(8) {
            let _ = doc.push_length_delimited(fnn(4), nested.clone()).unwrap();
            approx += nested.len() as usize + 2;
        }
        i += 1;
    }
    doc.to_buf().unwrap().into_vec()
}

/// Runs `f` in timed batches and reports the median batch cost.
fn bench(name: &str, input_len: usize, mut f: impl FnMut()) {
    // Calibrate the batch size so one sample is long enough to time.
    let mut iters = 1u32;
    loop {
        let t = Instant::now();
        for _ in 0..iters {
            f();
        }
        if t.elapsed().as_nanos() >= MIN_SAMPLE_NANOS || iters >= 1 << 20 {
            break;
        }
        iters *= 2;
    }

    let mut samples = [0u128; SAMPLES];
    for slot in &mut samples {
        let t = Instant::now();
        for _ in 0..iters {
            f();
        }
        *slot = t.elapsed().as_nanos();
    }
    samples.sort_unstable();
    let median = samples[SAMPLES / 2];
    let ns_per_iter = median as f64 / f64::from(iters);
    let mib_per_s = if input_len == 0 {
        0.0
    } else {
        input_len as f64 / (ns_per_iter / 1e9) / (1024.0 * 1024.0)
    };
    println!("{name:<36} {ns_per_iter:>12.1} ns/iter {mib_per_s:>10.1} MiB/s");
}

fn cursor_walk(data: &[u8]) -> u64 {
    fn walk(data: &[u8], acc: &mut u64) {
        for field in FieldCursor::new(data) {
            let field = field.expect("bench input is well-formed");
            match field.value {
                WireValue::Varint(v) => *acc = acc.wrapping_add(v),
                WireValue::Len(payload) if field.tag.field_number().as_inner() == 4 => {
                    walk(payload, acc);
                }
                _ => {}
            }
        }
    }
    let mut acc = 0;
    walk(data, &mut acc);
    acc
}

fn main() {
    let small = build_message(10 * 1024);
    let large = build_message(100 * 1024);
    println!("input sizes: small={} bytes, large={} bytes", small.len(), large.len());

    for (label, data) in [("10k", &small), ("100k", &large)] {
        bench(&format!("cursor_walk_{label}"), data.len(), || {
            black_box(cursor_walk(black_box(data)));
        });
        bench(&format!("borrowed_patch_parse_{label}"), data.len(), || {
            black_box(BorrowedPatch::from_bytes(black_box(data)).unwrap());
        });
        bench(&format!("borrowed_document_parse_{label}"), data.len(), || {
            black_box(BorrowedDocument::from_bytes(black_box(data)).unwrap());
        });
    }

    // Sparse edit: flip one varint, then save (unchanged spans copy verbatim).
    {
        let mut patch = BorrowedPatch::from_bytes(&large).unwrap();
        let root = patch.root();
        let field = patch.fields_by_number(root, fnn(1)).unwrap().next().unwrap();
        patch.set_varint(field, 1).unwrap();
        bench("patch_save_one_edit_100k", large.len(), || {
            black_box(patch.save().unwrap());
        });
    }

    // Dense re-encode for comparison.
    {
        let doc = Document::from_bytes(&large).unwrap();
        bench("document_to_buf_100k", large.len(), || {
            black_box(doc.to_buf().unwrap());
        });
    }

    // Borrowed encoder: small nested message, one exact allocation.
    {
        let inner = [
            Field::new(field_number!(1), Value::Varint(150)),
            Field::new(field_number!(2), Value::Bytes(b"payload bytes")),
        ];
        let fields = [
            Field::new(field_number!(3), Value::Message(&inner)),
            Field::new(field_number!(4), Value::Fixed64(0x1122_3344_5566_7788)),
            Field::new(field_number!(5), Value::Varint(u64::MAX)),
        ];
        let encoded_len = encode::encode(&fields).unwrap().len() as usize;
        bench("encode_borrowed_small", encoded_len, || {
            black_box(encode::encode(black_box(&fields)).unwrap());
        });
    }
}
