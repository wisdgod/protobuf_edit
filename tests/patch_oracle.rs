//! The cross-machine equivalence oracle for the one-shot patch.
//!
//! On canonical input the patch and the session speak one editing
//! semantics: the same command script, driven in lockstep against
//! both machines, must save the same bytes — a divergence means one
//! side has a bug. The script generator is deterministic (seeded
//! xorshift), biased toward the interesting faces: scalar re-sets,
//! payload replacement, descent plus interior edits, deletion, and
//! insertion at every anchor.
//!
//! Two guards ride along: canonical wire is a subset of tolerant
//! wire, so a payload the session opens must open under the patch
//! too; and every patch save must walk green under the traverse
//! cursor of the same dialect.

// The full consumer closure this suite drives; under any narrower
// feature set the target compiles empty, so per-cell `--all-targets`
// builds stay green.
#![cfg(all(
    feature = "draft-grouped",
    feature = "draft-groupless",
    feature = "markup-grouped",
    feature = "markup-groupless",
    feature = "patch-grouped",
    feature = "patch-groupless",
    feature = "review-grouped",
    feature = "review-groupless",
    feature = "session-grouped",
    feature = "session-groupless",
    feature = "traverse-grouped",
    feature = "traverse-groupless"
))]

extern crate alloc;

use alloc::vec::Vec;

/// Deterministic xorshift64* — no external randomness in the suite.
struct Rng(u64);

impl Rng {
    const fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    const fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// Minimal (canonical) varint emission.
fn emit_varint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = (value & 0x7F) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

fn emit_tag(out: &mut Vec<u8>, field: u32, code: u32) {
    emit_varint(out, u64::from((field << 3) | code));
}

/// A small-biased random word (all widths reachable, short common).
const fn small_word(rng: &mut Rng) -> u64 {
    let word = rng.next();
    word >> (rng.below(64) as u32)
}

/// Pads the just-emitted varint in place: each step sets the
/// continuation bit on the current last byte and appends a zero
/// limb — the reference readers' tolerant domain. `cap` bounds the
/// total width (five for tags and prefixes, ten for values).
fn pad_last_varint(rng: &mut Rng, out: &mut Vec<u8>, start: usize, cap: usize) {
    let width = out.len() - start;
    let room = cap.saturating_sub(width);
    if room == 0 {
        return;
    }
    for _ in 0..rng.below(room + 1) {
        let last = out.len() - 1;
        out[last] |= 0x80;
        out.push(0x00);
    }
}

/// [`emit_tag`], padded at random.
fn emit_tag_padded(rng: &mut Rng, out: &mut Vec<u8>, field: u32, code: u32) {
    let start = out.len();
    emit_tag(out, field, code);
    pad_last_varint(rng, out, start, 5);
}

/// One tolerant layer, recursively: [`gen_layer`]'s shapes with
/// padded tags, padded varint values, and padded LEN prefixes
/// scattered through — the draft's admission domain.
fn gen_layer_padded(rng: &mut Rng, out: &mut Vec<u8>, depth: u32, groups: bool) {
    let n = 1 + rng.below(5);
    for _ in 0..n {
        let field = 1 + rng.below(14) as u32;
        let arms = if groups { 6 } else { 5 };
        match rng.below(arms) {
            0 => {
                emit_tag_padded(rng, out, field, 0);
                let start = out.len();
                emit_varint(out, small_word(rng));
                pad_last_varint(rng, out, start, 10);
            }
            1 => {
                emit_tag_padded(rng, out, field, 5);
                out.extend_from_slice(&(rng.next() as u32).to_le_bytes());
            }
            2 => {
                emit_tag_padded(rng, out, field, 1);
                out.extend_from_slice(&rng.next().to_le_bytes());
            }
            3 => {
                // A raw LEN payload behind a possibly padded
                // prefix: opaque bytes.
                emit_tag_padded(rng, out, field, 2);
                let len = rng.below(6);
                let start = out.len();
                emit_varint(out, len as u64);
                pad_last_varint(rng, out, start, 5);
                for _ in 0..len {
                    out.push(rng.next() as u8);
                }
            }
            4 if depth > 0 => {
                // A message LEN payload: tolerant interior.
                emit_tag_padded(rng, out, field, 2);
                let mut inner = Vec::new();
                gen_layer_padded(rng, &mut inner, depth - 1, groups);
                let start = out.len();
                emit_varint(out, inner.len() as u64);
                pad_last_varint(rng, out, start, 5);
                out.extend_from_slice(&inner);
            }
            4 => {
                emit_tag_padded(rng, out, field, 2);
                let start = out.len();
                emit_varint(out, 0);
                pad_last_varint(rng, out, start, 5);
            }
            _ if depth > 0 => {
                emit_tag_padded(rng, out, field, 3);
                gen_layer_padded(rng, out, depth - 1, groups);
                emit_tag_padded(rng, out, field, 4);
            }
            _ => {
                emit_tag_padded(rng, out, field, 3);
                emit_tag_padded(rng, out, field, 4);
            }
        }
    }
}

/// One canonical layer, recursively: scalars, raw LENs, message
/// LENs, and (grouped only) groups.
fn gen_layer(rng: &mut Rng, out: &mut Vec<u8>, depth: u32, groups: bool) {
    let n = 1 + rng.below(5);
    for _ in 0..n {
        let field = 1 + rng.below(14) as u32;
        let arms = if groups { 6 } else { 5 };
        match rng.below(arms) {
            0 => {
                emit_tag(out, field, 0);
                emit_varint(out, small_word(rng));
            }
            1 => {
                emit_tag(out, field, 5);
                out.extend_from_slice(&(rng.next() as u32).to_le_bytes());
            }
            2 => {
                emit_tag(out, field, 1);
                out.extend_from_slice(&rng.next().to_le_bytes());
            }
            3 => {
                // A raw LEN payload: opaque bytes.
                emit_tag(out, field, 2);
                let len = rng.below(6);
                emit_varint(out, len as u64);
                for _ in 0..len {
                    out.push(rng.next() as u8);
                }
            }
            4 if depth > 0 => {
                // A message LEN payload: canonical interior.
                emit_tag(out, field, 2);
                let mut inner = Vec::new();
                gen_layer(rng, &mut inner, depth - 1, groups);
                emit_varint(out, inner.len() as u64);
                out.extend_from_slice(&inner);
            }
            4 => {
                emit_tag(out, field, 2);
                emit_varint(out, 0);
            }
            _ if depth > 0 => {
                emit_tag(out, field, 3);
                gen_layer(rng, out, depth - 1, groups);
                emit_tag(out, field, 4);
            }
            _ => {
                emit_tag(out, field, 3);
                emit_tag(out, field, 4);
            }
        }
    }
}

macro_rules! dialect_oracle {
    ($mod_name:ident, $groups:expr, open: $open:ident, $patch:path, $session:path,
     $p_at:path, $s_at:path, $kind:path, $p_descent:path, $s_descent:path,
     $walk:expr) => {
        mod $mod_name {
            use protobuf_edit::{DepthLimit, FieldNumber};

            use super::*;

            use $kind as RecordKind;
            use $p_at as PAt;
            use $p_descent as PDescent;
            use $patch as Patch;
            use $s_at as SAt;
            use $s_descent as SDescent;
            use $session as Session;

            const fn f(n: u32) -> FieldNumber {
                FieldNumber::new(n).expect("script fields are in range")
            }

            /// Saves both machines and compares the bytes; then
            /// walks the patch's product with the traverse cursor.
            /// The sizing query faces ride along: each must name
            /// the exact length its save then produces.
            #[track_caller]
            fn cross_check(p: &Patch<'_, '_>, s: &Session, seed: u64, step: usize) {
                let pv = p.save().expect("patch save succeeds");
                let sv = s.save().expect("session save succeeds");
                assert_eq!(pv, sv.as_slice(), "save divergence at seed {seed} step {step}");
                let plen = p.save_len().expect("patch save_len succeeds");
                assert_eq!(
                    plen as usize,
                    pv.len(),
                    "patch save_len drift at seed {seed} step {step}"
                );
                let slen = s.save_len().expect("session save_len succeeds");
                // The price faces differ in width across tenures
                // (owned answers `usize`, borrowed `u32`): widen.
                assert_eq!(
                    slen as u64,
                    sv.len() as u64,
                    "session save_len drift at seed {seed} step {step}"
                );
                let walk: fn(&[u8]) -> bool = $walk;
                assert!(walk(&pv), "traverse faulted on patch save at seed {seed} step {step}");
            }

            /// Drives one deterministic script against both machines.
            #[allow(clippy::too_many_lines, reason = "one lockstep driver, one flow")]
            fn drive(seed: u64) {
                let mut rng = Rng(seed | 1);
                let mut doc = Vec::new();
                gen_layer(&mut rng, &mut doc, 2, $groups);

                let mut p = Patch::open(&doc, DepthLimit::REFERENCE).expect("canonical doc opens");
                let mut s = Session::$open(&doc).expect("canonical doc opens");
                // Patch handles whose descent was ever attempted:
                // their payload status may lawfully differ between
                // the acceptance domains, so wholesale replacement
                // is off-script for them.
                let mut probed: Vec<protobuf_edit::patch::Handle> = Vec::new();

                for step in 0..40 {
                    let pt: Vec<_> = p.top().collect();
                    let st: Vec<_> = s.top().collect();
                    assert_eq!(pt.len(), st.len(), "top-layer drift at seed {seed} step {step}");
                    let op = rng.below(10);
                    if pt.is_empty() || op >= 7 {
                        let field = f(1 + rng.below(14) as u32);
                        let (p_anchor, s_anchor) = if pt.is_empty() {
                            (PAt::TailOf(None), SAt::TailOf(None))
                        } else {
                            match rng.below(3) {
                                0 => (PAt::HeadOf(None), SAt::HeadOf(None)),
                                1 => (PAt::TailOf(None), SAt::TailOf(None)),
                                _ => {
                                    // Deleted anchors are a lawful
                                    // contract divergence (the patch
                                    // names the surviving gap, the
                                    // session refuses the dead row),
                                    // so the lockstep script avoids
                                    // them.
                                    let i = rng.below(pt.len());
                                    if p.status(pt[i]) == protobuf_edit::patch::EditStatus::Deleted
                                    {
                                        (PAt::TailOf(None), SAt::TailOf(None))
                                    } else {
                                        (PAt::After(pt[i]), SAt::After(st[i]))
                                    }
                                }
                            }
                        };
                        match rng.below(3) {
                            0 => {
                                let v = small_word(&mut rng);
                                let pr = p.insert_varint(p_anchor, field, v);
                                let sr = s.insert_varint(s_anchor, field, v);
                                assert_eq!(pr.is_err(), sr.is_err());
                            }
                            1 => {
                                let bits = rng.next();
                                let pr = p.insert_i64(p_anchor, field, bits);
                                let sr = s.insert_i64(s_anchor, field, bits);
                                assert_eq!(pr.is_err(), sr.is_err());
                            }
                            _ => {
                                let len = rng.below(5);
                                let payload: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
                                let pr = p.insert_payload_copy(p_anchor, field, &payload);
                                let sr = s.insert_payload(s_anchor, field, &payload);
                                assert_eq!(pr.is_err(), sr.is_err());
                            }
                        }
                    } else if op == 6 {
                        let i = rng.below(pt.len());
                        let pr = p.delete(pt[i]);
                        let sr = s.delete(st[i]);
                        assert_eq!(pr.is_err(), sr.is_err(), "delete drift at seed {seed}");
                    } else {
                        let i = rng.below(pt.len());
                        match p.kind(pt[i]) {
                            RecordKind::Varint => {
                                let v = small_word(&mut rng);
                                let pr = p.set_varint(pt[i], v);
                                let sr = s.set_varint(st[i], v);
                                assert_eq!(pr.is_err(), sr.is_err());
                            }
                            RecordKind::I32 => {
                                let bits = rng.next() as u32;
                                let pr = p.set_i32(pt[i], bits);
                                let sr = s.set_i32(st[i], bits);
                                assert_eq!(pr.is_err(), sr.is_err());
                            }
                            RecordKind::I64 => {
                                let bits = rng.next();
                                let pr = p.set_i64(pt[i], bits);
                                let sr = s.set_i64(st[i], bits);
                                assert_eq!(pr.is_err(), sr.is_err());
                            }
                            RecordKind::Len if rng.below(2) == 0 && !probed.contains(&pt[i]) => {
                                let len = rng.below(5);
                                let payload: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
                                let pr = p.set_payload_copy(pt[i], &payload);
                                let sr = s.set_payload(st[i], &payload);
                                assert_eq!(pr.is_err(), sr.is_err());
                            }
                            _ if p.status(pt[i]) == protobuf_edit::patch::EditStatus::Deleted
                                || (matches!(p.kind(pt[i]), RecordKind::Len)
                                    && p.status(pt[i])
                                        != protobuf_edit::patch::EditStatus::Intact) =>
                            {
                                // Deleted and authored-payload
                                // targets diverge lawfully: the
                                // revisable session descends both
                                // (undelete exists, and it parses
                                // pending payloads); the commit-only
                                // patch refuses.
                            }
                            _ => {
                                // Descend (a container, or a LEN
                                // held back from replacement).
                                probed.push(pt[i]);
                                let p_opened =
                                    matches!(p.descend(pt[i]), Ok(PDescent::Opened { .. }));
                                let s_opened =
                                    matches!(s.descend(st[i]), Ok(SDescent::Opened { .. }));
                                // Canonical is a subset of tolerant.
                                assert!(
                                    p_opened || !s_opened,
                                    "session opened what patch refused at seed {seed}"
                                );
                                if p_opened && s_opened {
                                    let pk: Vec<_> = p.children(pt[i]).collect();
                                    let sk: Vec<_> =
                                        s.children(st[i]).expect("opened container").collect();
                                    assert_eq!(pk.len(), sk.len(), "interior drift {seed}");
                                    if !pk.is_empty() {
                                        let j = rng.below(pk.len());
                                        match p.kind(pk[j]) {
                                            RecordKind::Varint => {
                                                let v = small_word(&mut rng);
                                                let pr = p.set_varint(pk[j], v);
                                                let sr = s.set_varint(sk[j], v);
                                                assert_eq!(pr.is_err(), sr.is_err());
                                            }
                                            RecordKind::I64 => {
                                                let bits = rng.next();
                                                let pr = p.set_i64(pk[j], bits);
                                                let sr = s.set_i64(sk[j], bits);
                                                assert_eq!(pr.is_err(), sr.is_err());
                                            }
                                            _ => {
                                                let pr = p.delete(pk[j]);
                                                let sr = s.delete(sk[j]);
                                                assert_eq!(pr.is_err(), sr.is_err());
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    if step % 10 == 9 {
                        cross_check(&p, &s, seed, step);
                    }
                }
                cross_check(&p, &s, seed, 40);
            }

            #[test]
            fn scripted_edits_save_identical_bytes() {
                let seeds: u64 = if cfg!(miri) { 4 } else { 64 };
                for seed in 0..seeds {
                    drive(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0xD1F4);
                }
            }

            /// Large borrowed payloads across insert, wholesale
            /// set, and re-set: the borrowed patch faces must save
            /// byte-identically to the session's staged copies.
            #[test]
            fn large_borrowed_payloads_save_identical_bytes() {
                let len: usize = if cfg!(miri) { 512 } else { 1 << 20 };
                let mut rng = Rng(0xB0B0_1E5C_0FFE_E001);
                let payloads: Vec<Vec<u8>> =
                    (0..3).map(|_| (0..len).map(|_| rng.next() as u8).collect()).collect();
                let mut doc = Vec::new();
                gen_layer(&mut rng, &mut doc, 2, $groups);
                let mut p = Patch::open(&doc, DepthLimit::REFERENCE).expect("canonical doc opens");
                let mut s = Session::$open(&doc).expect("canonical doc opens");
                let pt: Vec<_> = p.top().collect();
                let st: Vec<_> = s.top().collect();
                let ph = p.insert_payload(PAt::HeadOf(None), f(9), &payloads[0]).unwrap();
                let sh = s.insert_payload(SAt::HeadOf(None), f(9), &payloads[0]).unwrap();
                p.insert_payload(PAt::TailOf(None), f(10), &payloads[1]).unwrap();
                s.insert_payload(SAt::TailOf(None), f(10), &payloads[1]).unwrap();
                // Replace the first scanned LEN wholesale, if any.
                for (i, &handle) in pt.iter().enumerate() {
                    if matches!(p.kind(handle), RecordKind::Len) {
                        p.set_payload(handle, &payloads[2]).unwrap();
                        s.set_payload(st[i], &payloads[2]).unwrap();
                        break;
                    }
                }
                // Re-set the authored record: the borrowed slot
                // overwrites in place.
                p.set_payload(ph, &payloads[1]).unwrap();
                s.set_payload(sh, &payloads[1]).unwrap();
                cross_check(&p, &s, 0, 0);
            }
        }
    };
}

#[cfg(all(feature = "patch-grouped", feature = "session-grouped", feature = "traverse-grouped"))]
dialect_oracle!(
    grouped_oracle,
    true,
    open: open_copy,
    protobuf_edit::patch::grouped::Patch,
    protobuf_edit::session::grouped::Session,
    protobuf_edit::patch::grouped::InsertAt,
    protobuf_edit::session::grouped::InsertAt,
    protobuf_edit::wire::grouped::RecordKind,
    protobuf_edit::patch::grouped::Descent,
    protobuf_edit::session::grouped::Descent,
    |bytes| {
        use protobuf_edit::traverse::GroupDepth;
        use protobuf_edit::traverse::grouped::Cursor;
        Cursor::over(bytes, GroupDepth::REFERENCE)
            .expect("saved documents stay in the size class")
            .all(|entry| entry.is_ok())
    }
);

#[cfg(all(
    feature = "patch-groupless",
    feature = "session-groupless",
    feature = "traverse-groupless"
))]
dialect_oracle!(
    groupless_oracle,
    false,
    open: open_copy,
    protobuf_edit::patch::groupless::Patch,
    protobuf_edit::session::groupless::Session,
    protobuf_edit::patch::groupless::InsertAt,
    protobuf_edit::session::groupless::InsertAt,
    protobuf_edit::wire::groupless::RecordKind,
    protobuf_edit::patch::groupless::Descent,
    protobuf_edit::session::groupless::Descent,
    |bytes| {
        use protobuf_edit::traverse::groupless::Cursor;
        Cursor::over(bytes)
            .expect("saved documents stay in the size class")
            .all(|entry| entry.is_ok())
    }
);

// The review is the session's borrowed-tenure twin: same canonical
// door, same revision log, the source held by reference. The same
// lockstep judge pins it against the patch over the canonical
// domain — only the open door differs.

#[cfg(all(feature = "patch-grouped", feature = "review-grouped", feature = "traverse-grouped"))]
dialect_oracle!(
    grouped_review_oracle,
    true,
    open: open,
    protobuf_edit::patch::grouped::Patch,
    protobuf_edit::review::grouped::Review,
    protobuf_edit::patch::grouped::InsertAt,
    protobuf_edit::review::grouped::InsertAt,
    protobuf_edit::wire::grouped::RecordKind,
    protobuf_edit::patch::grouped::Descent,
    protobuf_edit::review::grouped::Descent,
    |bytes| {
        use protobuf_edit::traverse::GroupDepth;
        use protobuf_edit::traverse::grouped::Cursor;
        Cursor::over(bytes, GroupDepth::REFERENCE)
            .expect("saved documents stay in the size class")
            .all(|entry| entry.is_ok())
    }
);

#[cfg(all(
    feature = "patch-groupless",
    feature = "review-groupless",
    feature = "traverse-groupless"
))]
dialect_oracle!(
    groupless_review_oracle,
    false,
    open: open,
    protobuf_edit::patch::groupless::Patch,
    protobuf_edit::review::groupless::Review,
    protobuf_edit::patch::groupless::InsertAt,
    protobuf_edit::review::groupless::InsertAt,
    protobuf_edit::wire::groupless::RecordKind,
    protobuf_edit::patch::groupless::Descent,
    protobuf_edit::review::groupless::Descent,
    |bytes| {
        use protobuf_edit::traverse::groupless::Cursor;
        Cursor::over(bytes)
            .expect("saved documents stay in the size class")
            .all(|entry| entry.is_ok())
    }
);

// ─── the draft oracle: patch equivalence over the tolerant domain ───

/// The revisable-vs-patch lockstep judge: both machines are
/// tolerant, so on padded documents the same revert-free command
/// script must save byte-identical documents, price them
/// identically, report identical span tables, and answer the
/// reverse index alike — and after any such prefix, `revert_all`
/// must restore the padded source byte-exactly (the revert
/// oracle). Agreement with the session's semantics rides
/// transitively: `dialect_oracle!` pins patch ≡ session on their
/// shared canonical domain, and this judge pins each tolerant
/// revisable machine (draft owning, markup borrowing) ≡ patch on
/// the whole tolerant domain. The tenure token picks the open
/// door.
macro_rules! open_revisable {
    (vec, $machine:ident, $doc:ident) => {
        $machine::open($doc.clone()).expect("padded doc opens")
    };
    (borrow, $machine:ident, $doc:ident) => {
        $machine::open(&$doc).expect("padded doc opens")
    };
}

macro_rules! draft_oracle {
    ($mod_name:ident, $groups:expr, tenure: $tenure:ident, $patch:path, $draft:path,
     $p_at:path, $d_at:path, $kind:path, $p_descent:path, $d_descent:path,
     $walk:expr) => {
        mod $mod_name {
            use protobuf_edit::{DepthLimit, FieldNumber};

            use super::*;

            use $d_at as DAt;
            use $d_descent as DDescent;
            use $draft as Draft;
            use $kind as RecordKind;
            use $p_at as PAt;
            use $p_descent as PDescent;
            use $patch as Patch;

            const fn f(n: u32) -> FieldNumber {
                FieldNumber::new(n).expect("script fields are in range")
            }

            /// Saves both machines and compares bytes, prices, span
            /// tables, and the reverse index; then walks the save
            /// with the traverse cursor (tolerant re-ingestion).
            #[track_caller]
            fn cross_check(p: &Patch<'_, '_>, d: &Draft, doc_len: u32, seed: u64, step: usize) {
                let pv = p.save().expect("patch save succeeds");
                let dv = d.save().expect("draft save succeeds");
                assert_eq!(pv, dv, "save divergence at seed {seed} step {step}");
                assert_eq!(
                    p.save_len().expect("patch save_len succeeds"),
                    d.save_len().expect("draft save_len succeeds"),
                    "price divergence at seed {seed} step {step}"
                );
                let pt: Vec<(u32, u32)> = p
                    .save_spans()
                    .expect("patch save_spans succeeds")
                    .iter()
                    .map(|(_, s)| (s.start(), s.end()))
                    .collect();
                let dt: Vec<(u32, u32)> = d
                    .save_spans()
                    .expect("draft save_spans succeeds")
                    .iter()
                    .map(|(_, s)| (s.start(), s.end()))
                    .collect();
                assert_eq!(pt, dt, "span-table divergence at seed {seed} step {step}");
                // The reverse index answers by the same source
                // footprint at every byte (handles are per-machine;
                // whole-record spans are not).
                for pos in 0..=doc_len {
                    let pa = p.narrowest(pos).and_then(|h| p.span(h));
                    let da =
                        d.narrowest(pos).map(|h| d.span(h).expect("narrowest answers live rows"));
                    assert_eq!(
                        pa,
                        da.flatten(),
                        "narrowest divergence at byte {pos}, seed {seed} step {step}"
                    );
                }
                let walk: fn(&[u8]) -> bool = $walk;
                assert!(walk(&pv), "traverse faulted on the save at seed {seed} step {step}");
            }

            /// Drives one deterministic revert-free script against
            /// both machines, then the revert oracle on the draft.
            #[allow(clippy::too_many_lines, reason = "one lockstep driver, one flow")]
            fn drive(seed: u64) {
                let mut rng = Rng(seed | 1);
                let mut doc = Vec::new();
                gen_layer_padded(&mut rng, &mut doc, 2, $groups);
                let doc_len = u32::try_from(doc.len()).expect("scripts stay small");

                let mut p = Patch::open(&doc, DepthLimit::REFERENCE).expect("padded doc opens");
                let mut d = open_revisable!($tenure, Draft, doc);
                // Handles whose descent was ever attempted: their
                // payload status is a resident verdict, so wholesale
                // replacement is off-script for them (the draft
                // additionally guards interiors carrying history).
                let mut probed: Vec<protobuf_edit::patch::Handle> = Vec::new();

                for step in 0..40 {
                    let pt: Vec<_> = p.top().collect();
                    let dt: Vec<_> = d.top().collect();
                    assert_eq!(pt.len(), dt.len(), "top-layer drift at seed {seed} step {step}");
                    let op = rng.below(10);
                    if pt.is_empty() || op >= 7 {
                        let field = f(1 + rng.below(14) as u32);
                        let (p_anchor, d_anchor) = if pt.is_empty() {
                            (PAt::TailOf(None), DAt::TailOf(None))
                        } else {
                            match rng.below(3) {
                                0 => (PAt::HeadOf(None), DAt::HeadOf(None)),
                                1 => (PAt::TailOf(None), DAt::TailOf(None)),
                                _ => {
                                    // Deleted anchors diverge
                                    // lawfully across the revision
                                    // poles; the lockstep script
                                    // avoids them.
                                    let i = rng.below(pt.len());
                                    if p.status(pt[i]) == protobuf_edit::patch::EditStatus::Deleted
                                    {
                                        (PAt::TailOf(None), DAt::TailOf(None))
                                    } else {
                                        (PAt::After(pt[i]), DAt::After(dt[i]))
                                    }
                                }
                            }
                        };
                        match rng.below(3) {
                            0 => {
                                let v = small_word(&mut rng);
                                let pr = p.insert_varint(p_anchor, field, v);
                                let dr = d.insert_varint(d_anchor, field, v);
                                assert_eq!(pr.is_err(), dr.is_err());
                            }
                            1 => {
                                let bits = rng.next();
                                let pr = p.insert_i64(p_anchor, field, bits);
                                let dr = d.insert_i64(d_anchor, field, bits);
                                assert_eq!(pr.is_err(), dr.is_err());
                            }
                            _ => {
                                let len = rng.below(5);
                                let payload: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
                                let pr = p.insert_payload_copy(p_anchor, field, &payload);
                                let dr = d.insert_payload(d_anchor, field, &payload);
                                assert_eq!(pr.is_err(), dr.is_err());
                            }
                        }
                    } else if op == 6 {
                        let i = rng.below(pt.len());
                        let pr = p.delete(pt[i]);
                        let dr = d.delete(dt[i]);
                        assert_eq!(pr.is_err(), dr.is_err(), "delete drift at seed {seed}");
                    } else {
                        let i = rng.below(pt.len());
                        match p.kind(pt[i]) {
                            RecordKind::Varint => {
                                let v = small_word(&mut rng);
                                let pr = p.set_varint(pt[i], v);
                                let dr = d.set_varint(dt[i], v);
                                assert_eq!(pr.is_err(), dr.is_err());
                            }
                            RecordKind::I32 => {
                                let bits = rng.next() as u32;
                                let pr = p.set_i32(pt[i], bits);
                                let dr = d.set_i32(dt[i], bits);
                                assert_eq!(pr.is_err(), dr.is_err());
                            }
                            RecordKind::I64 => {
                                let bits = rng.next();
                                let pr = p.set_i64(pt[i], bits);
                                let dr = d.set_i64(dt[i], bits);
                                assert_eq!(pr.is_err(), dr.is_err());
                            }
                            RecordKind::Len if rng.below(2) == 0 && !probed.contains(&pt[i]) => {
                                let len = rng.below(5);
                                let payload: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
                                let pr = p.set_payload_copy(pt[i], &payload);
                                let dr = d.set_payload(dt[i], &payload);
                                assert_eq!(pr.is_err(), dr.is_err());
                            }
                            _ if p.status(pt[i]) == protobuf_edit::patch::EditStatus::Deleted
                                || (matches!(p.kind(pt[i]), RecordKind::Len)
                                    && p.status(pt[i])
                                        != protobuf_edit::patch::EditStatus::Intact) =>
                            {
                                // Deleted targets and authored
                                // payloads stay off-script: the
                                // commit-only patch and the
                                // revisable draft answer their
                                // descents under different
                                // contracts.
                            }
                            _ => {
                                // Descend: both machines are
                                // tolerant, so the verdicts agree
                                // exactly.
                                probed.push(pt[i]);
                                let p_opened =
                                    matches!(p.descend(pt[i]), Ok(PDescent::Opened { .. }));
                                let d_opened =
                                    matches!(d.descend(dt[i]), Ok(DDescent::Opened { .. }));
                                assert_eq!(
                                    p_opened, d_opened,
                                    "descent verdict drift at seed {seed}"
                                );
                                if p_opened {
                                    let pk: Vec<_> = p.children(pt[i]).collect();
                                    let dk: Vec<_> =
                                        d.children(dt[i]).expect("opened container").collect();
                                    assert_eq!(pk.len(), dk.len(), "interior drift {seed}");
                                    if !pk.is_empty() {
                                        let j = rng.below(pk.len());
                                        match p.kind(pk[j]) {
                                            RecordKind::Varint => {
                                                let v = small_word(&mut rng);
                                                let pr = p.set_varint(pk[j], v);
                                                let dr = d.set_varint(dk[j], v);
                                                assert_eq!(pr.is_err(), dr.is_err());
                                            }
                                            RecordKind::I64 => {
                                                let bits = rng.next();
                                                let pr = p.set_i64(pk[j], bits);
                                                let dr = d.set_i64(dk[j], bits);
                                                assert_eq!(pr.is_err(), dr.is_err());
                                            }
                                            _ => {
                                                let pr = p.delete(pk[j]);
                                                let dr = d.delete(dk[j]);
                                                assert_eq!(pr.is_err(), dr.is_err());
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    if step % 10 == 9 {
                        cross_check(&p, &d, doc_len, seed, step);
                    }
                }
                cross_check(&p, &d, doc_len, seed, 40);

                // The revert oracle: this script is one arbitrary
                // command prefix, and the full unwind must restore
                // the padded source byte-exactly.
                d.revert_all();
                assert_eq!(d.pending(), 0);
                assert_eq!(
                    d.save().expect("clean save succeeds"),
                    doc,
                    "revert oracle failed at seed {seed}"
                );
                assert_eq!(d.save_len().expect("clean price succeeds"), doc_len);
            }

            #[test]
            fn scripted_edits_match_the_patch_and_revert_to_the_padded_source() {
                let seeds: u64 = if cfg!(miri) { 4 } else { 64 };
                for seed in 0..seeds {
                    drive(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0x0D1F);
                }
            }
        }
    };
}

#[cfg(all(feature = "patch-grouped", feature = "draft-grouped", feature = "traverse-grouped"))]
draft_oracle!(
    grouped_draft_oracle,
    true,
    tenure: vec,
    protobuf_edit::patch::grouped::Patch,
    protobuf_edit::draft::grouped::Draft,
    protobuf_edit::patch::grouped::InsertAt,
    protobuf_edit::draft::grouped::InsertAt,
    protobuf_edit::wire::grouped::RecordKind,
    protobuf_edit::patch::grouped::Descent,
    protobuf_edit::draft::grouped::Descent,
    |bytes| {
        use protobuf_edit::traverse::GroupDepth;
        use protobuf_edit::traverse::grouped::Cursor;
        Cursor::over(bytes, GroupDepth::REFERENCE)
            .expect("saved documents stay in the size class")
            .all(|entry| entry.is_ok())
    }
);

#[cfg(all(
    feature = "patch-groupless",
    feature = "draft-groupless",
    feature = "traverse-groupless"
))]
draft_oracle!(
    groupless_draft_oracle,
    false,
    tenure: vec,
    protobuf_edit::patch::groupless::Patch,
    protobuf_edit::draft::groupless::Draft,
    protobuf_edit::patch::groupless::InsertAt,
    protobuf_edit::draft::groupless::InsertAt,
    protobuf_edit::wire::groupless::RecordKind,
    protobuf_edit::patch::groupless::Descent,
    protobuf_edit::draft::groupless::Descent,
    |bytes| {
        use protobuf_edit::traverse::groupless::Cursor;
        Cursor::over(bytes)
            .expect("saved documents stay in the size class")
            .all(|entry| entry.is_ok())
    }
);

#[cfg(all(feature = "patch-grouped", feature = "markup-grouped", feature = "traverse-grouped"))]
draft_oracle!(
    grouped_markup_oracle,
    true,
    tenure: borrow,
    protobuf_edit::patch::grouped::Patch,
    protobuf_edit::markup::grouped::Markup,
    protobuf_edit::patch::grouped::InsertAt,
    protobuf_edit::markup::grouped::InsertAt,
    protobuf_edit::wire::grouped::RecordKind,
    protobuf_edit::patch::grouped::Descent,
    protobuf_edit::markup::grouped::Descent,
    |bytes| {
        use protobuf_edit::traverse::GroupDepth;
        use protobuf_edit::traverse::grouped::Cursor;
        Cursor::over(bytes, GroupDepth::REFERENCE)
            .expect("saved documents stay in the size class")
            .all(|entry| entry.is_ok())
    }
);

#[cfg(all(
    feature = "patch-groupless",
    feature = "markup-groupless",
    feature = "traverse-groupless"
))]
draft_oracle!(
    groupless_markup_oracle,
    false,
    tenure: borrow,
    protobuf_edit::patch::groupless::Patch,
    protobuf_edit::markup::groupless::Markup,
    protobuf_edit::patch::groupless::InsertAt,
    protobuf_edit::markup::groupless::InsertAt,
    protobuf_edit::wire::groupless::RecordKind,
    protobuf_edit::patch::groupless::Descent,
    protobuf_edit::markup::groupless::Descent,
    |bytes| {
        use protobuf_edit::traverse::groupless::Cursor;
        Cursor::over(bytes)
            .expect("saved documents stay in the size class")
            .all(|entry| entry.is_ok())
    }
);
