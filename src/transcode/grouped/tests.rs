//! Contract pins: each test states one clause of the machine's
//! contract (identity fidelity, the free/locked algebras, the
//! redirect protocols, suppression, and chunking invariance).

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

const D: DepthLimit = DepthLimit::REFERENCE;

/// Runs one job over `data` in `step`-sized chunks.
#[track_caller]
fn run<R: Rule>(
    data: &[u8],
    step: usize,
    standard: Standard,
    rule: &mut R,
) -> Result<Vec<u8>, Fault> {
    let mut out = Vec::new();
    let mut sink = |bytes: &[u8]| out.extend_from_slice(bytes);
    let mut t = Transcoder::new(standard, D);
    for chunk in data.chunks(step.max(1)) {
        t.feed(chunk, rule, &mut sink)?;
    }
    t.finish(rule, &mut sink)?;
    Ok(out)
}

/// Asserts the outcome is chunking-invariant and returns it.
#[track_caller]
fn invariant<R: Rule, F: FnMut() -> R>(
    data: &[u8],
    standard: Standard,
    mut fresh: F,
) -> Result<Vec<u8>, Fault> {
    let mut base: Option<Result<Vec<u8>, Fault>> = None;
    for step in [1, 2, 3, 5, 7, data.len().max(1)] {
        let out = run(data, step, standard, &mut fresh());
        match &base {
            None => base = Some(out),
            Some(b) => assert_eq!(*b, out, "chunk step {step} moved the outcome"),
        }
    }
    base.expect("at least one step ran")
}

// ─── identity ───

#[test]
fn the_default_rule_is_a_bit_true_transcoder() {
    // Padded tag, padded prefix, padded value, a group with an
    // i32, nested passed LENs: all verbatim under Tolerant.
    let data = h("88 00 01 0A 82 80 00 61 62 08 81 00 3B 0D 01020304 3C 12 04 0A 02 08 01");
    let out = invariant(&data, Standard::Tolerant, || ()).unwrap();
    assert_eq!(out, data);
}

// ─── the coordinate-space capability gate ───

#[test]
fn the_feed_gate_refuses_a_chunk_past_the_coordinate_space() {
    // The cursor is injected two bytes short of the space's top
    // (`u64::MAX − 1` admissible bytes): a one-byte chunk still
    // admits and consumes...
    let mut t = Transcoder::new(Standard::Tolerant, D);
    t.pump.off = u64::MAX - 2;
    t.feed(&h("08"), &mut (), &mut |_: &[u8]| {}).unwrap();
    assert_eq!(t.offset(), u64::MAX - 1);

    // ...and one byte more would need the unaddressable sentinel
    // coordinate: refused whole at admission, nothing consumed,
    // terminal.
    let fault = t.feed(&h("00"), &mut (), &mut |_: &[u8]| {}).unwrap_err();
    assert!(matches!(
        fault,
        Fault::Wire { at, breach: WireBreach::OffsetExhausted } if at == u64::MAX - 1
    ));
    let Fault::Wire { breach, .. } = fault else { unreachable!() };
    assert_eq!(breach.class(), crate::FaultClass::Capability);
}

#[test]
fn a_len_declared_out_to_the_coordinate_ceiling_is_refused() {
    // The space holds `u64::MAX − 1` bytes, so a payload whose end
    // lands on the sentinel coordinate can never be satisfied — and
    // a zone parked on the sentinel would also unlatch `locked()`.
    // Refused where the declaration is read: head and prefix consume
    // two bytes (cursor → MAX−2), declared end (MAX−2)+2 = MAX.
    let mut t = Transcoder::new(Standard::Tolerant, D);
    t.pump.off = u64::MAX - 4;
    let fault = t.feed(&h("0A 02"), &mut (), &mut |_: &[u8]| {}).unwrap_err();
    assert!(matches!(
        fault,
        Fault::Wire { at, breach: WireBreach::OffsetExhausted } if at == u64::MAX - 2
    ));
    let Fault::Wire { breach, .. } = fault else { unreachable!() };
    assert_eq!(breach.class(), crate::FaultClass::Capability);

    // One byte lower, the same declaration ends at MAX−1 and is
    // admitted (the machine then waits on the payload).
    let mut t = Transcoder::new(Standard::Tolerant, D);
    t.pump.off = u64::MAX - 5;
    t.feed(&h("0A 02"), &mut (), &mut |_: &[u8]| {}).unwrap();
}

// ─── free scalar verbs ───

struct DropField(u32);
impl Rule for DropField {
    fn on_varint(&mut self, _at: u64, field: FieldNumber, _v: u64, _w: u8) -> FreeScalar<'_, u64> {
        if field.as_inner() == self.0 { FreeScalar::Drop } else { FreeScalar::Keep }
    }
}

#[test]
fn free_drop_erases_records() {
    let data = h("08 01 10 02 08 03");
    let out = invariant(&data, Standard::CanonicalMinimal, || DropField(1)).unwrap();
    assert_eq!(out, h("10 02"));
}

struct RewriteVarint(u32, u64);
impl Rule for RewriteVarint {
    fn on_varint(&mut self, _at: u64, field: FieldNumber, _v: u64, _w: u8) -> FreeScalar<'_, u64> {
        if field.as_inner() == self.0 { FreeScalar::Rewrite(self.1) } else { FreeScalar::Keep }
    }
}

#[test]
fn free_rewrite_reencodes_minimally_and_keeps_the_tag_verbatim() {
    // Padded tag stays; padded value is replaced by the minimal
    // spelling of the new value.
    let data = h("88 00 8102");
    let out = invariant(&data, Standard::Tolerant, || RewriteVarint(1, 7)).unwrap();
    assert_eq!(out, h("88 00 07"));
}

/// Inserts a pre-encoded record before field 1, then drops it: the
/// in-place any-length replacement composition.
struct InsertThenDrop {
    asked: bool,
}
impl Rule for InsertThenDrop {
    fn on_varint(&mut self, _at: u64, field: FieldNumber, _v: u64, _w: u8) -> FreeScalar<'_, u64> {
        if field.as_inner() == 1 && !self.asked {
            self.asked = true;
            return FreeScalar::Insert(&[0x10, 0x07]);
        }
        if field.as_inner() == 1 {
            self.asked = false;
            return FreeScalar::Drop;
        }
        FreeScalar::Keep
    }
}

#[test]
fn insert_then_drop_composes_in_place_replacement() {
    let data = h("08 01 18 02");
    let out =
        invariant(&data, Standard::CanonicalMinimal, || InsertThenDrop { asked: false }).unwrap();
    assert_eq!(out, h("10 07 18 02"));
}

// ─── the locked algebra ───

/// Enters LEN field 1 and rewrites varint field 2 inside.
struct LockedRewrite(u64);
impl Rule for LockedRewrite {
    fn on_len(&mut self, _at: u64, field: FieldNumber, _len: PayloadLen) -> FreeLen<'_> {
        if field.as_inner() == 1 { FreeLen::Commit } else { FreeLen::Pass }
    }
    fn on_varint_locked(
        &mut self,
        _at: u64,
        _f: FieldNumber,
        _v: u64,
        _w: u8,
    ) -> LockedScalar<u64> {
        LockedScalar::Rewrite(self.0)
    }
}

#[test]
fn locked_rewrites_pad_to_the_source_width_under_tolerant() {
    // f2 = 128 (two bytes); rewrite to 1: padded to two bytes, the
    // enclosing length untouched.
    let data = h("0A 03 10 8001");
    let out = invariant(&data, Standard::Tolerant, || LockedRewrite(1)).unwrap();
    assert_eq!(out, h("0A 03 10 8100"));
}

#[test]
fn locked_rewrites_wider_than_the_source_are_breaches() {
    let data = h("0A 02 10 01");
    let fault = invariant(&data, Standard::Tolerant, || LockedRewrite(128)).unwrap_err();
    assert!(matches!(
        fault,
        Fault::Rule(RuleFault {
            at: 2,
            kind: RuleFaultKind::RewriteOverflow { width: 1, need: 2, .. }
        })
    ));
}

#[test]
fn canonical_minimal_locks_rewrites_to_the_exact_width() {
    // Under CanonicalMinimal a narrower value cannot pad (the
    // output must re-ingest under the declared standard).
    let data = h("0A 03 10 8001");
    let fault = invariant(&data, Standard::CanonicalMinimal, || LockedRewrite(1)).unwrap_err();
    assert!(matches!(
        fault,
        Fault::Rule(RuleFault { kind: RuleFaultKind::RewriteWidthMismatch { .. }, .. })
    ));
    // An equal-width rewrite passes.
    let out = run(&data, 64, Standard::CanonicalMinimal, &mut LockedRewrite(200)).unwrap();
    assert_eq!(out, h("0A 03 10 C801"));
}

#[test]
fn enter_notifies_exit_and_locks_the_interior() {
    struct Witness {
        exits: Vec<(u32, u64)>,
    }
    impl Rule for Witness {
        fn on_len(&mut self, _at: u64, _f: FieldNumber, _l: PayloadLen) -> FreeLen<'_> {
            FreeLen::Commit
        }
        fn on_len_exit(&mut self, field: FieldNumber, at: u64) {
            self.exits.push((field.as_inner(), at));
        }
    }
    let data = h("0A 02 08 01");
    let mut rule = Witness { exits: Vec::new() };
    let out = run(&data, 64, Standard::CanonicalMinimal, &mut rule).unwrap();
    assert_eq!(out, data);
    assert_eq!(rule.exits, [(1, 4)]);
}

#[test]
fn a_word_suspended_across_the_seal_is_the_seal_cut() {
    struct EnterAll;
    impl Rule for EnterAll {
        fn on_len(&mut self, _at: u64, _f: FieldNumber, _l: PayloadLen) -> FreeLen<'_> {
            FreeLen::Commit
        }
        fn on_len_locked(&mut self, _at: u64, _f: FieldNumber, _l: PayloadLen) -> LockedLen<'_> {
            LockedLen::Commit
        }
    }
    // The tag closes at the seal, the value word lies outside:
    // the seal truncates the record. Nothing splices from the
    // parent zone.
    let fault = invariant(&h("12 01 08 2A"), Standard::Tolerant, || EnterAll).unwrap_err();
    assert!(matches!(fault, Fault::Wire { at: 3, breach: WireBreach::Varint }));
    // The same suspension at a nested LEN record's length word.
    let fault = invariant(&h("12 01 1A 01"), Standard::Tolerant, || EnterAll).unwrap_err();
    assert!(matches!(fault, Fault::Wire { at: 3, breach: WireBreach::Varint }));
    // Stream end at the seal changes nothing: the record cannot
    // complete inside the seal, and the head decides the moment
    // the tag closes.
    let fault = invariant(&h("12 01 08"), Standard::Tolerant, || EnterAll).unwrap_err();
    assert!(matches!(fault, Fault::Wire { at: 3, breach: WireBreach::Varint }));
}

// ─── LEN verbs ───

struct ReplaceLen<'r>(u32, &'r [u8]);
impl Rule for ReplaceLen<'_> {
    fn on_len(&mut self, _at: u64, field: FieldNumber, _len: PayloadLen) -> FreeLen<'_> {
        if field.as_inner() == self.0 { FreeLen::Replace(self.1) } else { FreeLen::Pass }
    }
}

#[test]
fn replace_is_equal_length_and_keeps_the_frame_verbatim() {
    // Padded prefix (3 in two bytes) survives the replacement.
    let data = h("1A 83 00 616263");
    let out = invariant(&data, Standard::Tolerant, || ReplaceLen(3, b"XYZ")).unwrap();
    assert_eq!(out, h("1A 83 00 58595A"));

    let fault = invariant(&data, Standard::Tolerant, || ReplaceLen(3, b"XY")).unwrap_err();
    assert!(matches!(
        fault,
        Fault::Rule(RuleFault { kind: RuleFaultKind::ReplaceLenMismatch { got: 2, .. }, .. })
    ));
}

#[test]
fn pass_forwards_large_payloads_across_chunks() {
    let mut data = h("1A 20");
    data.extend_from_slice(&[0xAB; 32]);
    let out = invariant(&data, Standard::CanonicalMinimal, || ()).unwrap();
    assert_eq!(out, data);
}

/// XORs every payload byte of field `0` with `1` — an equal-length
/// streaming transform (lawful at any depth).
struct XorTransform {
    field: u32,
    mask: u8,
    buf: Vec<u8>,
}
impl Rule for XorTransform {
    fn on_len(&mut self, _at: u64, field: FieldNumber, _len: PayloadLen) -> FreeLen<'_> {
        if field.as_inner() == self.field { FreeLen::Transform } else { FreeLen::Pass }
    }
    fn on_fragment<'s>(&'s mut self, fragment: &[u8]) -> &'s [u8] {
        self.buf.clear();
        self.buf.extend(fragment.iter().map(|b| b ^ self.mask));
        &self.buf
    }
}

#[test]
fn transform_streams_equal_length_content_edits() {
    let data = h("1A 03 616263");
    let out = invariant(&data, Standard::CanonicalMinimal, || XorTransform {
        field: 3,
        mask: 0x20,
        buf: Vec::new(),
    })
    .unwrap();
    assert_eq!(out, h("1A 03 414243"));
}

/// A transform that swallows fragments and never repays: the
/// shortfall breach.
struct SilentTransform;
impl Rule for SilentTransform {
    fn on_len(&mut self, _at: u64, _f: FieldNumber, _l: PayloadLen) -> FreeLen<'_> {
        FreeLen::Transform
    }
}

#[test]
fn transform_accounts_are_enforced() {
    let data = h("1A 03 616263");
    let fault = invariant(&data, Standard::CanonicalMinimal, || SilentTransform).unwrap_err();
    assert!(matches!(
        fault,
        Fault::Rule(RuleFault { at: 0, kind: RuleFaultKind::TransformShortfall { .. } })
    ));

    // Overpaying faults at the earliest determined point.
    struct Overpayer;
    impl Rule for Overpayer {
        fn on_len(&mut self, _at: u64, _f: FieldNumber, _l: PayloadLen) -> FreeLen<'_> {
            FreeLen::Transform
        }
        fn on_fragment<'s>(&'s mut self, _fragment: &[u8]) -> &'s [u8] {
            &[0xFF; 8]
        }
    }
    let fault = run(&data, 64, Standard::CanonicalMinimal, &mut Overpayer).unwrap_err();
    assert!(matches!(
        fault,
        Fault::Rule(RuleFault { kind: RuleFaultKind::TransformOverflow { .. }, .. })
    ));
}

/// Diverts field 3, buffers the payload, and reinjects it reversed
/// as a fresh pre-encoded record.
struct Reverser {
    gathered: Vec<u8>,
    staged: Vec<u8>,
    flushed: bool,
}
impl Rule for Reverser {
    fn on_len(&mut self, _at: u64, field: FieldNumber, _len: PayloadLen) -> FreeLen<'_> {
        if field.as_inner() == 3 { FreeLen::Divert } else { FreeLen::Pass }
    }
    fn on_fragment<'s>(&'s mut self, fragment: &[u8]) -> &'s [u8] {
        self.gathered.extend_from_slice(fragment);
        &[]
    }
    fn on_flush(&mut self) -> &[u8] {
        if self.flushed {
            return &[];
        }
        self.flushed = true;
        self.staged.clear();
        self.staged.push(0x1A);
        self.staged.push(self.gathered.len() as u8);
        self.staged.extend(self.gathered.iter().rev());
        &self.staged
    }
}

#[test]
fn divert_hands_the_payload_away_and_reinjects_in_place() {
    let data = h("08 01 1A 03 616263 08 02");
    let out = invariant(&data, Standard::CanonicalMinimal, || Reverser {
        gathered: Vec::new(),
        staged: Vec::new(),
        flushed: false,
    })
    .unwrap();
    assert_eq!(out, h("08 01 1A 03 636261 08 02"));
}

// ─── groups ───

struct DropGroup {
    field: u32,
    asks: u32,
}
impl Rule for DropGroup {
    fn on_group(&mut self, _at: u64, field: FieldNumber) -> FreeGroup<'_> {
        if field.as_inner() == self.field { FreeGroup::Drop } else { FreeGroup::Keep }
    }
    fn on_varint(&mut self, _at: u64, _f: FieldNumber, _v: u64, _w: u8) -> FreeScalar<'_, u64> {
        self.asks += 1;
        FreeScalar::Keep
    }
}

#[test]
fn a_dropped_group_suppresses_asks_but_wire_law_runs() {
    // Group 3 { f1, nested group 2 { f1 }, LEN } then a top-level
    // varint: everything inside vanishes silently, pairing and
    // skipping still judged.
    let data = h("1B 08 01 13 08 02 14 1A 02 6162 1C 08 05");
    let mut rule = DropGroup { field: 3, asks: 0 };
    let out = run(&data, 64, Standard::CanonicalMinimal, &mut rule).unwrap();
    assert_eq!(out, h("08 05"));
    assert_eq!(rule.asks, 1, "only the record outside the dropped tree is asked");

    // Wire law inside the suppressed tree still faults.
    let bad = h("1B 13 1C 1C");
    let fault = run(&bad, 64, Standard::CanonicalMinimal, &mut DropGroup { field: 3, asks: 0 })
        .unwrap_err();
    assert!(matches!(fault, Fault::Wire { breach: WireBreach::Grouping, .. }));
}

#[test]
fn kept_groups_ride_verbatim_with_notifications() {
    struct Witness {
        events: Vec<(u32, u64, bool)>,
    }
    impl Rule for Witness {
        fn on_group_enter(&mut self, field: FieldNumber, at: u64) {
            self.events.push((field.as_inner(), at, true));
        }
        fn on_group_exit(&mut self, field: FieldNumber, at: u64) {
            self.events.push((field.as_inner(), at, false));
        }
    }
    let data = h("1B 08 01 1C");
    let mut rule = Witness { events: Vec::new() };
    let out = run(&data, 64, Standard::CanonicalMinimal, &mut rule).unwrap();
    assert_eq!(out, data);
    assert_eq!(rule.events, [(3, 1, true), (3, 3, false)]);
}

// ─── tail injection and wire law ───

struct TailInjector {
    injected: bool,
}
impl Rule for TailInjector {
    fn on_end(&mut self) -> &[u8] {
        if self.injected {
            return &[];
        }
        self.injected = true;
        &[0x08, 0x2A]
    }
}

#[test]
fn the_stream_tail_ask_appends_after_the_last_record() {
    let data = h("10 01");
    let out =
        invariant(&data, Standard::CanonicalMinimal, || TailInjector { injected: false }).unwrap();
    assert_eq!(out, h("10 01 08 2A"));
}

#[test]
fn wire_faults_summarize_into_the_breach_vocabulary() {
    let fault = invariant(&h("00"), Standard::CanonicalMinimal, || ()).unwrap_err();
    assert!(matches!(fault, Fault::Wire { at: 0, breach: WireBreach::Tag }));

    // EOF inside a value.
    let fault = invariant(&h("08"), Standard::CanonicalMinimal, || ()).unwrap_err();
    assert!(matches!(fault, Fault::Wire { breach: WireBreach::Truncated, .. }));
}

#[test]
fn entered_len_depth_is_bounded() {
    struct EnterAll;
    impl Rule for EnterAll {
        fn on_len(&mut self, _at: u64, _f: FieldNumber, _l: PayloadLen) -> FreeLen<'_> {
            FreeLen::Commit
        }
        fn on_len_locked(&mut self, _at: u64, _f: FieldNumber, _l: PayloadLen) -> LockedLen<'_> {
            LockedLen::Commit
        }
    }
    // 101 nested LENs, built inside out (outer prefixes need two
    // varint bytes).
    let mut data = Vec::new();
    for _ in 0..101 {
        let mut outer = alloc::vec![0x0A_u8];
        crate::varint::push64(&mut outer, data.len() as u64);
        outer.extend_from_slice(&data);
        data = outer;
    }
    let fault = run(&data, 4096, Standard::CanonicalMinimal, &mut EnterAll).unwrap_err();
    assert!(matches!(fault, Fault::Wire { breach: WireBreach::Depth, .. }));
}

#[test]
#[should_panic(expected = "transcoder already terminal")]
fn feeding_after_a_fault_is_a_named_caller_bug() {
    let mut t = Transcoder::new(Standard::CanonicalMinimal, D);
    let mut out = |_: &[u8]| {};
    let _ = t.feed(&h("00"), &mut (), &mut out);
    let _ = t.feed(&h("08 01"), &mut (), &mut out);
}

// ─── the chunk-source verbs ───

#[test]
fn source_verbs_equal_their_whole_slice_twins_around_groups() {
    // group f1 { varint f2=7 } · LEN f2 "hi": inject a record
    // before the group from a chunked source, and replace the LEN
    // payload from the same source — the whole-slice twins must
    // produce identical bytes at every chunk step.
    let data = h("0B 10 07 0C 12 02 68 69");

    struct Whole {
        injected: bool,
    }
    impl Rule for Whole {
        fn on_group(&mut self, _at: u64, f: FieldNumber) -> FreeGroup<'_> {
            if f.as_inner() == 1 && !self.injected {
                self.injected = true;
                FreeGroup::Insert(&[0x18, 0x2A])
            } else {
                FreeGroup::Keep
            }
        }
        fn on_len(&mut self, _at: u64, f: FieldNumber, _l: PayloadLen) -> FreeLen<'_> {
            if f.as_inner() == 2 { FreeLen::Replace(b"XY") } else { FreeLen::Pass }
        }
    }
    let expected = invariant(&data, Standard::Tolerant, || Whole { injected: false }).unwrap();

    struct Sourced<'a> {
        injected: bool,
        pieces: &'a [&'a [u8]],
        next: usize,
    }
    impl Rule for Sourced<'_> {
        fn on_group(&mut self, _at: u64, f: FieldNumber) -> FreeGroup<'_> {
            if f.as_inner() == 1 && !self.injected {
                self.injected = true;
                FreeGroup::InsertSource(PayloadLen::new(2).unwrap())
            } else {
                FreeGroup::Keep
            }
        }
        fn on_len(&mut self, _at: u64, f: FieldNumber, _l: PayloadLen) -> FreeLen<'_> {
            if f.as_inner() == 2 { FreeLen::ReplaceSource } else { FreeLen::Pass }
        }
        fn on_source(&mut self) -> &[u8] {
            let piece = self.pieces.get(self.next).copied().unwrap_or(&[]);
            self.next += 1;
            piece
        }
    }
    // The group injection's account consumes the first two pieces,
    // the replacement's the rest.
    let pieces: [&[u8]; 4] = [&[0x18], &[0x2A], &[0x58], &[0x59]];
    let sourced = invariant(&data, Standard::Tolerant, || Sourced {
        injected: false,
        pieces: &pieces,
        next: 0,
    })
    .unwrap();
    assert_eq!(sourced, expected);

    // A short source is the rule's own breach, quoted with what it
    // still owes.
    let short: [&[u8]; 3] = [&[0x18], &[0x2A], &[0x58]];
    let fault = run(
        &data,
        data.len(),
        Standard::Tolerant,
        &mut Sourced { injected: false, pieces: &short, next: 0 },
    )
    .unwrap_err();
    assert!(matches!(
        fault,
        Fault::Rule(breach) if matches!(
            breach.kind(),
            RuleFaultKind::SourceShort { owed, .. } if owed.as_inner() == 1
        )
    ));
}
