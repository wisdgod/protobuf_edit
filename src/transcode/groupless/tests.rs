//! Contract pins for the groupless transcoder: exhaustive on the
//! dialect clauses (capability refusal, root-only free layer),
//! representative on shared semantics.

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

// ─── the dialect's own clauses ───

#[test]
fn group_codes_are_the_inherited_capability_refusal() {
    let fault = invariant(&h("0B"), Standard::Tolerant, || ()).unwrap_err();
    assert!(matches!(fault, Fault::Wire { at: 0, breach: WireBreach::GroupCode }));
}

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

#[test]
fn the_free_layer_is_exactly_the_root() {
    // Enter locks; the interior varint reaches the locked ask, and
    // a locked rewrite must hold width.
    struct EnterAndRewrite;
    impl Rule for EnterAndRewrite {
        fn on_len(&mut self, _at: u64, _f: FieldNumber, _l: PayloadLen) -> FreeLen<'_> {
            FreeLen::Commit
        }
        fn on_varint_locked(
            &mut self,
            _at: u64,
            _f: FieldNumber,
            _v: u64,
            _w: u8,
        ) -> LockedScalar<u64> {
            LockedScalar::Rewrite(300)
        }
    }
    let data = h("0A 02 08 01");
    let fault = invariant(&data, Standard::Tolerant, || EnterAndRewrite).unwrap_err();
    assert!(matches!(
        fault,
        Fault::Rule(RuleFault { kind: RuleFaultKind::RewriteOverflow { .. }, .. })
    ));
}

// ─── shared semantics, representative ───

#[test]
fn the_default_rule_is_a_bit_true_transcoder() {
    let data = h("88 00 01 0A 82 80 00 61 62 08 81 00 15 01020304 12 04 0A 02 08 01");
    let out = invariant(&data, Standard::Tolerant, || ()).unwrap();
    assert_eq!(out, data);
}

#[test]
fn locked_rewrites_pad_to_the_source_width_under_tolerant() {
    struct LockedRewrite;
    impl Rule for LockedRewrite {
        fn on_len(&mut self, _at: u64, _f: FieldNumber, _l: PayloadLen) -> FreeLen<'_> {
            FreeLen::Commit
        }
        fn on_varint_locked(
            &mut self,
            _at: u64,
            _f: FieldNumber,
            _v: u64,
            _w: u8,
        ) -> LockedScalar<u64> {
            LockedScalar::Rewrite(1)
        }
    }
    let data = h("0A 03 10 8001");
    let out = invariant(&data, Standard::Tolerant, || LockedRewrite).unwrap();
    assert_eq!(out, h("0A 03 10 8100"));
}

#[test]
fn transform_streams_and_accounts() {
    struct Xor;
    impl Rule for Xor {
        fn on_len(&mut self, _at: u64, _f: FieldNumber, _l: PayloadLen) -> FreeLen<'_> {
            FreeLen::Transform
        }
        fn on_fragment<'s>(&'s mut self, fragment: &[u8]) -> &'s [u8] {
            // Equal length by construction: flip in place via a
            // static-free per-call buffer is impossible without
            // state, so this test keeps a byte and asserts the
            // account instead through a stateless echo.
            fragment_len_check(fragment)
        }
    }
    // A stateless echo cannot borrow the fragment (lifetimes), so
    // this rule underpays: the shortfall account must fire.
    fn fragment_len_check(_fragment: &[u8]) -> &'static [u8] {
        &[]
    }
    let data = h("1A 03 616263");
    let fault = invariant(&data, Standard::CanonicalMinimal, || Xor).unwrap_err();
    assert!(matches!(
        fault,
        Fault::Rule(RuleFault { kind: RuleFaultKind::TransformShortfall { .. }, .. })
    ));
}

#[test]
fn divert_reinjects_at_the_records_position() {
    struct Swap {
        gathered: Vec<u8>,
        staged: Vec<u8>,
        done: bool,
    }
    impl Rule for Swap {
        fn on_len(&mut self, _at: u64, field: FieldNumber, _l: PayloadLen) -> FreeLen<'_> {
            if field.as_inner() == 3 { FreeLen::Divert } else { FreeLen::Pass }
        }
        fn on_fragment<'s>(&'s mut self, fragment: &[u8]) -> &'s [u8] {
            self.gathered.extend_from_slice(fragment);
            &[]
        }
        fn on_flush(&mut self) -> &[u8] {
            if self.done {
                return &[];
            }
            self.done = true;
            self.staged.clear();
            self.staged.push(0x1A);
            self.staged.push(self.gathered.len() as u8);
            self.staged.extend(self.gathered.iter().rev());
            &self.staged
        }
    }
    let data = h("08 01 1A 03 616263 08 02");
    let out = invariant(&data, Standard::CanonicalMinimal, || Swap {
        gathered: Vec::new(),
        staged: Vec::new(),
        done: false,
    })
    .unwrap();
    assert_eq!(out, h("08 01 1A 03 636261 08 02"));
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
fn eof_verdicts_pass_through() {
    let fault = invariant(&h("0A 05 6161"), Standard::Tolerant, || ()).unwrap_err();
    assert!(matches!(fault, Fault::Wire { at: 4, breach: WireBreach::Truncated }));
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

#[test]
#[should_panic(expected = "transcoder already terminal")]
fn feeding_after_a_fault_is_a_named_caller_bug() {
    let mut t = Transcoder::new(Standard::CanonicalMinimal, D);
    let mut out = |_: &[u8]| {};
    let _ = t.feed(&h("0B"), &mut (), &mut out);
    let _ = t.feed(&h("08 01"), &mut (), &mut out);
}

// ─── the chunk-source verbs ───

/// A scripted chunk source: answers `pieces` in order, one per
/// ask, judged by the account it serves.
struct Scripted<'a> {
    /// The verdicts, keyed by ask order at f1 varints and f2 LENs.
    insert_at_f1: Option<PayloadLen>,
    replace_f2: bool,
    pieces: &'a [&'a [u8]],
    next: usize,
    inserted: bool,
}

impl Rule for Scripted<'_> {
    fn on_varint(&mut self, _at: u64, field: FieldNumber, _v: u64, _w: u8) -> FreeScalar<'_, u64> {
        match self.insert_at_f1 {
            Some(len) if field.as_inner() == 1 && !self.inserted => {
                self.inserted = true;
                FreeScalar::InsertSource(len)
            }
            _ => FreeScalar::Keep,
        }
    }
    fn on_len(&mut self, _at: u64, field: FieldNumber, _l: PayloadLen) -> FreeLen<'_> {
        if self.replace_f2 && field.as_inner() == 2 {
            FreeLen::ReplaceSource
        } else {
            FreeLen::Pass
        }
    }
    fn on_source(&mut self) -> &[u8] {
        let piece = self.pieces.get(self.next).copied().unwrap_or(&[]);
        self.next += 1;
        piece
    }
}

#[test]
fn source_verbs_equal_their_whole_slice_twins() {
    // varint f1=7 · LEN f2 "hi": insert a record before f1 from a
    // chunked source, and replace f2's payload from another — the
    // whole-slice twins must produce identical bytes at every
    // chunk step.
    let data = h("08 07 12 02 68 69");

    struct Whole {
        inserted: bool,
    }
    impl Rule for Whole {
        fn on_varint(&mut self, _at: u64, f: FieldNumber, _v: u64, _w: u8) -> FreeScalar<'_, u64> {
            if f.as_inner() == 1 && !self.inserted {
                self.inserted = true;
                FreeScalar::Insert(&[0x18, 0x2A])
            } else {
                FreeScalar::Keep
            }
        }
        fn on_len(&mut self, _at: u64, f: FieldNumber, _l: PayloadLen) -> FreeLen<'_> {
            if f.as_inner() == 2 { FreeLen::Replace(b"XY") } else { FreeLen::Pass }
        }
    }
    let expected = invariant(&data, Standard::Tolerant, || Whole { inserted: false }).unwrap();

    let insert_pieces: [&[u8]; 2] = [&[0x18], &[0x2A]];
    let sourced = invariant(&data, Standard::Tolerant, || Scripted {
        insert_at_f1: Some(PayloadLen::new(2).unwrap()),
        replace_f2: false,
        pieces: &insert_pieces,
        next: 0,
        inserted: false,
    })
    .unwrap();
    assert_eq!(sourced[..4], expected[..4], "the sourced insert emits the declared bytes");

    // The full pairing: both source verbs against both
    // whole-slice verbs, byte-identical — the insert's account
    // consumes the first two pieces, the replace's the rest.
    let replace_pieces: [&[u8]; 4] = [&[0x18], &[0x2A], &[0x58], &[0x59]];
    let both = invariant(&data, Standard::Tolerant, || Scripted {
        insert_at_f1: Some(PayloadLen::new(2).unwrap()),
        replace_f2: true,
        pieces: &replace_pieces,
        next: 0,
        inserted: false,
    })
    .unwrap();
    assert_eq!(both, expected);
}

#[test]
fn short_and_long_sources_are_the_rules_own_breaches() {
    let data = h("12 02 68 69");
    // Short: the source closes (answers empty) owing one byte.
    let pieces: [&[u8]; 1] = [b"X"];
    let fault = run(
        &data,
        data.len(),
        Standard::Tolerant,
        &mut Scripted {
            insert_at_f1: None,
            replace_f2: true,
            pieces: &pieces,
            next: 0,
            inserted: false,
        },
    )
    .unwrap_err();
    assert!(matches!(
        fault,
        Fault::Rule(breach) if matches!(
            breach.kind(),
            RuleFaultKind::SourceShort { owed, .. } if owed.as_inner() == 1
        )
    ));

    // Long: a chunk past the account is refused whole — the
    // output holds nothing of the overrunning chunk.
    let pieces: [&[u8]; 2] = [b"X", b"YZ"];
    let mut emitted = Vec::new();
    let mut t = Transcoder::new(Standard::Tolerant, D);
    let mut rule = Scripted {
        insert_at_f1: None,
        replace_f2: true,
        pieces: &pieces,
        next: 0,
        inserted: false,
    };
    let fault =
        t.feed(&data, &mut rule, &mut |bytes: &[u8]| emitted.extend_from_slice(bytes)).unwrap_err();
    assert!(matches!(
        fault,
        Fault::Rule(breach) if matches!(breach.kind(), RuleFaultKind::SourceOverrun { .. })
    ));
    assert_eq!(emitted, h("12 02 58"), "head, prefix, and the in-account piece only");
}
