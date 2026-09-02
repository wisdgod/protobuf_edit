//! Pump-level pins: facts every machine relies on but none states.

use super::{Pump, Verdict};
use crate::Standard;

/// [`Verdict::Done`]'s derivation root on the held face: the carry
/// holds the completed construct's source bytes, so `carry.len()`
/// is the source width — on the single-byte fast path, the
/// in-chunk loop, and a construct cut across two feeds alike.
#[test]
fn the_held_face_leaves_the_carry_holding_the_source_width() {
    let mut pump = Pump::new(Standard::Tolerant);

    // Width one: the fast path stores the byte before completing.
    let mut chunk: &[u8] = &[0x7F];
    assert!(matches!(pump.step_value_held(&mut chunk, Standard::Tolerant), Verdict::Done(0x7F)));
    assert_eq!(pump.carry.len(), 1);
    pump.carry.clear();

    // Width two, whole in one chunk: 150 = [0x96, 0x01].
    let mut chunk: &[u8] = &[0x96, 0x01];
    assert!(matches!(pump.step_value_held(&mut chunk, Standard::Tolerant), Verdict::Done(150)));
    assert_eq!(pump.carry.len(), 2);
    pump.carry.clear();

    // The same construct cut across two feeds.
    let mut first: &[u8] = &[0x96];
    assert!(matches!(pump.step_value_held(&mut first, Standard::Tolerant), Verdict::More));
    let mut second: &[u8] = &[0x01];
    assert!(matches!(pump.step_value_held(&mut second, Standard::Tolerant), Verdict::Done(150)));
    assert_eq!(pump.carry.len(), 2);
}

/// The spent face clears at `Done` — a value consumer owes no
/// bookkeeping and the next construct steps on an empty carry —
/// while a fault verdict still holds the refused construct (its
/// coordinate is derived from the carry).
#[test]
fn the_spent_face_clears_at_done_and_holds_on_a_fault() {
    let mut pump = Pump::new(Standard::CanonicalMinimal);

    let mut chunk: &[u8] = &[0x96, 0x01];
    assert!(matches!(pump.step_value(&mut chunk, Standard::CanonicalMinimal), Verdict::Done(150)));
    assert!(pump.carry.is_empty());

    // Padded 150 refused under the minimal standard: the carry
    // still holds all three source bytes, so `construct_start`
    // names the construct's first byte.
    let mut padded: &[u8] = &[0x96, 0x81, 0x00];
    assert!(matches!(
        pump.step_value(&mut padded, Standard::CanonicalMinimal),
        Verdict::NonMinimal
    ));
    assert_eq!(pump.carry.len(), 3);
    assert_eq!(pump.construct_start(), 2);
}
