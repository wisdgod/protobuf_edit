//! The groupless fixed patch cell's scoped rows: the slab-demand
//! boundary judged in-module, so the lone cell compiles it. The
//! command batteries, exhaustion sweeps, and heap-twin lockstep
//! live in the integration judges.

use core::mem::MaybeUninit;

use super::*;
use crate::DepthLimit;

#[test]
fn the_slab_judgment_is_exact_at_any_address() {
    // varint f1=150 · LEN f2 "hi": two top rows, one payload.
    let doc = [0x08, 0x96, 0x01, 0x12, 0x02, 0x68, 0x69];
    let mut backing = [MaybeUninit::<u8>::uninit(); 1 << 12];
    let mixed = Plan::new(8, 4, 4, 64, 2).unwrap();
    let borrowed = BorrowPlan::new(8, 4, 4, 2).unwrap();
    let copy = CopyPlan::new(8, 4, 4, 64, 2).unwrap();
    let judged = [
        (mixed.bytes(DepthLimit::REFERENCE), 0_usize),
        (borrowed.bytes(DepthLimit::REFERENCE), 1),
        (copy.bytes(DepthLimit::REFERENCE), 2),
    ];
    for (need, door) in judged {
        let need = usize::try_from(need).unwrap();
        assert!(need + 8 <= backing.len(), "the fixture slab covers the demand");
        for offset in 0..8 {
            // Exactly the demand carves and opens, at every
            // address; one byte fewer refuses as a pure length
            // compare before any lane is touched.
            let exact = &mut backing[offset..offset + need];
            let opened = match door {
                0 => Patch::open(&doc, DepthLimit::REFERENCE, &mixed, exact).map(|_| ()),
                1 => BorrowPatch::open(&doc, DepthLimit::REFERENCE, &borrowed, exact).map(|_| ()),
                _ => CopyPatch::open(&doc, DepthLimit::REFERENCE, &copy, exact).map(|_| ()),
            };
            assert!(opened.is_ok(), "door {door} refused its own price at offset {offset}");
            let short = &mut backing[offset..offset + need - 1];
            let refused = match door {
                0 => Patch::open(&doc, DepthLimit::REFERENCE, &mixed, short).map(|_| ()),
                1 => BorrowPatch::open(&doc, DepthLimit::REFERENCE, &borrowed, short).map(|_| ()),
                _ => CopyPatch::open(&doc, DepthLimit::REFERENCE, &copy, short).map(|_| ()),
            };
            assert!(
                matches!(refused, Err(OpenFault::SlabShort { .. })),
                "door {door} carved one byte under its price at offset {offset}"
            );
        }
    }
}
