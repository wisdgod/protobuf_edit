//! The fixed-scratch family's feature-form judge: a `#![no_std]`
//! `#![no_main]` consumer with only the fixed cells enabled and no
//! `#[global_allocator]`, built for a bare-metal target.
//!
//! The allocator link obligation is billed by crate-graph
//! membership, not by use, so this binary builds exactly when no
//! alloc obligation survives in the enabled graph — one build
//! judges the gated `extern crate alloc`, the strata's gated alloc
//! faces, and the fixed cells' no-implication rule at once. The
//! `alloc-free-cell` feature is the tightness control: it adds
//! the heap-hosted cell that allocates nothing, and the same
//! allocator-free build must keep holding. The `alloc-control`
//! feature is the red control: it pulls one allocating heap cell,
//! and the build must then fail naming the allocator obligation
//! (`judge.sh` holds all four parts).
//!
//! The body is one real job per pilot family, so the probe also
//! proves the faces are reachable and complete under the cut, not
//! merely present.

#![no_std]
#![no_main]

use core::hint::black_box;
use core::mem::MaybeUninit;

use protobuf_edit::fixed_inplace::groupless as fixed_inplace;
use protobuf_edit::fixed_inspect::groupless as fixed_inspect;
use protobuf_edit::fixed_patch::groupless as fixed_patch;
use protobuf_edit::inplace::{Action, Rule, RuleSet};
use protobuf_edit::inspect::{Admitted, NoAdvice};
use protobuf_edit::path::Segment;
use protobuf_edit::{DepthLimit, FieldNumber};

/// One allocator-free job per fixed family, end to end: a rule job
/// landed in the caller's own buffer, a patch opened, edited, and
/// saved into caller memory, and an inspection parsed and queried
/// over a stack slab — every working byte carved from that slab.
/// The inspect job also proves the widened host vocabulary
/// (`Admitted`, the advisor faces) carries no alloc obligation.
fn exercise() -> u32 {
    let field = FieldNumber::new(1).unwrap();

    let rules = [Rule { path: &[Segment::Field(field)], action: Action::SetVarint(0) }];
    let set = RuleSet::over(&rules).unwrap();
    let plan = fixed_inplace::Plan::new(1).unwrap();
    let mut slab = [MaybeUninit::<u8>::uninit(); 4096];
    assert!(plan.bytes(&set, DepthLimit::REFERENCE) <= slab.len());
    let mut buf = [0x08, 0x05];
    let stats =
        fixed_inplace::apply(&mut buf, &set, DepthLimit::REFERENCE, &plan, &mut slab).unwrap();

    let plan = fixed_patch::Plan::new(4, 2, 2, 32, 2).unwrap();
    let mut slab = [MaybeUninit::<u8>::uninit(); 8192];
    assert!(plan.bytes(DepthLimit::REFERENCE) <= slab.len() as u64);
    let msg = [0x08, 0x05];
    let mut patch =
        fixed_patch::Patch::open(&msg, DepthLimit::REFERENCE, &plan, &mut slab).unwrap();
    let record = patch.top().next().unwrap();
    patch.set_varint(record, 0x7F).unwrap();
    let mut out = [0u8; 8];
    let written = patch.save_into(&mut out).unwrap();

    // varint f1=150 · LEN f2 "hi": admit, parse over a stack slab,
    // query words and the hex-view reverse index.
    let doc = [0x08, 0x96, 0x01, 0x12, 0x02, 0x68, 0x69];
    let input = Admitted::new(&doc).unwrap();
    let plan = fixed_inspect::Plan::new(4).unwrap();
    let mut slab = [MaybeUninit::<u8>::uninit(); 256];
    assert!(plan.bytes(DepthLimit::REFERENCE) <= slab.len() as u64);
    let tree =
        fixed_inspect::Tree::parse(input, DepthLimit::REFERENCE, &mut NoAdvice, &plan, &mut slab)
            .unwrap();
    let first = tree.top().next().unwrap();
    let word = tree.varint_word(first).unwrap_or(0);
    let covered = tree.narrowest(5).map_or(0, |id| tree.span(id).len());

    #[allow(clippy::cast_possible_truncation)]
    let inspected = word as u32 + covered + tree.node_count();

    stats.replaced() + written + u32::from(out[1]) + u32::from(buf[1]) + inspected
}

#[unsafe(no_mangle)]
extern "C" fn _start() -> ! {
    black_box(exercise());
    loop {}
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
