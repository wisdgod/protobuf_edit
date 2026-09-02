#!/usr/bin/env bash
# The no-alloc consumer judge, runnable locally and in CI. Four
# parts, each recorded: (1) the probe builds for a bare-metal
# target with only the fixed-scratch cells and no
# #[global_allocator]; (2) the tightness control — the same probe
# plus the allocation-free heap cell — must also build, proving
# the alloc gate did not re-grow over a cell that owes nothing;
# (3) the red control — the probe plus one allocating heap cell —
# must fail to build; (4) the red failure must name the allocator
# obligation, so a refusal for any other reason cannot impersonate
# the judgment.
set -u
cd "$(dirname "$0")"

target=x86_64-unknown-none
if ! rustup target list --installed | grep -qx "$target"; then
    echo "no-alloc judge: missing target $target (run: rustup target add $target)" >&2
    exit 2
fi

if ! cargo build --target "$target"; then
    echo "no-alloc judge RED: the fixed-cells-only probe did not build" >&2
    exit 1
fi
echo "no-alloc judge 1/4: green leg built (fixed cells only, no #[global_allocator])"

if ! cargo build --target "$target" --features alloc-free-cell; then
    echo "no-alloc judge RED: the allocation-free heap cell re-grew the gate (traverse-groupless owes no allocator)" >&2
    exit 1
fi
echo "no-alloc judge 2/4: tightness control built (the allocation-free heap cell stays unbilled)"

if red_log=$(cargo build --target "$target" --features alloc-control 2>&1); then
    echo "no-alloc judge RED: the alloc-pulling control built — the instrument is blind" >&2
    exit 1
fi
echo "no-alloc judge 3/4: red control refused (one heap cell restores the graph's allocator obligation)"

if ! printf '%s\n' "$red_log" | grep -q "no global memory allocator found"; then
    echo "no-alloc judge RED: the control failed for another reason:" >&2
    printf '%s\n' "$red_log" >&2
    exit 1
fi
echo "no-alloc judge 4/4: the refusal names the allocator obligation (no global memory allocator found)"
