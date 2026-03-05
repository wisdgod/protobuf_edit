# protobuf_edit

Low-level, schema-less utilities for inspecting and editing raw Protocol Buffers binary data.

This crate is designed for situations where you do **not** have (or do not want to depend on)
generated protobuf types, but still need to:

- inspect a message at the wire level,
- edit selected fields,
- keep byte-level fidelity where possible.

## Design principles

- Performance-oriented: keep hot paths simple and allocation-light.
- Practical correctness: prefer explicit, testable invariants over cleverness.
- Byte fidelity: preserve original bytes for unchanged fields when possible.
- Two models on purpose: choose between `Document` and `Patch` based on workload.

## Editing models

`protobuf_edit` intentionally exposes two different models:

- `Document`: an arena-backed structured editor.
  - Decodes a message into typed storage slots.
  - Maintains raw varint/tag/len-prefix caches and updates them eagerly on edits.
  - Best for deep, structured transformations.
- `Patch`: a span-based patcher.
  - Scans the message and records byte spans into the original source buffer.
  - Tracks payload edits lazily and materializes them on `save()`, copying unchanged spans verbatim.
  - Supports inserting and deleting fields; `save_and_reparse()` refreshes spans after changes.
  - Best for “edit a few fields and forward the message” workflows.

Short aliases are also provided:

- `ArenaTree` = `Document`
- `SpanTree` = `Patch`

## API layout

Public modules are grouped by concern:

- `protobuf_edit::buf`: shared byte storage (`Buf`, `BufAllocError`)
- `protobuf_edit::error`: shared crate error (`TreeError`)
- `protobuf_edit::document`: arena-backed structured editing API
- `protobuf_edit::patch`: span-based editing API
- `protobuf_edit::wire`: tag primitives (`Tag`, `FieldNumber`, `WireType`)
- `protobuf_edit::varint`: varint and zigzag codecs
- `protobuf_edit::stream`: incremental wire parser

Common entry types are still re-exported at the crate root for convenience.

## Quick start

### Build / edit with `Document`

```rust
use protobuf_edit::{buf::Buf, document::Document, wire::FieldNumber};

let mut doc = Document::new();
let f1 = FieldNumber::new(1).unwrap();
doc.push_varint(f1, 150).unwrap();

let bytes: Buf = doc.to_buf().unwrap();
assert!(!bytes.is_empty());
```

### Patch bytes with `Patch`

```rust
use protobuf_edit::{patch::Patch, wire::{FieldNumber, Tag, WireType}};

let mut patch = Patch::from_bytes(&[0x08, 0x96, 0x01]).unwrap(); // field 1 = 150
let root = patch.root();
let tag = Tag::from_parts(FieldNumber::new(1).unwrap(), WireType::Varint);

let field_id = patch.fields_by_tag(root, tag).unwrap().next().unwrap();
let before = patch.varint(field_id).unwrap();
patch.set_varint(field_id, before + 1).unwrap();

let tag2 = Tag::from_parts(FieldNumber::new(2).unwrap(), WireType::Varint);
let _new_field = patch.insert_varint(root, tag2, 7).unwrap();
patch.delete_field(field_id).unwrap();

let out = patch.save().unwrap();
assert_ne!(out.as_slice(), &[0x08, 0x96, 0x01]);

let reparsed = patch.save_and_reparse().unwrap();
assert!(!reparsed.root_bytes().is_empty());
```

## Features

- `group`: enables protobuf group wire types (`StartGroup`/`EndGroup`) support.
- `nightly` (default): enables nightly-only optimizations and internal features.

## License

Apache-2.0. See `LICENSE`.
