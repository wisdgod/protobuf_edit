# protobuf_edit

Low-level, schema-less utilities for inspecting and editing raw Protocol Buffers binary data.

This crate is designed for situations where you do **not** have (or do not want to depend on)
generated protobuf types, but still need to:

- inspect a message at the wire level,
- edit selected fields,
- extract fields from a byte stream as it arrives,
- keep byte-level fidelity where possible.

`no_std` + `alloc`. Requires a nightly toolchain.

## Design principles

- Performance-oriented: keep hot paths simple, allocation-light, and copy-free where possible.
- Practical correctness: prefer explicit, testable invariants over cleverness.
- Byte fidelity: preserve original bytes (including non-canonical varints) for unchanged fields.
- Multiple models on purpose: choose between `Document`, `Patch`, and the stream walkers based on workload.

## Choosing a model

| Model | Best for | Cost profile |
|---|---|---|
| `Document` | deep structured transformations, building messages from scratch | eager decode into typed pools |
| `Patch` | "edit a few fields and forward the message" | span scan only; unchanged bytes copied verbatim on `save()` |
| `Scanner` | extracting a few fields from one complete buffer | zero-copy, zero-alloc, single pass |
| `ChunkStream` | the same extraction over data that arrives in pieces | buffers only boundary-straddling state |

## API layout

Public modules are grouped by concern:

- `protobuf_edit::buf`: shared byte storage (`Buf`, `BufAllocError`)
- `protobuf_edit::error`: shared crate error (`TreeError`)
- `protobuf_edit::document`: arena-backed structured editing
- `protobuf_edit::patch`: span-based editing
- `protobuf_edit::stream`: trie-matched wire walkers (`Scanner`, `ChunkStream`)
- `protobuf_edit::wire`: tag primitives (`Tag`, `FieldNumber`, `WireType`, `tag!`)
- `protobuf_edit::varint`: varint and zigzag codecs

The crate root re-exports only the shared vocabulary (`Buf`, `TreeError`, `Tag`,
`FieldNumber`, `WireType`) and each model's entry type (`Document`, `BorrowedDocument`,
`Patch`, `BorrowedPatch`); everything else lives in its module.

## `Document`: structured editing

`Document` eagerly decodes a message into typed storage pools (varint / fixed32 / fixed64 /
length-delimited), keeps fields in insertion order, and links repeated fields per tag.
Raw wire bytes (tag, varint, length prefix) are cached alongside decoded values, so
re-encoding an untouched field reproduces its original bytes exactly.

Construction:

- `Document::new()` / `Document::with_capacities(caps)` — build from scratch
- `Document::from_bytes(data)` — decode with heuristic pre-reservation
- `Document::from_bytes_precise(data)` — two-pass decode with exact capacities
- `BorrowedDocument::from_bytes(data)` — zero-copy: payloads borrow from `data`;
  `into_owned()` upgrades to an independent `Document`

Building and encoding:

```rust
use protobuf_edit::{Buf, Document, FieldNumber};

let mut doc = Document::new();
let f1 = FieldNumber::new(1).unwrap();
let f2 = FieldNumber::new(2).unwrap();
doc.push_varint(f1, 150)?;
doc.push_length_delimited(f2, Buf::from_static(b"hello"))?;

let bytes: Buf = doc.to_buf()?; // or encode_into(&mut buf) / encoded_len()
```

Reading with `FieldRef`:

```rust
let doc = Document::from_bytes(bytes.as_slice())?;

// Iterate everything in insertion order:
for field in doc.field_refs() {
    let _ = (field.tag(), field.wire_type());
}

// Look up by tag; interpret the wire value as a protobuf scalar type:
let t = tag!(1, Varint);
let v: u64 = doc.first_ref(t).unwrap().as_uint64().unwrap();
```

`FieldRef` offers the full scalar matrix (`as_uint32/64`, `as_int32/64`, `as_sint32/64`,
`as_bool`, `as_fixed*`/`as_sfixed*`, `as_float`/`as_double`, `as_bytes`), packed-repeated
iterators (`packed_uint32(...)` etc.), and nested access via `as_message()`.

Editing with `FieldMut`:

```rust
let mut doc = Document::from_bytes(bytes.as_slice())?;

let mut f = doc.first_mut(tag!(1, Varint)).unwrap();
f.set_uint64(151)?;                 // or f.uint64(|v| *v += 1)?
f.mark_removed();                   // tombstone; skipped by encoding

// Nested messages, closure style:
doc.first_mut(tag!(2, Len)).unwrap()
    .message(|nested| nested.push_varint(field_number!(3), 7).map(|_| ()))?;

// Or RAII style — MessageGuard derefs to Document, finish() re-encodes:
let mut guard = doc.first_mut(tag!(2, Len)).unwrap().decode_message()?;
guard.push_varint(field_number!(4), 8)?;
guard.finish()?;
```

Repeated fields: `repeated_refs(tag)` iterates live occurrences; `repeated_visit_mut(tag, f)`
edits them in place. `visit_planned_refs` / `edit_planned_mut` walk a multi-level
`(tag, capacities)` path plan across nested messages in one call.

## `Patch`: span-based editing

`Patch` scans a message once and records byte spans into the source buffer. Reads decode
on demand straight from those spans; edits are stored as overlays. `save()` writes output
by copying unchanged spans verbatim and materializing only the overlays, so untouched
bytes survive byte-for-byte.

- `Patch::from_bytes(data)` clones the input; `Patch::from_buf(buf)` takes ownership;
  `BorrowedPatch::from_bytes(data)` borrows it (zero-copy)
- Navigation: `root()`, `message_fields(msg)`, `fields_by_tag(msg, tag)`,
  `parse_child_message(field)` lazily parses a nested message
- Reads: `varint(field)`, `i32_bits` / `i64_bits`, `bytes`; `enable_read_cache()` memoizes
  repeated varint reads
- Spans: `field_spans(field)` (tag / len-prefix / payload sub-spans),
  `field_root_spans` maps into absolute root coordinates — useful for hex-view UIs
- Edits: `set_varint` / `set_i32_bits` / `set_i64_bits` / `set_bytes`,
  `insert_*(msg, tag, ...)`, `delete_field`, `clear_field_edit`
- Output: `save()` → `Buf`, `save_and_reparse()` refreshes spans after heavy editing
- Transactions: `txn_begin()` / `txn_commit()` / `txn_rollback()`, or the RAII
  `Txn::begin(&mut patch)` guard (rolls back on drop)

```rust
use protobuf_edit::{Patch, tag};

let mut patch = Patch::from_bytes(&[0x08, 0x96, 0x01])?; // field 1 = 150
let root = patch.root();
let t = tag!(1, Varint);

let field = patch.fields_by_tag(root, t)?.next().unwrap();
let before = patch.varint(field)?;
patch.set_varint(field, before + 1)?;
patch.insert_varint(root, tag!(2, Varint), 7)?;

let out = patch.save()?;
```

## `stream`: trie-matched wire walkers

Compile the paths you care about into a `const` trie, then walk bytes and receive
callbacks only for matched paths. Nesting is tracked as a frame stack over one logical
byte stream; nothing is decoded for subtrees that cannot match.

```rust
use protobuf_edit::stream::{Scanner, ChunkStream, WireHandler};
use protobuf_edit::{const_trie, tag, wire::Tag};

const PATH: [Tag; 2] = tag!([(3, Len), (1, Varint)]);
let trie = const_trie!(3, 2, [&PATH]); // MAX_NODES, MAX_EDGES, paths

struct Sum(u64);
impl WireHandler for Sum {
    fn on_varint(&mut self, _path: &[Tag], v: u64) -> Result<(), protobuf_edit::TreeError> {
        self.0 += v;
        Ok(())
    }
}

// One complete buffer: zero-copy, zero-alloc.
let mut sum = Sum(0);
Scanner::with_trie(trie).scan(message_bytes, &mut sum)?;

// Chunked input: only boundary-straddling state is buffered.
let mut stream = ChunkStream::with_trie(trie);
for chunk in chunks {
    stream.feed(chunk, &mut sum)?;
}
stream.finish()?; // errors if a field is left unfinished
```

`WireHandler` has default no-op implementations for `on_varint`, `on_i32`, `on_i64`,
`on_length_delimited`, and (with the `group` feature) `on_group`; implement only what you
need. Each callback receives the full tag path of the matched field.

`ChunkStream::set_emit_partial_matches(true)` additionally reports matched
length-delimited/group payloads as they accumulate (`is_last == false`), which lets huge
payloads flow through without ever being buffered whole.

## `wire`, `varint`, `buf`

- `wire`: `Tag` (non-zero `(field_number << 3) | wire_type`), `FieldNumber` (niche-packed
  `1..=2^29-1`), `WireType`, `encode_tag` / `encode_tag_value` / `decode_tag`, and
  `FieldCursor` — a zero-allocation iterator over one complete message that yields each
  field's decoded value, exact raw span, and offset (`Result<RawField, CursorError>`,
  errors carry offset + kind).
- Definition macros, compile-time checked and structure-preserving:
  `tag!(1, Len)` / `tag!(1, 2)` → `Tag` (no `WireType` import needed),
  `tag!([(1, Len), (3, Varint)])` → `[Tag; 2]`;
  `field_number!(5)` → `FieldNumber`, `field_number!([[1], [2]])` → `[[FieldNumber; 1]; 2]`.
- `varint`: `encode32/64`, `decode32/64` (branchless single-byte fast path, overlong-encoding
  rejection), `encoded_len32/64`, and `zigzag_encode32/64` / `zigzag_decode32/64` for `sint*`.
- `buf::Buf`: the crate-wide byte container — 16 bytes on the stack with three backing modes:
  inline (≤ 12 bytes), owned heap, or borrowed external memory. `Buf::from_vec` /
  `Buf::into_vec` move allocations without copying; `Buf::from_static` wraps constants.
  Fallible (`try_*`) variants exist for every growth path.

All fallible APIs return `TreeError`. Decode failures are structured:
`Malformed { offset }` points at the failing unit within the buffer being decoded
(message-local for nested messages) and `Truncated` reports an input that ended
inside a field. The remaining variants describe states: `InvalidId` (stale or
foreign id, or data unavailable for it), `Corrupted` (internal invariant broken),
`CapacityExceeded`, `InvalidTag`, and `WireTypeMismatch`.

## Cargo features

- `nightly` (default): nightly-only optimizations in dependencies (`hashbrown`, `rustc-hash`).
  The crate itself always requires nightly rustc.
- `group`: wire support for `SGROUP`/`EGROUP` fields across all models.

## Limits

- Message size ≤ `i32::MAX` bytes; `Document` holds at most 65 535 fields per message.
- Nesting depth in the stream walkers is capped at 100.

## License

Apache-2.0. See `LICENSE`.
