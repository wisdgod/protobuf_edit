# protobuf_edit

Schema-less, low-level inspection and editing of Protocol Buffers
wire bytes. No generated types and no `.proto` inputs: the library
reads and writes the wire format itself, for tooling that meets
protobuf as bytes — debuggers, proxies, forensics, hex-view UIs,
migration jobs. Where schema knowledge exists, the caller supplies
it explicitly; where it doesn't, the wire format's own facts are all
the library claims. `#![no_std]` with `alloc` riding the heap
cells' features (the fixed-scratch cells run with no allocator in
the graph at all), zero required dependencies (the priced cells —
`priced-session-*` and `priced-transfer-session-*` — alone pull
`hashbrown` and `rustc-hash`, both `no_std`), nightly Rust, 32- and
64-bit targets.

## In 30 seconds

36 scenario modules cover the read/write/author space; each ships
two independent types — a **grouped** dialect (full wire language
including legacy start/end-group codes) and a **groupless** twin
(modern four-code subset that rejects group codes as a capability
judgment). Every module × dialect pair is a separate cargo feature
(`<module>-<dialect>`, plus capability cells over their base cells:
a `transfer-<module>-*` pair on each of the thirteen
transfer-capable families, and the priced cells `priced-session-*`
and `priced-transfer-session-*` over the session pair), all
additive, all optional. The unconditional
strata — `wire` (tag vocabulary), `varint` (encoding theorems and
reading kernels), `scalar` (typed scalar matrix), `path`
(selection-path programs) — are always present.

Validate a stream chunk by chunk:

```rust
use protobuf_edit::scan::groupless::Validator;
use protobuf_edit::scan::Standard;

let mut v = Validator::new(Standard::Tolerant);
v.feed(&[0x08, 0x96, 0x01]).unwrap();   // field 1, varint 150
v.finish().unwrap();                      // stream complete, legal
```

## Pick your features

Start from what you need to *do*, enable the matching feature(s),
and pick a dialect.

| I want to … | Module | Feature | Entry point |
|---|---|---|---|
| Select records by compiled path programs | `select` | `select-*` | `Matches::over`, `Program::over` |
| Walk records with a borrowed cursor | `traverse` | `traverse-*` | `Cursor::over` |
| Build a read-only tree with byte geometry (hex views) | `inspect` | `inspect-*` | `Tree::parse` |
| Standing index over `&[u8]` with zero allocator traffic | `fixed_inspect` | `fixed-inspect-*` | `Tree::parse`, `Plan::new` |
| Build a movable, cacheable tree from an owned buffer | `retain` | `retain-*` | `Retained::parse` |
| Route records from a chunked stream by path programs | `route` | `route-*` | `Router::new`, `Program::over` |
| Validate / extract from a stream, chunk by chunk | `scan` | `scan-*` | `Validator::new`, `Parser::new` |
| Build a movable, cacheable tree from a chunked stream | `collect` | `collect-*` | `Collector::new` → `feed` → `finish` |
| Build a standing index over a stable-replay source | `survey` | `survey-*` | `Survey::open`, `fetch_payloads` |
| Batch-rewrite records by path rules | `rewrite` | `rewrite-*` | `rewrite()`, `RuleSet::over` |
| Equal-width edits landed in your own buffer | `inplace` | `inplace-*` | `apply()`, `RuleSet::over` |
| Equal-width edits in your buffer with zero allocator traffic | `fixed_inplace` | `fixed-inplace-*` | `apply()`, `Plan::new` |
| Convert between the wire dialects | `convert` | `convert-*` | `Converter::new` |
| Splice records online, any-length edits | `splice` | `splice-*` | `splice()`, `Rule` |
| One-shot edit over `&[u8]`, zero-copy fidelity | `patch` | `patch-*` | `Patch::open` |
| One-shot edit over `&[u8]` with zero allocator traffic | `fixed_patch` | `fixed-patch-*` | `Patch::open`, `Plan::new` |
| Editing with undo over a borrowed slice, zero-copy open | `markup` | `markup-*` | `Markup::open` |
| One-shot edit owning its buffer, movable mid-edit | `adopt` | `adopt-*` | `Adopt::open` |
| Editing with undo over padded wire, byte-exact fidelity | `draft` | `draft-*` | `Draft::open` |
| One-shot edit under canonical admission over `&[u8]` | `amend` | `amend-*` | `Amend::open` |
| Editing with undo over a borrowed slice, canonical admission | `review` | `review-*` | `Review::open` |
| One-shot edit under canonical admission, owning its buffer | `intake` | `intake-*` | `Intake::open` |
| Full editing session with undo | `session` | `session-*` | `Session::open`, `DocBytes::load` |
| A session that knows its exact save price in O(1) | `session` | `priced-session-*` | `Session::into_priced` |
| Rewire a chunked stream by path-bound actions | `rewire` | `rewire-*` | `Rewirer::new`, `Actions::over` |
| Transcode between acceptance standards | `transcode` | `transcode-*` | `Transcoder::new` |
| One-shot edits over a document that arrives in chunks | `stream_adopt` | `stream-adopt-*` | `Ingest::new` → `feed` → `finish` |
| Editing with undo over a document that arrives in chunks | `stream_draft` | `stream-draft-*` | `Ingest::new` → `feed` → `finish` |
| One-shot edit under canonical admission over a document that arrives in chunks | `stream_intake` | `stream-intake-*` | `Ingest::new` → `feed` → `finish` |
| Batch-rewrite records over a stable-replay source | `replay_rewrite` | `replay-rewrite-*` | `rewrite()`, `RuleSet::over` |
| Convert between the wire dialects over a stable-replay source | `replay_convert` | `replay-convert-*` | `convert()`, `Program::over` |
| Splice records over a stable-replay source, any-length edits | `replay_splice` | `replay-splice-*` | `splice()`, `Rule` |
| One-shot edit over a stable-replay source, byte-exact fidelity | `overhaul` | `overhaul-*` | `Overhaul::open` |
| Editing with undo over a stable-replay source | `maintain` | `maintain-*` | `Maintain::open` |
| One-shot edit under canonical admission over a stable-replay source | `refit` | `refit-*` | `Refit::open` |
| Editing with undo under canonical admission over a stable-replay source | `commission` | `commission-*` | `Commission::open` |
| Build a message from typed values | `construct` | `construct-*` | `Builder::new` |
| Relocate records and import across documents | the `Transfer…` sibling of any editor above | `transfer-<module>-*` | `TransferPatch::open`, `TransferSession::open_copy`, … |
| A transfer session that knows its exact save price in O(1) | `session` | `priced-transfer-session-*` | `TransferSession::into_priced` |
| Transplant records within or across documents | every offline editor's `Transfer…` sibling + `construct` | `transfer-<module>-*` | `record_ref` → `copy_record` / `move_record` / `copy_record_from` / `push_record` |

### Choosing a machine

The table answers by task. When several rows fit, the axes decide,
in the order a job usually fixes them:

- **Reading, whole buffer in hand.** An ad-hoc walk is `traverse`;
  standing queries over byte geometry are `inspect` (borrowing your
  buffer) or `retain` (owning its own — movable, cacheable,
  `Send + Sync`); path-designated extraction is `select`.
- **Reading a stream.** Whole-stream verdicts chunk by chunk are
  `scan`; path-designated delivery out of the stream is `route`;
  standing byte-geometry queries over a document that arrives in
  chunks are `collect` — each feed parses as it copies into the
  owned source, and `finish` seals the same movable, `Send + Sync`
  index `retain` builds from a buffer, with no reparse at the seal
  (the saving over collect-then-parse is exactly the
  post-collection read of the parsed bytes: near the whole input
  for parse-dense documents whose LEN interiors are selected,
  small for opaque-heavy ones).
- **Editing a buffer, one shot.** Three machines, split by who
  decides and when:
  - `patch`/`adopt`/`amend`/`intake` — *you address records by
    handle* after a full parse: descend, read, then edit exactly
    what you touched. `patch` borrows the buffer; `adopt` owns it
    (movable mid-edit, returnable, cacheable — the same commands,
    the same saves); `amend` and `intake` are their twins under
    canonical-minimal admission (padded wire refuses at the door,
    and saves re-ingest canonically) — `amend` borrowing, `intake`
    owning.
  - `rewrite` — *compiled rules decide*: the plan admits once and
    applies to any number of documents; two passes buy an exactly
    reserved output and gap insertion (`HeadOf`/`TailOf`).
  - `splice` — *your code decides per record*, payload in hand: one
    pass, any-length edits, every cascade settled on the way out.
    On a single document it clears the same job in one pass against
    the rewriter's two — static designation buys rule reuse and a
    declarative vocabulary, not per-record speed.
  - `inplace` — *compiled rules decide, and your buffer is the
    product*: equal-width edits (value/payload replacement,
    renumbering, whole-record substitution, tombstoning) land
    directly in the caller's own allocation — one judge walk, an
    infallible allocation-free write loop, zero output allocation,
    untouched bytes never rewritten. Width-moving edits (insert,
    delete, grow, shrink) stay with the three machines above.
- **Editing across turns.** Four revisable facades, split by
  acceptance and tenure: `session` — canonical, owned, precise
  undo, width erasure; `draft` — tolerant, owned, the same
  commands and undo with `patch`'s byte fidelity (padding rides
  saves verbatim, and `revert_all` restores the padded source
  exactly); `markup` — `draft`'s faces over a slice the caller
  keeps, zero copies at open; `review` — the same borrowed door
  under canonical admission, `session`'s commands and undo. Each
  facade also ships a borrowed-payload sibling (`BorrowSession`,
  `BorrowDraft`, `BorrowMarkup`, `BorrowReview`): installs retain
  the caller's slices as immutable slots instead of staging
  copies, with the payload lifetime on the type. And each ships a
  mixed-backing sibling (`MixSession`, `MixDraft`, `MixMarkup`,
  `MixReview`) whose faces select the backing per install —
  unsuffixed faces retain borrowed slices, `_copy` twins and the
  staged frames copy transients in — so long-lived templates and
  dying temporaries interleave on one undo log.
- **Editing a stream.** `rewire` applies path-bound zero-cascade
  actions with zero content buffering; `transcode` asks your rule
  per record under locked lengths. Neither buffers; neither can
  change a committed container's length — that job is buffered by
  nature (`splice`, `patch`, `draft`, `session`). A stream you
  intend to edit *offline* is ingested instead: `stream_adopt` and
  `stream_draft` parse each chunk as it arrives into the owned
  source and seal at `finish` into the matching buffered editor,
  and `stream_intake` is the tolerant pair's canonical twin — the
  same fed construction, with every framing word and varint value
  judged canonical-minimal as it arrives, sealing into `intake`'s
  machine — one fused pass, so the saving over collect-then-open
  is exactly the post-collection read of the framing bytes (near
  the whole input for parse-dense documents, small for
  opaque-heavy ones).
- **A source you can walk again, but not address.** When the input
  is sequential-repeatable — a file, a snapshot, an object-store
  blob, possibly larger than memory — implement
  `StableReplaySource` once per storage kind (the supply contract
  lives in `replay_source`, selectable directly as `replay-source`;
  the slice-backed reference source ships with it) and the replay
  cells run the buffered jobs in walks, retaining zero source
  bytes: `survey` builds the standing index in one walk (topology,
  `u64` span geometry, decoded scalar words resident in the rows,
  so scalar queries never re-read the source; payload bytes are
  answered by later walks, and `fetch_payloads` resolves k handles
  in one source-ordered walk); `replay_rewrite` runs compiled rule
  batches (pass 1 judges everything and compiles the edit script,
  pass 2 splices without parsing); `replay_convert` changes the
  wire dialect itself under the buffered converter's directional
  laws; `replay_splice` asks your code
  per record (answers staged by copy at the ask; LEN payloads met
  in two typed phases — head declaration, close verdict — instead
  of in hand); `overhaul` is the one-shot handle-addressed editor
  (commit-only saves, untouched extents ridden verbatim by the
  save walk), `maintain` its revisable twin (exact undo, every
  growth edge fallible), and `refit` and `commission` their
  canonical-admission siblings (padded spellings refused at the
  door or parked at the descent, saves already minimal). Working
  memory scales with record structure and
  edit size, never source length. A buffered cell wants the
  random-access slice instead; a stream cell wants one pass with
  no rewind.
- **Changing the dialect itself.** `convert` — the feature names
  the output dialect; everything else preserves the input's.
  Over a sequential-repeatable source, `replay_convert` is the
  same job in walks.
- **Starting from values, no input document.** `construct`.
- **No allocator, or caller-supplied working memory?** The
  fixed-scratch cells run their hosts' exact jobs with every
  working byte carved from one caller slab under a capacity
  contract: `fixed_patch` for handle-addressed one-shot edits
  (saves into your slice or sink), `fixed_inplace` for rule-driven
  equal-width edits landed in your own buffer, `fixed_inspect` for
  standing byte-geometry queries over `&[u8]` — allocator-free end
  to end, so all three run where no allocator exists at all. Within
  an adequate plan the outcome is byte-identical to the host twin;
  exhaustion is a deterministic refusal naming the lane, and the
  budget faces close the sizing loop (prototype with a generous
  plan, read the budget, ship the tight one).

### `no_std`

The library is `#![no_std]` unconditionally; nothing in it names
`std` (one test-only lock aside). Three tiers, selected purely by
features:

- **Allocator-free to build**: the substrate leaves (`wire-*`,
  `varint-*`, `scalar`), the borrowed cursor walk
  (`traverse-groupless`), and the stable-replay supply contract
  (`replay-source`) link with no global allocator at all — a
  bare-metal consumer selecting only these builds for targets like
  `x86_64-unknown-none`, and CI proves both directions every push
  (each billed cell must fail without `alloc`, each free surface
  must build).
- **Allocator-free to run**: `fixed_patch`, `fixed_inplace`, and
  `fixed_inspect` need `alloc` nowhere either — every working byte
  is carved from a caller slab under a capacity contract, so the
  cells run where allocation is forbidden rather than merely
  absent.
- **`alloc`, never `std`**: every other cell pulls `extern crate
  alloc` through its feature and uses the global allocator for
  rows and stores; no cell anywhere requires `std`.

Pick `default-features = false` and name the cells; the alloc
obligation follows automatically.

Fidelity is an axis too: the tolerant editors (`patch`, `markup`,
`adopt`, `draft`, `rewrite`, `splice`) re-emit untouched bytes exactly,
padding included — `inplace` never writes them at all, and
`overhaul` and the replay writers keep the same promise across
walks (untouched extents ride the splicing pass verbatim);
`session`, `amend`, `review`, and `intake` — and `refit` and
`commission` over a stable-replay source — admit
canonical input and re-derive framing; `transcode` is the
acceptance-changing machine.
If the output must re-ingest under `CanonicalMinimal`, the tolerant
buffered editors (`patch`, `adopt`, `draft`, `markup`) publish it
directly through their `save_canonical` family — every varint
construct in the materialized commitment closure re-emits minimally,
opaque LEN interiors ride as declared — while canonical-admission
input (`session`, `amend`, `review`, `intake`) already carries the
guarantee on its ordinary saves, and `transcode` remains the
streaming route.

Records relocate as designations. Every offline read or edit machine
mints one with `record_ref`: the exact source record bytes bound to
their proved framing. The relocation and import faces live on each
editing family's `Transfer…` sibling machines, behind that family's
monotone `transfer-<module>-*` feature — the base machines carry
none of the capability's state or dispatch. On the same machine,
`copy_record`, `move_record`, `copy_payload`, and `move_payload`
relocate by
coordinates — zero payload bytes staged, byte-exact fidelity, and on
the revisable siblings a move is one pending step whose one revert
restores both sides. Across machines, `copy_record_from` imports a
designation byte-exactly (tolerant hosts take `RecordRef` and keep
met framing; canonical hosts take `CanonicalRecordRef`, the proof
`try_canonical` mints — padded framing refuses at the proof, never
re-encoded), and `construct`'s `push_record` asserts one as a
canonical root record. Copies are output-authored: they answer no
source span and designate nothing onward. `rewire` and `transcode`
stay out by profile — they retain no stream content, and external
records inject there as plain byte slices.

### Dialect: grouped vs groupless

- **groupless** — for modern protobuf traffic (proto3, most proto2).
  Group codes (wire types 3 and 4) are refused with a capability
  fault. Choose this unless you know groups are present.
- **grouped** — the full six-code wire language. Required when
  reading legacy messages that use the `group` field type.

A groupless machine's group-code refusal is not an error in the
wire format — it is a capability boundary. If your input *might*
contain groups, route on the first group code: a groupless refusal
tells you to retry with the grouped twin.

### Cargo.toml

Enable exactly the features you need:

```toml
[dependencies]
protobuf_edit = { version = "0.0", features = ["scan-groupless"] }
```

Multiple features compose freely:

```toml
[dependencies]
protobuf_edit = { version = "0.0", features = [
    "session-grouped",
    "construct-groupless",
    "inspect-groupless",
] }
```

No feature implies another cell's feature. The stream-stepping
pump behind `scan`, `route`, `transcode`, and `rewire`, the
cursor engine behind `traverse`, `select`, `rewrite`, `inplace`,
`convert`, and `splice`, and the pull pump and script strata
behind the replay cells, are private internal strata — selecting a
cell compiles its own public faces and nothing of its stratum
siblings'. The only implications are in-family: a capability
feature (`transfer-*`, `priced-*`) enables the cell it extends. A
convert feature names its *output* dialect and reads the dialect
it converts away from.

## The scenario space

An unconditional stratum that every scenario consumes:

- `wire` — the contract vocabulary: `FieldNumber`, `PayloadLen`,
  `Low3`, and the two dialect tables (`wire::grouped`,
  `wire::groupless`) classifying tag codes.
- `varint` — format theorems (encoded lengths, canonical emission,
  zigzag) and the two reading kernels: bounded slice reads
  (`varint::slice`) and the chunk-boundary carry stepper
  (`varint::carry`).
- `scalar` — the typed scalar matrix: wire words and fixed bits to
  schema-typed values and back, with per-type domain judgments.
- `path` — the selection-path vocabulary: root-anchored `Segment`
  programs compiled once by `Program::over` (const-capable) and
  consumed by the static machines, plus the `Crossing` trail
  element their faults quote.

Scenario modules ride behind same-named features, one pair per
occupied point of the eight-axis scenario space (intent · presence ·
designation · dialect · acceptance · backing · revision · scratch;
axes whose domain is empty at a point are omitted from its
coordinates, and each module doc carries its full `Coordinates:`
line). Each pair
ships two independent concrete types — a `grouped` dialect (all six
wire codes; groups walk as in-band enter/exit) and a `groupless`
twin (four codes; group codes refused as a capability judgment):

| Module | Coordinates | Features | Role |
|---|---|---|---|
| `select` | read · buffered · static · tolerant/canonical (per entry type) · borrowed | `select-grouped`, `select-groupless` | The path-program selector: compiled paths deliver matching records from one buffered message. |
| `traverse` | read · buffered · online · tolerant/canonical (per entry type) · borrowed | `traverse-grouped`, `traverse-groupless` | The borrowed single-pass cursor — the dynamic-decode substrate. |
| `inspect` | read · buffered · offline · Standard · borrowed | `inspect-grouped`, `inspect-groupless` | The eager whole-tree inspector over one buffered message. |
| `fixed_inspect` | read · buffered · offline · Standard · borrowed · fixed scratch | `fixed-inspect-grouped`, `fixed-inspect-groupless` | The fixed-scratch inspector: the host's eager whole-tree queries with the row arena, frame stack, and path mirror carved from one caller-supplied slab — zero allocator traffic end to end, so the cells run where no allocator exists. The `Plan` declares rows alone (peak demand — evaporated speculative rows count) and derives both stacks; `Plan::bytes` prices the slab exactly at any address, row exhaustion refuses deterministically with no product published, and `budget()` closes the sizing loop. |
| `retain` | read · buffered · offline · Standard · owned | `retain-grouped`, `retain-groupless` | The self-contained owned inspector: the same whole-tree queries over a moved-in buffer, detachable and `Send + Sync`. |
| `route` | read · stream · static · Standard | `route-grouped`, `route-groupless` | The streaming path-program router: compiled paths deliver PathId-tagged events and borrowed tap segments from chunked bytes. |
| `scan` | read · stream · online · Standard | `scan-grouped`, `scan-groupless` | The one-pass chunked validator/extractor; verdicts independent of chunking. |
| `collect` | read · stream · offline · Standard · owned | `collect-grouped`, `collect-groupless` | The stream-collect owned inspector: `feed` parses each chunk as it copies it into the owned source (the retained copy is the finished index's own backing — the stream-presence exception), and the consuming `finish` — total, wire faults are product data — seals the standing queryable tree with no reparse. The one feed error is the pre-read coordinate refusal, returning every absorbed byte. |
| `survey` | read · sequential-repeatable · offline · Standard | `survey-grouped`, `survey-groupless` | The standing-index survey over a stable-replay source: one index walk builds the queryable row product — topology, `u64` span geometry, decoded scalar words (scalar queries stay infallible) — retaining zero source bytes; payload bytes are answered by later walks (`read_payload`, `payload_sink`, and `fetch_payloads`, which resolves k handles in one source-ordered walk). |
| `rewrite` | write · buffered · static · Standard · borrowed · commit-only | `rewrite-grouped`, `rewrite-groupless`; `transfer-rewrite-grouped`, `transfer-rewrite-groupless` | The rule-driven batch rewriter: borrowed input, compiled rules, two passes, new output. The `transfer-rewrite-*` cells add the source-transfer plan stratum (`TransferRuleSet`, `TransferRule`): compiled jobs that copy and move path-designated records and payloads; the plain plans carry none of it. |
| `inplace` | write · buffered · static · Standard · in-place · commit-only | `inplace-grouped`, `inplace-groupless` | The rule-driven same-allocation in-place editor: equal-width edits (value/payload replacement, renumbering, whole-record substitution, tombstoning) landed directly in the caller's own buffer — one judge walk, an infallible allocation-free write loop, zero output allocation. |
| `fixed_inplace` | write · buffered · static · Standard · in-place · commit-only · fixed scratch | `fixed-inplace-grouped`, `fixed-inplace-groupless` | The fixed-scratch in-place editor: the host's equal-width rule jobs with matcher tables, walk stacks, and the write list carved from one caller-supplied slab — zero allocator traffic end to end, so the cells run where no allocator exists. `Plan::bytes` prices the slab exactly, exhaustion is a deterministic refusal with the buffer byte-identical to entry, and `apply_budget` closes the sizing loop. |
| `convert` | write · buffered · static · crossing · Standard · borrowed · commit-only | `convert-grouped`, `convert-groupless` | The dialect-crossing converter: the feature names the OUTPUT dialect — `convert-groupless` re-frames every group in grouped input as a LEN record, `convert-grouped` re-frames Program-designated LEN records in groupless input as groups. |
| `splice` | write · buffered · online · Standard · borrowed · commit-only | `splice-grouped`, `splice-groupless`; `transfer-splice-grouped`, `transfer-splice-groupless` | The rule-driven online splicer: one ask per record, variable-length edits, every length cascade settled in one pass. The `transfer-splice-*` cells add the source-aware rule overlay (`SourceRule`, `splice_sources`): verdicts that relocate the current record or payload; the plain rules carry none of it. |
| `patch` | write · buffered · offline · tolerant · borrowed · commit-only | `patch-grouped`, `patch-groupless`; `transfer-patch-grouped`, `transfer-patch-groupless` | The borrowed one-shot patch: commit-only edits over `&[u8]`, byte-exact fidelity for everything untouched; the `save_canonical` family publishes the same records under `CanonicalMinimal`. The mixed `Patch` carries all three payload supplies; `BorrowPatch` and `CopyPatch` pin one each. The `transfer-patch-*` cells add the `TransferPatch` sibling: whole-record relocation and external import; the base machines carry none of it. |
| `fixed_patch` | write · buffered · offline · tolerant · borrowed · commit-only · fixed scratch | `fixed-patch-grouped`, `fixed-patch-groupless` | The fixed-scratch one-shot patch: patch's commands, byte-exact fidelity, and canonical saves over working memory carved from one caller slab under a `Plan` capacity contract — no allocator anywhere, saves land in a caller slice (`save_into`) or sink, exhaustion is a deterministic refusal naming the lane, and `budget()` closes the sizing loop. The mixed `Patch` carries all three payload supplies; `BorrowPatch` and `CopyPatch` pin one each. |
| `markup` | write · buffered · offline · tolerant · borrowed · revisable | `markup-grouped`, `markup-groupless`; `transfer-markup-grouped`, `transfer-markup-groupless` | The borrowed revisable editor: draft's commands and undo over a slice the caller keeps — zero copies at open, and a refusal never touched the buffer; the `save_canonical` family publishes the same records under `CanonicalMinimal`. `Markup` copies payloads at the command; `BorrowMarkup` retains borrowed payload slices, one immutable slot per install; `MixMarkup` selects the backing per install (unsuffixed faces retain, `_copy` and frame faces copy). The `transfer-markup-*` cells add the `TransferMarkup` and `TransferBorrowMarkup` siblings: whole-record relocation and external import; the base machines carry none of it. |
| `adopt` | write · buffered · offline · tolerant · owned · commit-only | `adopt-grouped`, `adopt-groupless`; `transfer-adopt-grouped`, `transfer-adopt-groupless` | The ownership-transfer one-shot editor: patch's commands and saves over a moved-in buffer, transactional tenure at both doors; the `save_canonical` family publishes the same records under `CanonicalMinimal`. The mixed `Adopt` carries all three payload supplies; `BorrowAdopt` and `CopyAdopt` pin one each. The `transfer-adopt-*` cells add the `TransferAdopt` sibling: whole-record relocation and external import; the base machines carry none of it. |
| `draft` | write · buffered · offline · tolerant · owned · revisable | `draft-grouped`, `draft-groupless`; `transfer-draft-grouped`, `transfer-draft-groupless` | The tolerant revisable editor: session's commands and undo with patch's byte fidelity over a moved-in buffer — padding rides saves verbatim, and revert restores it exactly; the `save_canonical` family publishes the same records under `CanonicalMinimal`. `Draft` copies payloads at the command; `BorrowDraft` retains borrowed payload slices, one immutable slot per install; `MixDraft` selects the backing per install (unsuffixed faces retain, `_copy` and frame faces copy). The `transfer-draft-*` cells add the `TransferDraft` and `TransferBorrowDraft` siblings: whole-record relocation and external import; the base machines carry none of it. |
| `amend` | write · buffered · offline · canonical · borrowed · commit-only | `amend-grouped`, `amend-groupless`; `transfer-amend-grouped`, `transfer-amend-groupless` | The canonical-admission borrowed one-shot editor: patch's commands and saves with padded wire refused at the door — no width column exists, and saves re-ingest under `CanonicalMinimal`. The mixed `Amend` carries all three payload supplies; `BorrowAmend` and `CopyAmend` pin one each. The `transfer-amend-*` cells add the `TransferAmend` sibling: whole-record relocation and external import; the base machines carry none of it. |
| `review` | write · buffered · offline · canonical · borrowed · revisable | `review-grouped`, `review-groupless`; `transfer-review-grouped`, `transfer-review-groupless` | The canonical-admission borrowed revisable editor: session's commands and undo over a slice the caller keeps — padded wire refuses at the door, zero copies through it. `Review` copies payloads at the command; `BorrowReview` retains borrowed payload slices, one immutable slot per install; `MixReview` selects the backing per install (unsuffixed faces retain, `_copy` and frame faces copy). The `transfer-review-*` cells add the `TransferReview` and `TransferBorrowReview` siblings: whole-record relocation and external import; the base machines carry none of it. |
| `intake` | write · buffered · offline · canonical · owned · commit-only | `intake-grouped`, `intake-groupless`; `transfer-intake-grouped`, `transfer-intake-groupless` | The canonical-admission one-shot editor: adopt's commands, saves, and tenure with padded wire refused at the door — no width column exists, and saves re-ingest under `CanonicalMinimal`. The `transfer-intake-*` cells add the `TransferIntake` sibling: whole-record relocation and external import; the base machines carry none of it. |
| `session` | write · buffered · offline · canonical · owned · revisable | `session-grouped`, `session-groupless`; `priced-session-grouped`, `priced-session-groupless`; `transfer-session-grouped`, `transfer-session-groupless`; `priced-transfer-session-grouped`, `priced-transfer-session-groupless` | The handle-based editing session with precise undo and a two-pass save. `Session` copies payloads at the command; `BorrowSession` retains borrowed payload slices, one immutable slot per install; `MixSession` selects the backing per install (unsuffixed faces retain, `_copy` and frame faces copy). The priced cells add `PricedSession` (`Session::into_priced`), the typestate that settles the exact save price at every command: `save_len` answers in O(1) while every rewritten body sits in the length class, and over-cap accounting stays exact with the fault surfacing byte-identically at the save faces. The `transfer-session-*` cells add the `TransferSession` and `TransferBorrowSession` siblings — whole-record relocation and external import — and the `priced-transfer-session-*` cells add `PricedTransferSession` (`TransferSession::into_priced`) under the transfer profile's own ceiling theorem; the base machines carry none of it. |
| `rewire` | write · stream · static · Standard · commit-only | `rewire-grouped`, `rewire-groupless` | The streaming path-program rewirer: per-path actions bound at construction, zero buffering of stream content. |
| `transcode` | write · stream · online · Standard · commit-only | `transcode-grouped`, `transcode-groupless` | The streaming equal-length transcoder; zero buffering of stream content. |
| `stream_adopt` | write · stream · offline · tolerant · owned · commit-only | `stream-adopt-grouped`, `stream-adopt-groupless`; `transfer-stream-adopt-grouped`, `transfer-stream-adopt-groupless` | The stream-ingest one-shot editor: `feed` parses each chunk as it copies it into the owned source (the retained copy is the offline product — the stream-presence exception), and `finish` seals adopt's machine with no reparse; the saving over collect-then-open is the post-collection read of the framing bytes, small for opaque-heavy documents. Failures return the accumulated source with exact whole-chunk custody. The `transfer-stream-adopt-*` cells add the `TransferAdopt` sealed sibling behind `Ingest::finish_transfer`; the base seal carries none of it. |
| `stream_draft` | write · stream · offline · tolerant · owned · revisable | `stream-draft-grouped`, `stream-draft-groupless`; `transfer-stream-draft-grouped`, `transfer-stream-draft-groupless` | The stream-ingest revisable editor: the same fed construction sealed into draft's machine — undo, byte fidelity, and every growth edge fallible with the site named; the saving over collect-then-open is the post-collection read of the framing bytes, small for opaque-heavy documents. The `transfer-stream-draft-*` cells add the `TransferDraft` and `TransferBorrowDraft` sealed siblings behind `Ingest::finish_transfer`; the base seal carries none of it. |
| `stream_intake` | write · stream · offline · canonical · owned · commit-only | `stream-intake-grouped`, `stream-intake-groupless`; `transfer-stream-intake-grouped`, `transfer-stream-intake-groupless` | The stream-ingest canonical one-shot editor: `feed` judges every framing word and varint value canonical-minimal the moment its last byte arrives — across chunk edges through the carry — as it copies each chunk into the owned source (the retained copy is the offline product — the stream-presence exception), and `finish` seals intake's machine with no reparse; the saving over collect-then-open is the post-collection read of the framing bytes, small for opaque-heavy documents. Failures return the accumulated source with exact whole-chunk custody. The `transfer-stream-intake-*` cells add the `TransferIntake` sealed sibling behind `Ingest::finish_transfer`; the base seal carries none of it. |
| `replay_rewrite` | write · sequential-repeatable · static · Standard · commit-only | `replay-rewrite-grouped`, `replay-rewrite-groupless` | The rule-driven batch rewriter over a stable-replay source: pass 1 owns every judgment and compiles a source-anchored edit script, pass 2 is a splicing pump that parses nothing — working memory scales with record structure and edit size, never source length. |
| `replay_convert` | write · sequential-repeatable · static · crossing · Standard · commit-only | `replay-convert-grouped`, `replay-convert-groupless` | The dialect-crossing converter over a stable-replay source: the feature names the OUTPUT dialect — `replay-convert-groupless` walks the grouped language and re-frames every group as a LEN record, `replay-convert-grouped` walks the groupless language and re-frames Program-designated LEN records as groups (routed-but-untargeted LENs commit and re-settle exactly as rewrite's crossings; unrouted ones ride opaque). |
| `replay_splice` | write · sequential-repeatable · online · Standard · commit-only | `replay-splice-grouped`, `replay-splice-groupless` | The rule-driven splicer over a stable-replay source: one ask per record with answers staged by copy, LEN payloads met in two typed phases (head declaration, close verdict) instead of in hand, and a splicing walk from which the rule is absent. |
| `overhaul` | write · sequential-repeatable · offline · tolerant · commit-only | `overhaul-grouped`, `overhaul-groupless` | The one-shot editor over a stable-replay source: an index walk opens the top layer, `descend`/`materialize` commit LEN interiors on demand, commands touch no source byte, and one splicing save walk rides untouched extents verbatim, byte for byte — saves land in a fresh or appended buffer (restored on refusal) or a caller sink (the handed prefix reported). Three payload-backing forms (`Overhaul` mixed, `BorrowOverhaul`, `CopyOverhaul`). |
| `maintain` | write · sequential-repeatable · offline · tolerant · revisable | `maintain-grouped`, `maintain-groupless` | The revisable editor over a stable-replay source: the markup twin's commands, revision log, and byte-fidelity saves rebuilt over walks — banked words and stored met widths make revert walk-free, authored payloads descend and fetch resident, `materialize` settles a batch in zero or one source-ordered walk, and every growth edge is fallible. Three payload-backing forms (`Maintain`, `BorrowMaintain`, `MixMaintain`) plus the tolerant pole's `save_canonical` family. |
| `refit` | write · sequential-repeatable · offline · canonical · commit-only | `refit-grouped`, `refit-groupless` | The canonical one-shot editor over a stable-replay source: the amend twin's commands and splicing saves rebuilt over walks — a padded tag, length prefix, varint value, or group end tag refuses whole at the door or parks as a resident verdict at the descent that meets it (the shared opaque `NonMinimal` carrier names site and met width), the rows store no framing widths, and untouched extents riding verbatim are already minimal, so every save closes under `CanonicalMinimal`. Three payload-backing forms (`Refit` mixed with scatter parts and staged frames, `BorrowRefit`, `CopyRefit`). |
| `commission` | write · sequential-repeatable · offline · canonical · revisable | `commission-grouped`, `commission-groupless` | The canonical revisable editor over a stable-replay source: the review twin's commands, revision log, and two-pass saves rebuilt over walks — the same canonical door and parked refusals as `refit`, banked words make revert walk-free with no met column to consult, every growth edge is fallible with per-edge booking, and saves guarantee `CanonicalMinimal` outright (no separate canonical family exists). Three payload-backing forms (`Commission` copy-only, `BorrowCommission`, `MixCommission`). |
| `construct` | author (outside the input axes) | `construct-grouped`, `construct-groupless` | The value-side builder: typed values in, message bytes out, exactly-reserved output. The mixed `Builder` borrows payloads by default with `_copy` twins; `CopyBuilder` copies every payload at the push, no lifetime parameter. |

Nothing moves shape under any feature combination: features only add
modules.

## Quick start

Walking a message with the borrowed cursor (feature
`traverse-groupless`):

```rust
use protobuf_edit::traverse::groupless::{Cursor, EntryKind, FaultKind};

// Field 1, varint 150; field 2, LEN "abc".
let msg = [0x08, 0x96, 0x01, 0x12, 0x03, b'a', b'b', b'c'];
let entries = Cursor::over(&msg).unwrap().collect::<Result<Vec<_>, _>>().unwrap();
assert_eq!(entries.len(), 2);
assert_eq!(entries[0].kind(), EntryKind::Varint(150));
assert_eq!(entries[1].kind(), EntryKind::Len(b"abc"));

// A group tag is well-formed wire outside this language.
let fault = Cursor::over(&[0x0B]).unwrap().next().unwrap().unwrap_err();
assert!(matches!(fault.kind(), FaultKind::GroupCode { .. }));
```

Editing under a session (feature `session-grouped`):

```rust
use protobuf_edit::session::DocBytes;
use protobuf_edit::session::grouped::Session;

// Seal a document, edit it in a session, save the result.
let doc = DocBytes::load(&[0x08, 0x96, 0x01]).unwrap();
let mut session = Session::open(doc).unwrap();
let record = session.top().next().unwrap();
session.set_varint(record, 7).unwrap();
assert_eq!(session.save().unwrap()[..], [0x08, 0x07]);
```

Building a message from typed values (feature `construct-groupless`):

```rust
use protobuf_edit::FieldNumber;
use protobuf_edit::construct::groupless::Builder;

let f1 = FieldNumber::new(1).unwrap();
let f2 = FieldNumber::new(2).unwrap();
let mut builder = Builder::new();
builder.push_varint(f1, 150);
builder.message(f2, |m| {
    m.push_string(f1, "hi");
});
assert!(builder.poisoned().is_none());

// Append into an existing buffer: one exact reservation.
let mut out = vec![0xAA];
builder.finish_into(&mut out).unwrap();
assert_eq!(out, [0xAA, 0x08, 0x96, 0x01, 0x12, 0x04, 0x0A, 0x02, 0x68, 0x69]);
```

Editing with zero allocator traffic — the fixed-scratch patch is
the borrowed one-shot patch with its working memory carved from
one caller slab under a capacity contract, and its saves land in
caller memory too (feature `fixed-patch-groupless`):

```rust
use core::mem::MaybeUninit;
use protobuf_edit::DepthLimit;
use protobuf_edit::fixed_patch::groupless::{Patch, Plan};

// varint f1=150 (value padded to two bytes) · LEN f2 "hi"
let msg = [0x08, 0x96, 0x81, 0x00, 0x12, 0x02, 0x68, 0x69];
let plan = Plan::new(4, 2, 2, 16, 2).unwrap();
let mut slab = [MaybeUninit::<u8>::uninit(); 512];
let mut patch = Patch::open(&msg, DepthLimit::REFERENCE, &plan, &mut slab).unwrap();

let second = patch.top().nth(1).unwrap();
patch.set_payload(second, b"no").unwrap();

// The padded varint rode verbatim; the same-length payload kept
// its prefix. The output is the caller's own buffer.
let mut out = [0u8; 8];
let written = patch.save_into(&mut out).unwrap();
assert_eq!(&out[..written as usize], [0x08, 0x96, 0x81, 0x00, 0x12, 0x02, 0x6E, 0x6F]);
```

…and the fixed-scratch in-place editor reuses one compiled rule
set, one plan, and one sized slab across a fleet of buffers — the
working set never grows, so one slab serves every job (feature
`fixed-inplace-groupless`):

```rust
use core::mem::MaybeUninit;
use protobuf_edit::fixed_inplace::groupless::{Plan, apply};
use protobuf_edit::inplace::{Action, Rule, RuleSet};
use protobuf_edit::path::Segment;
use protobuf_edit::{DepthLimit, FieldNumber};

let f1 = FieldNumber::new(1).unwrap();
let rules = [Rule { path: &[Segment::Field(f1)], action: Action::SetVarint(0) }];
let set = RuleSet::over(&rules).unwrap();
let plan = Plan::new(1).unwrap();
let mut slab = [MaybeUninit::<u8>::uninit(); 256];
assert!(plan.bytes(&set, DepthLimit::REFERENCE) <= slab.len());

let mut fleet = [[0x08, 0x05], [0x08, 0x7F]];
for buf in &mut fleet {
    apply(buf, &set, DepthLimit::REFERENCE, &plan, &mut slab).unwrap();
}
assert_eq!(fleet, [[0x08, 0x00], [0x08, 0x00]]);
```

Transplanting a record across documents (features
`transfer-draft-groupless` + `transfer-session-groupless`; the
import hosts are the `Transfer…` siblings, while any offline
machine — the base `Draft` here — designates with `record_ref`):

```rust
use protobuf_edit::session::groupless::transfer::{InsertAt, TransferSession};
use protobuf_edit::draft::groupless::transfer::{InsertAt as DraftAt, TransferDraft};
use protobuf_edit::draft::groupless::Draft;

// Designate a record in one document, import it into another —
// byte-exact, one command, one undo step.
let donor = Draft::open(vec![0x12, 0x82, 0x00, 0x68, 0x69]).unwrap();
let record = donor.record_ref(donor.top().next().unwrap()).unwrap();

// A tolerant host keeps the donor's padded prefix verbatim…
let mut draft = TransferDraft::open(vec![0x08, 0x01]).unwrap();
draft.copy_record_from(record, DraftAt::TailOf(None)).unwrap();
assert_eq!(draft.save().unwrap(), [0x08, 0x01, 0x12, 0x82, 0x00, 0x68, 0x69]);

// …while a canonical host demands the proof, and padding refuses
// at the proof instead of re-encoding.
let mut session = TransferSession::open_copy(&[0x08, 0x01]).unwrap();
assert!(record.try_canonical().is_err());
let minimal = Draft::open(vec![0x12, 0x02, 0x68, 0x69]).unwrap();
let proven = minimal.record_ref(minimal.top().next().unwrap()).unwrap();
session.copy_record_from(proven.try_canonical().unwrap(), InsertAt::TailOf(None)).unwrap();
assert_eq!(session.save().unwrap()[..], [0x08, 0x01, 0x12, 0x02, 0x68, 0x69]);
```

Moving a record inside one document (feature
`transfer-session-groupless`):

```rust
use protobuf_edit::session::groupless::transfer::{EditStatus, InsertAt, TransferSession};

let mut session = TransferSession::open_copy(&[0x08, 0x05, 0x10, 0x06]).unwrap();
let tops: Vec<_> = session.top().collect();
session.move_record(tops[0], InsertAt::After(tops[1])).unwrap();
assert_eq!(session.save().unwrap()[..], [0x10, 0x06, 0x08, 0x05]);
assert_eq!(session.status(tops[0]).unwrap(), EditStatus::Moved);

// One pending step: one revert restores the exact source reading.
assert_eq!(session.pending(), 1);
session.revert();
assert_eq!(session.save().unwrap()[..], [0x08, 0x05, 0x10, 0x06]);
```

On borrowed-source + borrowed-payload machines whose lifetimes
satisfy `'source: 'p` (`BorrowMarkup`, `BorrowReview`, their mixed
siblings `MixMarkup` and `MixReview`, and the borrowed faces of the
mixed one-shots), payload composition also works without any
transfer face: take the payload span from `source_spans`, slice
`source()`, and hand that external borrow back to `insert_payload`
— the machine retains the caller's own bytes.
The transfer faces — on the `Transfer…` sibling machines, behind
each family's `transfer-<module>-*` feature — exist because that
recipe cannot serve owned sources (self-borrow) or copy-only
stores (double staging); `copy_payload` covers every backing
uniformly, coordinates only.

Each block above is equivalent to a doctest that runs in this
repository's test suite.

## Performance

Per-line medians over five runs of `cargo bench` (`benches/core.rs`,
a dependency-free harness reporting the median of 25 timed batches
per line) on one x86-64 machine. Absolute numbers vary by host and
build; the relative shape is the claim. The 100k input is field-dense
(~16 B/record: varints, I32s, small LEN payloads, occasional nested
messages); the chunky input is a few large fields.

| Benchmark | This run |
|---|---|
| `traverse_walk_100k` | 85.4 µs · 1.13 GiB/s |
| `inspect_parse_100k` | 174 µs · 570 MiB/s |
| `scan_validate_100k` | 88.1 µs · 1.10 GiB/s |
| `scan_validate_chunked_100k` | 88.9 µs · 1.09 GiB/s |
| `scan_validate_groupless_100k` | 77.0 µs · 1.26 GiB/s |
| `scan_skip_all_100k` | 88.7 µs · 1.09 GiB/s |
| `patch_open_100k` | 85.1 µs · 1.14 GiB/s |
| `patch_edit_save_100k` | 11.1 µs · 8.68 GiB/s |
| `patch_edit_save_descended_100k` | 11.2 µs · 8.68 GiB/s |
| `patch_save_clean_100k` | 1.84 µs · 52.6 GiB/s |
| `patch_save_sink_100k` | 20.5 µs · 4.72 GiB/s (chunked sink delivery) |
| `patch_set_payload_borrowed_1m` | 24.5 µs · 39.9 GiB/s (1 MiB payload, single copy at save) |
| `patch_set_payload_copy_1m` | 58.8 µs · 16.6 GiB/s (the staging twin: two copies) |
| `session_save_one_edit_100k` | 26.4 µs · 3.67 GiB/s |
| `session_save_one_edit_chunky` | 52.2 GiB/s |
| `session_save_into_100k` | 27.2 µs · 3.56 GiB/s (caller-buffer save) |
| `priced_save_one_edit_100k` | 14.2 µs · 6.80 GiB/s (native ledger emit) |
| `session_set_payload_gated` | 30.0 ns/op (1024-entry undo log, depth 16) |
| `session_narrowest` | 20.0 ns/query (hex-view reverse index, 378 nested layers materialized) |
| `construct_small_nested_reuse` | 101.4 ns/message (5 records, reused buffer) |
| `construct_payload_borrowed_1m` | 23.2 µs · 42.2 GiB/s (1 MiB payload, single copy at finish) |
| `construct_payload_copy_1m` | 60.5 µs · 16.2 GiB/s (the staging twin: two copies) |
| `construct_payload_frames_1m` | 28.7 µs · 34.0 GiB/s (framed payload assembly) |
| `select_two_paths_100k` | 181 µs · 548 MiB/s (30.5 ns/record, one pass) |
| `rewrite_two_rules_100k` | 65.8 ns/record |
| `convert_groups_100k` | 94.4 µs · 1.03 GiB/s (groups → LEN, online settlement) |
| `replay_convert_groups_100k` | 197 µs · 503 MiB/s (the same job over a seeking walk) |
| `replay_convert_designations_100k` | 242 µs · 399 MiB/s (LEN → groups over a walk) |
| `overhaul_edit_save_100k` | 34.6 µs · 2.79 GiB/s (one edit, zero resident source bytes) |
| `maintain_grouped_edit_save_100k` | 88.1 µs · 1.10 GiB/s (revisable replay editor) |
| `maintain_groupless_edit_save_100k` | 74.0 µs · 1.31 GiB/s |
| `refit_grouped_edit_save_100k` | 80.2 µs · 1.21 GiB/s (canonical one-shot) |
| `refit_groupless_edit_save_100k` | 77.6 µs · 1.25 GiB/s |
| `commission_grouped_edit_save_100k` | 101 µs · 985 MiB/s (canonical revisable) |
| `commission_groupless_edit_save_100k` | 98.7 µs · 1004 MiB/s |
| `transcode_identity_100k` | 26.0 ns/record (31.9 under `CanonicalMinimal`) |

Wall-clock measurement on this crate is sensitive to code layout:
swings of about ±10% across otherwise-equal builds are normal, so
treat these as one machine's signposts. Comparative claims are settled with
fixed-workload instruction counts (callgrind), not wall clock, and
per-record denominators are printed by the harness itself rather
than hand-derived.

## Verification

- 2518 unit and integration tests plus 1767 doctests run green under
  `cargo test --all-features` (CI recounts the ran totals against
  this sentence, so these numbers cannot drift silently). Two
  suites additionally need local artifacts: the corpus oracle reads
  frozen libprotoc 35.1 observations from untracked reference
  vectors, and the live oracle asks a `protoc` on PATH to judge
  emitted bytes plus the two scalar questions it carries (the
  sint32 reduction order and the sint encodings), and to judge the
  padded-corpus value readings against `--decode_raw`; the rest of
  the scalar matrix is pinned offline under an explicitly strict
  domain policy (plain widths refuse out-of-domain words; sint32's
  recorded reduction order is the one carved-out fold). CI runs
  everything else and reconstructs the live oracle's schema from
  the tests' own pins.
- 573 allocator-discipline probes: the fault-injection sweeps drive
  every fallible growth face through injected allocator refusal,
  natively and under Miri, asserting each mutating command is
  atomic (the priced session's sweeps extend the judged fingerprint
  by `save_len()`, so a half-settled price ledger cannot hide
  behind an untouched tree) — and asserting the probe actually
  injected at least one fault, so a probe cannot pass by never
  exercising anything — and the counting probes beside them hold
  the no-allocation claims (sized writes behind a door's
  reservation, streaming rewirers fed content-heavy streams,
  identity splices, clean priced admissions, settled `save_len`
  answers, and priced reverts) to their exact allocator traffic.
- Miri under `-Zmiri-strict-provenance` covers the library tests
  (the fixed cells' in-module carve, lane, and matcher rows ride
  there) and the allocator-fault, differential, panic-location,
  panic-safety, re-emission, padded-twin, and patch-oracle suites,
  plus the fixed suites' named carve-boundary, exhaustion, store,
  and walk-bound rows (the corpus oracle joins on machines that
  carry the corpus) — the fixed cells' slab carve and arena
  invariants sit under exactly this judge. The fixed suites'
  differential and twin-identity rows run native in the battery:
  the groupless twin identity alone exceeds any practical
  interpreter budget.
- The 32-bit claim is machine-held: the crate checks under
  `wasm32-unknown-unknown` (CI gate; the 64-bit layouts stay
  pinned exactly, and the fixed cells pin exact sizes and
  alignments at both pointer widths with their carve ladders
  compile-time-asserted per width, so the check build evaluates
  what their tests would only execute), and the library tests plus every target-applicable
  integration suite (differential, padded-twins, parity,
  re-emission, auto-traits, allocator-fault, patch-oracle — all
  suites except the named exclusions) run green under
  `wasm32-wasip1`. The absentees each carry their
  reason: `should_panic` contracts and the two `catch_unwind`
  suites cannot run under panic = abort, the live oracle has no
  host `protoc`, and the corpus oracle and coordinates census are
  host-side artifact audits; all stay covered by the 64-bit
  battery.
- A 109-cell `cargo check` matrix — each of the 108 single-feature cells
  plus the no-feature cell — compiles warning-free, so every
  feature gate is a real consumption set.
- The no-allocator claim is machine-held end to end: a
  `#![no_std]` `#![no_main]` consumer with only the fixed-scratch
  cells enabled and no `#[global_allocator]` builds for a
  bare-metal target (`x86_64-unknown-none`) and runs one real job
  per fixed family — the allocator link obligation is billed by
  crate-graph membership, so the build succeeds exactly when no
  alloc obligation survives in the enabled graph. The judge
  carries its own red control (the same probe plus one heap cell
  must fail naming the allocator obligation) and runs in CI and
  locally (`probes/no_alloc_consumer/judge.sh`).
- A rustdoc matrix (every single-feature cell, the no-feature cell,
  and `--all-features`) builds under `RUSTDOCFLAGS="-D warnings"`.
- The panic surface is audited at the assembly level: release
  symbols show bounds checks and documented contract assertions
  only, with no literal `panic!`/`unreachable!` paths, and
  caller-contract panics report the caller's location via
  `#[track_caller]`.

## Design

- **Strict parsing buys zero-cost dispatch.** Admission and
  classification happen once, at a constructor with a name
  (`Admitted::new`, `DocBytes::load`, `Cursor::over`,
  `RuleSet::over`); past that boundary, coordinates are `u32` by
  proof and hot paths carry no re-checks. Committed wire violations
  are structured faults with positions, not best-effort recovery.
- **Contract types carry the proof.** The range-typed vocabulary
  (`FieldNumber`, `PayloadLen`, `DepthLimit`, `Span`) is validated
  at construction and judgment-free downstream. Handles mint from
  the structure that owns them; a forged handle panics by name
  instead of reading the wrong row.
- **Transactional mutation.** A refused command leaves no observable
  trace: session edits land whole or not at all, a refused
  `construct` finish leaves the caller's buffer untouched, a faulted
  rewrite job leaves its reuse buffer untouched, and a faulted
  transcode job's emitted prefix carries no promise — re-running is
  undo.
- **Explicit configuration, no probing.** Depth bounds
  (`DepthLimit`), acceptance standards (`Standard::Tolerant` vs
  `CanonicalMinimal`), and schema knowledge (inspect's `Advisor`,
  scan's per-LEN dispositions, rewrite's wildcard descend sets)
  are caller-declared. Where the answer has consequences, the
  library never guesses whether a LEN payload is a message:
  speculative descent exists only where it is harmless and labeled
  (inspect), and committed descent faults for real.
- **Dialects are types, not flags.** The grouped and groupless
  machines are independent concrete types sharing no dialect
  vocabulary; group support is decided at the type level, not
  checked per record on the hot path.
- **Declared allocation policy.** One rule partitions the crate: a
  machine owes fallible allocation only while it carries revisable
  interactive state across turns — holdings whose loss cannot be
  confined to the job in flight. That is the revisable editor
  family, all twenty-six machines: `Session`, `BorrowSession`, and
  `MixSession`; `Draft`, `BorrowDraft`, and `MixDraft`; `Markup`,
  `BorrowMarkup`, and `MixMarkup`; `Review`, `BorrowReview`, and
  `MixReview`; `Maintain`, `BorrowMaintain`, and `MixMaintain`;
  `Commission`, `BorrowCommission`, and `MixCommission`; and
  their transfer siblings `TransferSession` and
  `TransferBorrowSession`, `TransferDraft` and
  `TransferBorrowDraft`, `TransferMarkup` and
  `TransferBorrowMarkup`, `TransferReview` and
  `TransferBorrowReview` — plus the priced typestates
  `PricedSession` and `PricedTransferSession`
  over the session pair, whose ledgers reserve fallibly, and
  exactly, before each price-moving commit — their growth edges
  are fallible (`try_reserve`-class, refusals surface as
  structured faults). Every other machine's holdings end with the
  job, so the whole read side and the write-side one-shot jobs
  (`construct`, `rewrite`, and the `patch` family's one-shot
  cells) grow working memory under the global allocator's
  panic/abort discipline — each module doc states its side. The
  allocator-fault probes pin the fallible faces.
- **Byte fidelity.** Under tolerant acceptance, untouched records
  ride verbatim — padded (non-minimal) varints included — through
  rewrites, the identity transcode, and every `patch` save (where
  additionally a touched record's source tag and an
  unchanged-length LEN prefix ride verbatim). Session saves are
  byte-exact over the session's admission domain, and that domain
  is canonical-minimal: padded wire is refused at open, so it never
  rides a save. Canonical minimal emission is a duty exactly where
  the library authors bytes itself.

## Features and `no_std`

Feature naming and selection are covered in [Pick your
features](#pick-your-features) above. The default feature set is
empty; the unconditional strata (`wire`, `varint`, `scalar`, `path`,
and the root vocabulary) are always present regardless of features.
Features are strictly additive: no public type's shape moves with
any combination.

The crate is `#![no_std]`, and `extern crate alloc` rides the heap
cells' features: a build selecting only fixed-scratch cells or bare
substrate leaves compiles with no allocator in its crate graph (the
no-alloc consumer judge under Verification holds that mechanically).
It requires nightly Rust (`allow_internal_unsafe`,
`allow_internal_unstable`, `likely_unlikely`) and supports 32- and
64-bit targets only, enforced with a `compile_error!`.

## License

Apache-2.0. See `LICENSE`.
