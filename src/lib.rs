#![no_std]
#![feature(allow_internal_unsafe)]
#![feature(allow_internal_unstable)]
// Branch-weight hints live in the reading kernels and the walking
// and rewriting leaves; the attribute follows those modules' own
// gates so a build compiling none of them declares no unused
// feature.
#![cfg_attr(
    any(
        test,
        feature = "varint-slice",
        feature = "select-grouped",
        feature = "select-groupless",
        feature = "traverse-grouped",
        feature = "traverse-groupless",
        feature = "route-grouped",
        feature = "route-groupless",
        feature = "scan-grouped",
        feature = "scan-groupless",
        feature = "rewrite-grouped",
        feature = "rewrite-groupless",
        feature = "inplace-grouped",
        feature = "inplace-groupless",
        feature = "fixed-inplace-grouped",
        feature = "fixed-inplace-groupless",
        feature = "convert-grouped",
        feature = "convert-groupless",
        feature = "splice-grouped",
        feature = "splice-groupless",
        feature = "rewire-grouped",
        feature = "rewire-groupless",
        feature = "transcode-grouped",
        feature = "transcode-groupless",
        feature = "inspect-grouped",
        feature = "inspect-groupless",
        feature = "fixed-inspect-grouped",
        feature = "fixed-inspect-groupless",
        feature = "retain-grouped",
        feature = "retain-groupless",
        feature = "collect-grouped",
        feature = "collect-groupless",
        feature = "patch-grouped",
        feature = "patch-groupless",
        feature = "fixed-patch-grouped",
        feature = "fixed-patch-groupless",
        feature = "adopt-grouped",
        feature = "adopt-groupless",
        feature = "amend-grouped",
        feature = "amend-groupless",
        feature = "intake-grouped",
        feature = "intake-groupless",
        feature = "markup-grouped",
        feature = "markup-groupless",
        feature = "draft-grouped",
        feature = "draft-groupless",
        feature = "review-grouped",
        feature = "review-groupless",
        feature = "session-grouped",
        feature = "session-groupless",
        feature = "stream-adopt-grouped",
        feature = "stream-adopt-groupless",
        feature = "stream-draft-grouped",
        feature = "stream-draft-groupless",
        feature = "stream-intake-grouped",
        feature = "stream-intake-groupless",
        feature = "construct-grouped",
        feature = "construct-groupless"
    ),
    feature(likely_unlikely)
)]
#![allow(internal_features)]

//! Low-level, schema-less protobuf inspection and editing.
//!
//! The substrate strata, consumed by every scenario. Their roots —
//! the contract vocabulary and the format theorems — are
//! unconditional; the five substrate leaves (the two dialect
//! tables, the two reading kernels, the scalar matrix) compile
//! exactly when a scenario cell that consumes them is enabled or
//! a direct-selection feature (`wire-grouped`, `wire-groupless`,
//! `varint-slice`, `varint-carry`, `scalar`) names them for
//! hand-rolled composition:
//!
//! - [`wire`] — the contract vocabulary: [`FieldNumber`],
//!   [`PayloadLen`], [`Low3`] (unconditional), and the two dialect
//!   tables (`wire::grouped`, `wire::groupless`) classifying tag
//!   codes, each behind its dialect's consuming cells or its
//!   direct feature.
//! - [`varint`] — format theorems (encoded lengths, canonical
//!   emission, zigzag; unconditional) and the two reading kernels:
//!   bounded slice reads (`varint::slice`, with the buffered
//!   cells) and the chunk-boundary carry stepper (`varint::carry`,
//!   with the stream-scanning cells). Both kernels are
//!   width-tolerant and forgery-strict; scenario-specific
//!   acceptance (canonical minimality, caller-declared standards)
//!   lives with the scenarios that conclude it.
//! - `scalar` — the typed scalar matrix: wire words and fixed bits
//!   to schema-typed values and back, with per-type domain
//!   judgments (behind `construct` or its direct feature).
//! - [`path`] — the selection-path vocabulary: root-anchored
//!   [`path::Segment`] programs compiled by [`path::Program::over`]
//!   (const-capable), consumed by the static machines, plus the
//!   [`path::Crossing`] trail element their faults quote
//!   (unconditional).
//!
//! Two strata are conditional. `source` — the source-designation
//! contract types (`RecordRef`, `CanonicalRecordRef`, `PayloadRef`
//! per dialect), minted by the offline read and edit machines'
//! `record_ref` faces and consumed by the transfer and import
//! faces — compiles exactly when a machine that mints or consumes
//! it is enabled. `replay_source` — the sequential-repeatable
//! supply contract (`StableReplaySource`, its walk vocabulary,
//! and the slice-backed reference source), implemented by callers
//! and consumed by the replay cells — compiles when a replay cell
//! is enabled or its direct-selection feature (`replay-source`)
//! names it for hand-rolled composition.
//!
//! Scenario modules ride behind same-named features, one module
//! per supported scenario. Each names its position along the
//! scenario axes — intent · presence · designation · dialect ·
//! acceptance · backing · revision · scratch — in its module doc's
//! `Coordinates:` line (axes that do not apply are omitted). Each
//! module ships a grouped dialect and a groupless twin as
//! independent concrete types, listed here in a fixed order:
//!
//! - `select` — the path-program selector: compiled paths deliver
//!   matching records from one buffered message (read · buffered ·
//!   static · tolerant · borrowed).
//! - `traverse` — the borrowed single-pass cursor, the
//!   dynamic-decode substrate (read · buffered · online ·
//!   tolerant · borrowed).
//! - `inspect` — the eager whole-tree inspector over one
//!   buffered message (read · buffered · offline · tolerant ·
//!   borrowed).
//! - `fixed_inspect` — the fixed-scratch inspector: inspect's
//!   eager whole-tree queries with the row arena and the parse's
//!   stacks carved from one caller slab, zero allocator traffic
//!   end to end (read · buffered · offline · Standard · borrowed ·
//!   fixed scratch).
//! - `retain` — the self-contained owned inspector: the same
//!   whole-tree queries over a moved-in buffer, detachable and
//!   `Send + Sync` (read · buffered · offline · owned).
//! - `route` — the streaming path-program router: compiled paths
//!   deliver PathId-tagged events and borrowed tap segments from
//!   chunked bytes (read · stream · static · Standard).
//! - `scan` — the one-pass chunked validator/extractor
//!   (read · stream · online · Standard).
//! - `collect` — the stream-collect owned inspector: chunks parsed
//!   as they arrive into an owned source, sealed at `finish` into
//!   the standing queryable index — retain's product over a
//!   document that arrived in pieces (read · stream · offline ·
//!   Standard · owned).
//! - `survey` — the standing schema-less inspector over a
//!   stable-replay source: one index walk builds the row product
//!   (topology, `u64` spans, decoded scalar words) retaining zero
//!   source bytes; payload bytes are fetched by later walks
//!   (read · sequential-repeatable · offline · Standard).
//! - `rewrite` — the rule-driven batch rewriter (write ·
//!   buffered · static · tolerant · borrowed · commit-only).
//! - `inplace` — the rule-driven same-allocation in-place editor:
//!   equal-width record edits landed directly in the caller's own
//!   buffer, no output allocation (write · buffered · static ·
//!   Standard · in-place · commit-only).
//! - `fixed_inplace` — the fixed-scratch in-place editor: the same
//!   equal-width rule jobs with working memory carved from one
//!   caller slab, zero allocator traffic end to end (write ·
//!   buffered · static · Standard · in-place · commit-only ·
//!   fixed scratch).
//! - `convert` — the dialect-crossing converter pair: each cell is
//!   named by its OUTPUT dialect and reads the opposite one
//!   (write · buffered · static · crossing · Standard · borrowed ·
//!   commit-only).
//! - `splice` — the rule-driven buffered splicer: variable-length
//!   record edits with every length cascade settled in one pass
//!   (write · buffered · online · Standard · borrowed ·
//!   commit-only).
//! - `patch` — the borrowed one-shot editor: commit-only edits
//!   over `&[u8]`, byte-exact fidelity for everything untouched
//!   (write · buffered · offline · tolerant · borrowed ·
//!   commit-only).
//! - `fixed_patch` — the fixed-scratch one-shot patch: patch's
//!   commands and byte fidelity over caller-supplied working
//!   memory under a capacity contract, saves into a caller slice
//!   or sink (write · buffered · offline · tolerant · borrowed ·
//!   commit-only · fixed scratch).
//! - `markup` — the borrowed revisable editor: draft's commands
//!   and undo over a slice the caller keeps, zero copies at open
//!   (write · buffered · offline · tolerant · borrowed ·
//!   revisable).
//! - `adopt` — the ownership-transfer one-shot editor: patch's
//!   commands and saves over a moved-in buffer, transactional
//!   tenure at both doors (write · buffered · offline · tolerant ·
//!   owned · commit-only).
//! - `draft` — the tolerant revisable editor: session's commands
//!   and undo with patch's byte fidelity over a moved-in buffer
//!   (write · buffered · offline · tolerant · owned · revisable).
//! - `amend` — the canonical-admission borrowed one-shot editor:
//!   patch's commands and saves with session's admission — padded
//!   wire refuses at open, so no framing width is stored
//!   (write · buffered · offline · canonical · borrowed ·
//!   commit-only).
//! - `review` — the canonical-admission borrowed revisable
//!   editor: session's commands and undo over a slice the caller
//!   keeps — padded wire refuses at open, zero copies through the
//!   door (write · buffered · offline · canonical · borrowed ·
//!   revisable).
//! - `intake` — the canonical-admission one-shot editor: adopt's
//!   commands, saves, and transactional tenure with session's
//!   admission — padded wire refuses at open, so no framing width
//!   is stored (write · buffered · offline · canonical · owned ·
//!   commit-only).
//! - `session` — the handle-based editing session with precise
//!   undo and a two-pass save (write · buffered · offline ·
//!   canonical · owned · revisable).
//! - `rewire` — the streaming path-program rewirer: per-path
//!   actions bound at authoring, applied over chunked bytes
//!   (write · stream · static · Standard · commit-only).
//! - `transcode` — the streaming equal-length transcoder
//!   (write · stream · online · Standard · commit-only).
//! - `stream_adopt` — the stream-ingest one-shot editor: chunks
//!   parsed as they arrive into an owned source, sealed at
//!   `finish` into adopt's editing machine (write · stream ·
//!   offline · tolerant · owned · commit-only).
//! - `stream_draft` — the stream-ingest revisable editor: the
//!   same fed construction sealed into draft's editing machine,
//!   fallible at every growth edge (write · stream · offline ·
//!   tolerant · owned · revisable).
//! - `stream_intake` — the stream-ingest canonical one-shot
//!   editor: the same fed construction, judged canonical-minimal
//!   word by word as it arrives, sealed at `finish` into intake's
//!   editing machine (write · stream · offline · canonical ·
//!   owned · commit-only).
//! - `replay_rewrite` — the rule-driven batch rewriter over a
//!   stable-replay source: one walk judges and compiles the edit
//!   script, one splicing walk emits without parsing (write ·
//!   sequential-repeatable · static · Standard · commit-only).
//! - `replay_convert` — the dialect-crossing converter pair over a
//!   stable-replay source: each cell is named by its OUTPUT dialect
//!   and walks the opposite one (write · sequential-repeatable ·
//!   static · crossing · Standard · commit-only).
//! - `replay_splice` — the rule-driven splicer over a stable-replay
//!   source: one ask per record with LEN payloads met in two typed
//!   phases, answers staged by copy, one splicing walk (write ·
//!   sequential-repeatable · online · Standard · commit-only).
//! - `overhaul` — the one-shot editor over a stable-replay source:
//!   handle-addressed edits over an index built by walks, saved by
//!   one splicing walk that rides untouched extents verbatim
//!   (write · sequential-repeatable · offline · tolerant ·
//!   commit-only).
//! - `maintain` — the revisable editor over a stable-replay
//!   source: the markup twin's commands, exact undo, and
//!   byte-fidelity saves rebuilt over walks, every growth edge
//!   fallible (write · sequential-repeatable · offline · tolerant
//!   · revisable).
//! - `refit` — the one-shot editor over a stable-replay source
//!   under canonical-minimal admission: the amend twin's commands
//!   and splicing saves rebuilt over walks, padded spellings
//!   refused (write · sequential-repeatable · offline · canonical
//!   · commit-only).
//! - `commission` — the revisable editor over a stable-replay
//!   source under canonical-minimal admission: the review twin's
//!   commands, exact undo, and already-canonical saves rebuilt
//!   over walks, every growth edge fallible (write ·
//!   sequential-repeatable · offline · canonical · revisable).
//! - `construct` — the value-side builder: typed values to
//!   message bytes (author — outside the input axes).
//!
//! Nothing moves shape under any feature combination.
//!
//! One rule partitions allocation behavior across the scenario
//! modules: a machine owes fallible allocation only while it
//! carries revisable interactive state across turns — holdings
//! whose loss an abort cannot confine to the job in flight. The
//! revisable editor family carries exactly that — all twenty-six
//! forms: `Session`, `BorrowSession`, and `MixSession`; `Draft`,
//! `BorrowDraft`, and `MixDraft`; `Markup`, `BorrowMarkup`, and
//! `MixMarkup`; `Review`, `BorrowReview`, and `MixReview`;
//! `Maintain`, `BorrowMaintain`, and `MixMaintain`; `Commission`,
//! `BorrowCommission`, and `MixCommission`; and
//! their transfer siblings `TransferSession` and
//! `TransferBorrowSession`, `TransferDraft` and
//! `TransferBorrowDraft`, `TransferMarkup` and
//! `TransferBorrowMarkup`, `TransferReview` and
//! `TransferBorrowReview` — plus the priced dialect wrappers
//! (`PricedSession` and `PricedTransferSession` over the session
//! pair), whose ledgers add their own fallible edges; their
//! growth edges are fallible, and refusals surface as structured
//! faults. Every other machine's holdings are the in-flight
//! product of one job — an abort's loss ends with that job — so
//! working memory grows under the global allocator's panic/abort
//! discipline. Each module doc states its side.
//!
//! # Choosing features
//!
//! Every scenario module is gated behind a cargo feature named
//! `<module>-<dialect>`; thirteen families add a transfer capability
//! cell each (`transfer-<module>-<dialect>`), the session pair
//! adds a priced cell each (`priced-session-<dialect>`) and a
//! priced transfer cell each (`priced-transfer-session-<dialect>`),
//! three hosts project a fixed-scratch cell each
//! (`fixed-<module>-<dialect>`, implying nothing — enabling one
//! never pulls the heap host or the alloc crate), and the five
//! substrate leaves and the stable-replay supply stratum
//! (`replay-source`) are directly selectable — one hundred eight
//! features in all, default empty.
//! Enable exactly what you need — features are strictly additive
//! and no public type's shape moves with any combination. The
//! strata roots ([`wire`], [`varint`], [`path`], and the root
//! vocabulary) are always present; the five substrate leaves ride
//! their consuming cells or their direct-selection features.
//!
//! The crate is `#![no_std]` unconditionally and never names
//! `std`. The substrate leaves, `traverse-groupless`, and
//! `replay-source` link with no global allocator at all (a
//! bare-metal build selecting only these compiles as-is); the
//! fixed-scratch cells additionally run allocator-free on a
//! caller slab; every other cell pulls `alloc` through its
//! feature and needs nothing more.
//!
//! Start from your task:
//!
//! | Task | Module | Feature example |
//! |---|---|---|
//! | Select records by compiled path programs | `select` | `select-groupless` |
//! | Walk records with a borrowed cursor | `traverse` | `traverse-groupless` |
//! | Build a read-only tree with byte geometry | `inspect` | `inspect-groupless` |
//! | Build a read-only tree with byte geometry, zero allocator traffic | `fixed_inspect` | `fixed-inspect-groupless` |
//! | Build a movable, cacheable tree from an owned buffer | `retain` | `retain-groupless` |
//! | Route records from a chunked stream by path programs | `route` | `route-groupless` |
//! | Validate or extract from a chunked stream | `scan` | `scan-groupless` |
//! | Build a movable, cacheable tree from a chunked stream | `collect` | `collect-groupless` |
//! | Build a standing index over a stable-replay source | `survey` | `survey-groupless` |
//! | Batch-rewrite records by path rules | `rewrite` | `rewrite-grouped` |
//! | Equal-width edits landed in your own buffer | `inplace` | `inplace-groupless` |
//! | Equal-width edits in your buffer, zero allocator traffic | `fixed_inplace` | `fixed-inplace-groupless` |
//! | Convert between the wire dialects | `convert` | `convert-groupless` |
//! | Variable-length edits, cascades settled in one pass | `splice` | `splice-groupless` |
//! | One-shot borrowed edit, byte-exact fidelity | `patch` | `patch-groupless` |
//! | One-shot borrowed edit, zero allocator traffic | `fixed_patch` | `fixed-patch-groupless` |
//! | Editing with undo over a borrowed slice, zero-copy open | `markup` | `markup-groupless` |
//! | One-shot edit owning its buffer, movable mid-edit | `adopt` | `adopt-groupless` |
//! | Editing with undo over padded wire, byte-exact fidelity | `draft` | `draft-groupless` |
//! | One-shot borrowed edit under canonical admission | `amend` | `amend-groupless` |
//! | Editing with undo over a borrowed slice, canonical admission | `review` | `review-groupless` |
//! | One-shot edit under canonical admission, movable mid-edit | `intake` | `intake-groupless` |
//! | Editing session with undo | `session` | `session-grouped` |
//! | A session that knows its exact save price in O(1) | `session` | `priced-session-grouped` |
//! | Rewire a chunked stream by path-bound actions | `rewire` | `rewire-groupless` |
//! | Transcode between acceptance standards | `transcode` | `transcode-groupless` |
//! | One-shot edits over a document that arrives in chunks | `stream_adopt` | `stream-adopt-groupless` |
//! | Editing with undo over a document that arrives in chunks | `stream_draft` | `stream-draft-groupless` |
//! | One-shot edit under canonical admission over a document that arrives in chunks | `stream_intake` | `stream-intake-groupless` |
//! | Batch-rewrite records over a stable-replay source | `replay_rewrite` | `replay-rewrite-groupless` |
//! | Convert between the wire dialects over a stable-replay source | `replay_convert` | `replay-convert-groupless` |
//! | Splice records over a stable-replay source | `replay_splice` | `replay-splice-groupless` |
//! | One-shot edit over a stable-replay source | `overhaul` | `overhaul-groupless` |
//! | Editing with undo over a stable-replay source | `maintain` | `maintain-groupless` |
//! | One-shot edit under canonical admission over a stable-replay source | `refit` | `refit-groupless` |
//! | Editing with undo under canonical admission over a stable-replay source | `commission` | `commission-groupless` |
//! | Build a message from typed values | `construct` | `construct-groupless` |
//! | Relocate records and import across documents | any editor's `Transfer…` sibling | `transfer-session-groupless` |
//! | A transfer session that knows its exact save price in O(1) | `session` | `priced-transfer-session-grouped` |
//!
//! When several rows fit one task, the axes decide — first how the
//! input arrives, then the job's shape inside that presence:
//!
//! - **Reading, buffer in hand** — an ad-hoc walk → `traverse`;
//!   standing byte-geometry queries → `inspect` borrowing,
//!   `retain` owning; path-designated extraction → `select`.
//! - **Reading a stream** — whole-stream verdicts chunk by chunk →
//!   `scan`; path-designated delivery → `route`; standing
//!   byte-geometry queries over a document that arrives in chunks
//!   → `collect`, which parses each chunk as it copies it and
//!   seals into the owned index at `finish`.
//! - **Editing one buffer, one shot** — handle-addressed after a
//!   full parse → `patch` borrowing, `adopt` owning, `amend`
//!   borrowing and `intake` owning under canonical admission;
//!   compiled rules reused across documents → `rewrite`; your own
//!   per-record code with the payload in hand → `splice` — it
//!   clears the same job in one pass against the rewriter's two,
//!   while static designation buys plan reuse and gap insertion,
//!   not per-record speed. When every edit is equal-width
//!   (value/payload replacement, renumbering, whole-record
//!   substitution, tombstoning) and the result should land in the
//!   buffer you already own → `inplace`: one judge walk, zero
//!   output allocation, untouched bytes never rewritten —
//!   width-moving edits stay with the machines above.
//! - **Revision across turns** — `session` under canonical
//!   admission; `draft` under tolerant admission with patch's
//!   byte fidelity; `markup` when the same tolerant revision
//!   should borrow the buffer instead of taking it; `review` when
//!   the canonical revision should borrow it.
//! - **Editing a stream** — path-bound zero-cascade actions →
//!   `rewire`; per-record verdicts under locked lengths →
//!   `transcode`. No stream machine can move a committed
//!   container's length — that job is buffered by nature, and a
//!   stream you intend to *edit* is ingested instead:
//!   `stream_adopt` and `stream_draft` parse the chunks as they
//!   arrive and seal into the matching buffered editor, editing
//!   beginning after the seal; `stream_intake` is the tolerant
//!   pair's canonical twin — the same fed construction judged
//!   canonical-minimal as it arrives, sealing into `intake`'s
//!   machine.
//! - **A source you can walk again, but not address** — when the
//!   input is sequential-repeatable (a file, a snapshot — possibly
//!   larger than memory), implement
//!   `replay_source::StableReplaySource` once and the replay
//!   cells run the buffered jobs in walks, retaining zero source
//!   bytes: standing queries → `survey` (one index walk builds the
//!   rows with decoded words resident, payload bytes answered by
//!   later fetch walks); compiled rule batches → `replay_rewrite`
//!   (one walk judges and compiles the edit script, one splicing
//!   walk emits without parsing); changing the dialect itself →
//!   `replay_convert` (the buffered converter's directional laws
//!   over walks); your own per-record code →
//!   `replay_splice` (verdicts staged in the ask walk, LEN
//!   payloads met in two typed phases instead of in hand);
//!   handle-addressed one-shot edits → `overhaul` (commit-only
//!   saves; untouched extents ride the save walk verbatim);
//!   revision across turns → `maintain` (the markup twin's
//!   commands, exact undo, and byte-fidelity saves rebuilt over
//!   walks, every growth edge fallible); the same jobs under
//!   canonical-minimal admission → `refit` (the amend twin's
//!   one-shot commands; padded constructs refuse at the door or
//!   park as resident verdicts) and `commission` (the review
//!   twin's revision under the same door).
//!   Working memory scales with record structure and edit size,
//!   never source length — a buffered cell wants the
//!   random-access slice instead, a stream cell one pass with no
//!   rewind.
//! - **No allocator, or caller-supplied working memory** — the
//!   fixed-scratch cells run their hosts' exact jobs with every
//!   working byte carved from one caller slab under a capacity
//!   contract: handle-addressed one-shot edits → `fixed_patch`
//!   (saves into your slice or sink); rule-driven equal-width
//!   edits in your own buffer → `fixed_inplace`; standing
//!   byte-geometry queries over `&[u8]` → `fixed_inspect` (the
//!   row arena and parse stacks carved from the slab).
//!   Byte-identical to the host twin within an adequate plan;
//!   exhaustion is a deterministic refusal naming the lane, and
//!   the budget faces close the sizing loop.
//!
//! Each module's own doc carries a "Choosing a face" section for
//! the decisions inside the cell.
//!
//! Each module ships two independent types — pick a dialect suffix:
//!
//! - **`-groupless`** — the modern four-code wire language. Group
//!   codes (wire types 3 and 4) are refused as a capability
//!   judgment. Choose this for proto3 and most proto2 traffic.
//! - **`-grouped`** — the full six-code wire language including
//!   legacy start/end-group framing. Required when reading messages
//!   that use the `group` field type.
//!
//! The one exception to "the suffix names what the machine reads"
//! is `convert`, whose suffix names what it *writes*: each convert
//! cell reads the opposite dialect, because crossing is its job.
//!
//! No feature implies another cell's feature. The stream-stepping
//! pump behind scan, route, transcode, and rewire, the cursor
//! engine behind traverse, select, rewrite, inplace, convert, and
//! splice, and the pull pump and script strata behind the replay
//! cells, are private internal strata — selecting any of those
//! cells compiles its own public faces and nothing of its stratum
//! siblings'. The only implications are in-family: a capability
//! feature (`transfer-*`, `priced-*`) enables the cell it
//! extends.
//!
//! ```toml
//! [dependencies]
//! protobuf_edit = { version = "0.0", features = ["scan-groupless", "patch-grouped"] }
//! ```
//!
//! # Examples
//!
//! Decoding one record by hand with the substrate alone — the same
//! faces every scenario module composes, here selected directly
//! (features: `varint-slice`, `wire-groupless`):
//!
//! ```
//! # #[cfg(all(feature = "varint-slice", feature = "wire-groupless"))] {
//! use protobuf_edit::varint::slice;
//! use protobuf_edit::wire::groupless::{RecordKind, TagClass, classify};
//! use protobuf_edit::wire::{FieldNumber, Low3};
//!
//! // Field 1, varint 150 — protobuf's own documentation example.
//! let msg = [0x08, 0x96, 0x01];
//! let (word, tag_width) = slice::tag_word(&msg, 0, msg.len()).unwrap();
//! assert_eq!(FieldNumber::from_word(word), FieldNumber::new(1));
//! let class = classify(Low3::from_word(word));
//! assert_eq!(class, TagClass::Record(RecordKind::Varint));
//! let (value, _) = slice::value64(&msg, usize::from(tag_width), msg.len()).unwrap();
//! assert_eq!(value, 150);
//! # }
//! ```
//!
//! # Recipes
//!
//! The pairings that cross module lines — each notes the features
//! its doctest rides on (the modules stay independent; only the
//! caller's composition joins them).
//!
//! Machines move wire words; `scalar` gives them schema meaning.
//! A read pairs a machine's word face with the type's `decode_*`,
//! a write pairs the type's `encode_*` with a machine's command
//! (features: `patch-groupless`, `scalar`):
//!
//! ```
//! # #[cfg(all(feature = "patch-groupless", feature = "scalar"))] {
//! use protobuf_edit::DepthLimit;
//! use protobuf_edit::patch::groupless::Patch;
//! use protobuf_edit::scalar;
//!
//! // sint32 field 1 carrying -3 (zigzag wire word 5).
//! let msg = [0x08, 0x05];
//! let mut patch = Patch::open(&msg, DepthLimit::REFERENCE).unwrap();
//! let record = patch.top().next().unwrap();
//! assert_eq!(scalar::decode_sint32(patch.varint_word(record).unwrap()), -3);
//!
//! patch.set_varint(record, scalar::encode_sint32(-8)).unwrap();
//! assert_eq!(patch.save().unwrap(), [0x08, 0x0F]);
//! # }
//! ```
//!
//! A groupless machine refuses group codes as a capability
//! judgment, and the refusal names its class (features:
//! `patch-groupless`):
//!
//! ```
//! # #[cfg(feature = "patch-groupless")] {
//! use protobuf_edit::DepthLimit;
//! use protobuf_edit::patch::groupless::{OpenFault, Patch, Refusal};
//!
//! // An empty group of field 1: lawful wire outside the groupless
//! // language.
//! let msg = [0x0B, 0x0C];
//! assert!(matches!(
//!     Patch::open(&msg, DepthLimit::REFERENCE).err(),
//!     Some(OpenFault::Refused(Refusal::GroupCode { .. }))
//! ));
//! # }
//! ```
//!
//! That refusal class is the routing signal for the grouped twin:
//! the same bytes reopen under the six-code dialect (features:
//! `patch-grouped`):
//!
//! ```
//! # #[cfg(feature = "patch-grouped")] {
//! use protobuf_edit::DepthLimit;
//! use protobuf_edit::patch::grouped::Patch;
//!
//! // The empty group of field 1, reopened.
//! let msg = [0x0B, 0x0C];
//! let twin = Patch::open(&msg, DepthLimit::REFERENCE).unwrap();
//! assert_eq!(twin.top().count(), 1);
//! # }
//! ```
//!
//! A streaming validator is the cheap gate ahead of a buffered
//! editor: judge chunks as they arrive, and only a stream that
//! passed pays for an editing open. Declare the standard under
//! which the editor admits — the session is canonical-minimal; for
//! the tolerant `patch::open`, gate with `Standard::Tolerant`
//! (features: `scan-groupless`):
//!
//! ```
//! # #[cfg(feature = "scan-groupless")] {
//! use protobuf_edit::scan::Standard;
//! use protobuf_edit::scan::groupless::Validator;
//!
//! // varint f1=150 · LEN f2 "hi", arriving in chunks.
//! let msg = [0x08, 0x96, 0x01, 0x12, 0x02, 0x68, 0x69];
//! let mut gate = Validator::new(Standard::CanonicalMinimal);
//! for chunk in msg.chunks(3) {
//!     gate.feed(chunk).unwrap();
//! }
//! gate.finish().unwrap();
//! # }
//! ```
//!
//! …and the editing open only a passed stream pays for (features:
//! `session-groupless`):
//!
//! ```
//! # #[cfg(feature = "session-groupless")] {
//! use protobuf_edit::session::groupless::Session;
//!
//! // The gated stream above, buffered whole.
//! let msg = [0x08, 0x96, 0x01, 0x12, 0x02, 0x68, 0x69];
//! let mut session = Session::open_copy(&msg).unwrap();
//! let record = session.top().next().unwrap();
//! session.set_varint(record, 7).unwrap();
//! assert_eq!(session.save().unwrap()[..], [0x08, 0x07, 0x12, 0x02, 0x68, 0x69]);
//! # }
//! ```
//!
//! The value-side builder authors what the editors splice
//! (features: `construct-groupless`):
//!
//! ```
//! # #[cfg(feature = "construct-groupless")] {
//! use protobuf_edit::FieldNumber;
//! use protobuf_edit::construct::groupless::Builder;
//!
//! let f1 = FieldNumber::new(1).unwrap();
//! let mut builder = Builder::new();
//! builder.push_string(f1, "hi");
//! let body = builder.finish().unwrap();
//! assert_eq!(body, [0x0A, 0x02, 0x68, 0x69]);
//! # }
//! ```
//!
//! …and a `construct` product is exactly what `insert_payload` and
//! `set_payload` take (features: `patch-groupless`):
//!
//! ```
//! # #[cfg(feature = "patch-groupless")] {
//! use protobuf_edit::patch::groupless::{InsertAt, Patch};
//! use protobuf_edit::{DepthLimit, FieldNumber};
//!
//! // The builder's finish from above, spliced in whole.
//! let body = [0x0A, 0x02, 0x68, 0x69];
//! let msg = [0x08, 0x2A];
//! let mut patch = Patch::open(&msg, DepthLimit::REFERENCE).unwrap();
//! let f3 = FieldNumber::new(3).unwrap();
//! patch.insert_payload(InsertAt::TailOf(None), f3, &body).unwrap();
//! let saved = patch.save().unwrap();
//! assert_eq!(saved, [0x08, 0x2A, 0x1A, 0x04, 0x0A, 0x02, 0x68, 0x69]);
//! # }
//! ```

// u32 coordinates index usize spaces losslessly only on 32/64-bit
// pointer widths; the crate's subtraction-form extent checks assume
// the same. Anything else is out of contract.
#[cfg(not(any(target_pointer_width = "32", target_pointer_width = "64")))]
compile_error!("protobuf_edit supports 32-bit and 64-bit targets only");

// The allocator link obligation follows the cells that allocate:
// the scenario features below (capability features imply their
// bases, so bases alone carry the gate). The substrate leaves state
// wire facts with core alone, a fixed-scratch cell's working memory
// is the caller's slab, the stable-replay supply lends borrowed
// views, and the groupless traversal cursor walks borrowed bytes
// with no working set (its grouped twin pairs groups on a heap
// stack and is billed) — none pulls the alloc crate, so a build
// selecting only those compiles without a global allocator. The
// no-alloc consumer judge holds the gate in both directions:
// sufficient (the unbilled build links bare-metal) and tight (a
// billed cell that stops allocating reds the CI sweep).
#[cfg(any(
    test,
    feature = "select-grouped",
    feature = "select-groupless",
    feature = "traverse-grouped",
    feature = "inspect-grouped",
    feature = "inspect-groupless",
    feature = "retain-grouped",
    feature = "retain-groupless",
    feature = "route-grouped",
    feature = "route-groupless",
    feature = "scan-grouped",
    feature = "scan-groupless",
    feature = "collect-grouped",
    feature = "collect-groupless",
    feature = "rewrite-grouped",
    feature = "rewrite-groupless",
    feature = "inplace-grouped",
    feature = "inplace-groupless",
    feature = "convert-grouped",
    feature = "convert-groupless",
    feature = "splice-grouped",
    feature = "splice-groupless",
    feature = "patch-grouped",
    feature = "patch-groupless",
    feature = "markup-grouped",
    feature = "markup-groupless",
    feature = "adopt-grouped",
    feature = "adopt-groupless",
    feature = "draft-grouped",
    feature = "draft-groupless",
    feature = "amend-grouped",
    feature = "amend-groupless",
    feature = "review-grouped",
    feature = "review-groupless",
    feature = "intake-grouped",
    feature = "intake-groupless",
    feature = "session-grouped",
    feature = "session-groupless",
    feature = "rewire-grouped",
    feature = "rewire-groupless",
    feature = "transcode-grouped",
    feature = "transcode-groupless",
    feature = "stream-adopt-grouped",
    feature = "stream-adopt-groupless",
    feature = "stream-draft-grouped",
    feature = "stream-draft-groupless",
    feature = "stream-intake-grouped",
    feature = "stream-intake-groupless",
    feature = "survey-grouped",
    feature = "survey-groupless",
    feature = "replay-rewrite-grouped",
    feature = "replay-rewrite-groupless",
    feature = "replay-convert-grouped",
    feature = "replay-convert-groupless",
    feature = "replay-splice-grouped",
    feature = "replay-splice-groupless",
    feature = "overhaul-grouped",
    feature = "overhaul-groupless",
    feature = "maintain-grouped",
    feature = "maintain-groupless",
    feature = "refit-grouped",
    feature = "refit-groupless",
    feature = "commission-grouped",
    feature = "commission-groupless",
    feature = "construct-grouped",
    feature = "construct-groupless"
))]
extern crate alloc;

mod _macro;

mod admission;

// The stream machines' internal stepping stratum: the cross-chunk
// pump, its root-only twin, and the writers' staging ledger. Gated
// by the union of its consumers — the scenario cells that drive or
// compose it — never a public face of any of them.
#[allow(
    clippy::redundant_pub_crate,
    reason = "the public-type census reads `pub struct`/`pub enum` textually as public \
              surface; crate vocabulary inside this private module is spelled pub(crate) \
              so the roster stays true"
)]
#[cfg(any(
    feature = "scan-grouped",
    feature = "scan-groupless",
    feature = "route-grouped",
    feature = "route-groupless",
    feature = "rewire-grouped",
    feature = "rewire-groupless",
    feature = "transcode-grouped",
    feature = "transcode-groupless"
))]
mod pump;

// The buffered walk's internal cursor stratum: the checked
// single-pass engines the traverse faces re-export and the
// select/rewrite walks drive directly. Gated by the union of its
// consumers.
#[allow(
    clippy::redundant_pub_crate,
    reason = "the engine types are re-exported on the public traverse faces, so a \
              crate-only face spelled pub would leak through the re-export — pub(crate) \
              is load-bearing here, not redundant"
)]
#[cfg(any(
    feature = "select-grouped",
    feature = "select-groupless",
    feature = "rewrite-grouped",
    feature = "rewrite-groupless",
    feature = "inplace-grouped",
    feature = "inplace-groupless",
    feature = "fixed-inplace-groupless",
    feature = "convert-grouped",
    feature = "convert-groupless",
    feature = "splice-grouped",
    feature = "splice-groupless",
    feature = "traverse-grouped",
    feature = "traverse-groupless"
))]
mod cursor;

// The replay cells' internal stepping stratum: the carry kernel
// pulled over one supply walk in whole-source coordinates. Gated
// by the union of its consumers — the replay scenario cells —
// never a public face of any of them.
#[allow(
    clippy::redundant_pub_crate,
    reason = "the public-type census reads `pub struct`/`pub enum` textually as public \
              surface; crate vocabulary inside this private module is spelled pub(crate) \
              so the roster stays true"
)]
#[cfg(any(
    feature = "survey-grouped",
    feature = "survey-groupless",
    feature = "replay-rewrite-grouped",
    feature = "replay-rewrite-groupless",
    feature = "replay-convert-grouped",
    feature = "replay-convert-groupless",
    feature = "replay-splice-grouped",
    feature = "replay-splice-groupless",
    feature = "overhaul-grouped",
    feature = "overhaul-groupless",
    feature = "maintain-grouped",
    feature = "maintain-groupless",
    feature = "refit-grouped",
    feature = "refit-groupless",
    feature = "commission-grouped",
    feature = "commission-groupless"
))]
mod replay_pump;

#[allow(
    clippy::redundant_pub_crate,
    reason = "the public-type census reads `pub struct`/`pub enum` textually as public \
              surface; crate vocabulary inside this private module is spelled pub(crate) \
              so the roster stays true"
)]
#[cfg(any(
    feature = "replay-rewrite-grouped",
    feature = "replay-rewrite-groupless",
    feature = "replay-convert-grouped",
    feature = "replay-convert-groupless",
    feature = "replay-splice-grouped",
    feature = "replay-splice-groupless",
    feature = "overhaul-grouped",
    feature = "overhaul-groupless",
    feature = "maintain-grouped",
    feature = "maintain-groupless",
    feature = "refit-grouped",
    feature = "refit-groupless",
    feature = "commission-grouped",
    feature = "commission-groupless"
))]
mod replay_script;

// The revisable replay editors' shared store strata: the row,
// role-union, edit-algebra, revision-log, and value-store
// templates the maintain and commission cells instantiate inside
// their own dialect modules.
#[cfg(any(
    feature = "maintain-grouped",
    feature = "maintain-groupless",
    feature = "commission-grouped",
    feature = "commission-groupless"
))]
mod replay_revise;

// The stream-ingest cells' shared in-module judge corpus:
// boundary documents with emission-time geometry.
#[cfg(all(
    test,
    any(
        feature = "collect-grouped",
        feature = "collect-groupless",
        feature = "stream-adopt-grouped",
        feature = "stream-adopt-groupless",
        feature = "stream-draft-grouped",
        feature = "stream-draft-groupless",
        feature = "stream-intake-grouped",
        feature = "stream-intake-groupless"
    )
))]
mod stream_corpus;

// The one-shot editor family's internal core: macro-emitted store
// and machine strata for the patch/adopt/amend/intake instantiations.
#[cfg(any(
    feature = "patch-grouped",
    feature = "patch-groupless",
    feature = "adopt-grouped",
    feature = "adopt-groupless",
    feature = "amend-grouped",
    feature = "amend-groupless",
    feature = "intake-grouped",
    feature = "intake-groupless",
    feature = "stream-adopt-grouped",
    feature = "stream-adopt-groupless",
    feature = "stream-intake-grouped",
    feature = "stream-intake-groupless"
))]
mod editor;

// The revising editor family's internal core: macro-emitted layer
// and machine strata for the markup/draft/review/session
// instantiations.
#[cfg(any(
    feature = "markup-grouped",
    feature = "markup-groupless",
    feature = "draft-grouped",
    feature = "draft-groupless",
    feature = "review-grouped",
    feature = "review-groupless",
    feature = "session-grouped",
    feature = "session-groupless",
    feature = "stream-draft-grouped",
    feature = "stream-draft-groupless"
))]
mod revise;

// The fixed families' shared carving stratum: the slab splitter
// and the carve-order theorem's static side, consumed by every
// fixed cell's ladder emission.
#[allow(
    clippy::redundant_pub_crate,
    reason = "the public-type census reads `pub struct`/`pub enum` textually as public \
              surface; crate vocabulary inside this private module is spelled pub(crate) \
              so the roster stays true"
)]
#[cfg(any(
    feature = "fixed-inplace-grouped",
    feature = "fixed-inplace-groupless",
    feature = "fixed-inspect-grouped",
    feature = "fixed-inspect-groupless",
    feature = "fixed-patch-grouped",
    feature = "fixed-patch-groupless"
))]
mod fixed;

// The substrate strata, in the crate doc's order; then the
// scenario modules in the lattice's enumeration order (the census
// derives and enforces it). The strata roots are unconditional;
// the conditional leaves inside them (and the scalar matrix here)
// carry their consuming-cell/direct-selection gates.
pub mod wire;

pub mod varint;

#[cfg(any(
    test,
    feature = "scalar",
    feature = "construct-grouped",
    feature = "construct-groupless"
))]
pub mod scalar;

pub mod path;

// The source-designation contract vocabulary: minted by the offline
// read and edit machines, consumed by the transfer and import
// faces. Conditional, unlike the strata above: it compiles exactly
// when a machine that mints or consumes it is enabled, and the
// dialect submodules follow their own cells.
#[cfg(any(
    feature = "inspect-grouped",
    feature = "inspect-groupless",
    feature = "fixed-inspect-grouped",
    feature = "fixed-inspect-groupless",
    feature = "retain-grouped",
    feature = "retain-groupless",
    feature = "patch-grouped",
    feature = "patch-groupless",
    feature = "fixed-patch-grouped",
    feature = "fixed-patch-groupless",
    feature = "adopt-grouped",
    feature = "adopt-groupless",
    feature = "amend-grouped",
    feature = "amend-groupless",
    feature = "intake-grouped",
    feature = "intake-groupless",
    feature = "markup-grouped",
    feature = "markup-groupless",
    feature = "draft-grouped",
    feature = "draft-groupless",
    feature = "review-grouped",
    feature = "review-groupless",
    feature = "session-grouped",
    feature = "session-groupless",
    feature = "stream-adopt-grouped",
    feature = "stream-adopt-groupless",
    feature = "stream-draft-grouped",
    feature = "stream-draft-groupless",
    feature = "stream-intake-grouped",
    feature = "stream-intake-groupless",
    feature = "collect-grouped",
    feature = "collect-groupless",
    feature = "construct-grouped",
    feature = "construct-groupless"
))]
pub mod source;

// The stable-replay supply stratum: the sequential-repeatable
// source contract, its walk and coordinate vocabularies, and the
// slice-backed reference source. Conditional like `source`: it
// compiles exactly when a replay cell consumes it or its
// direct-selection feature names it for hand-rolled composition.
#[cfg(any(
    feature = "replay-source",
    feature = "survey-grouped",
    feature = "survey-groupless",
    feature = "replay-rewrite-grouped",
    feature = "replay-rewrite-groupless",
    feature = "replay-convert-grouped",
    feature = "replay-convert-groupless",
    feature = "replay-splice-grouped",
    feature = "replay-splice-groupless",
    feature = "overhaul-grouped",
    feature = "overhaul-groupless",
    feature = "maintain-grouped",
    feature = "maintain-groupless",
    feature = "refit-grouped",
    feature = "refit-groupless",
    feature = "commission-grouped",
    feature = "commission-groupless"
))]
pub mod replay_source;

#[cfg(any(feature = "select-grouped", feature = "select-groupless"))]
pub mod select;
#[cfg(any(feature = "traverse-grouped", feature = "traverse-groupless"))]
pub mod traverse;
#[cfg(any(
    feature = "inspect-grouped",
    feature = "inspect-groupless",
    feature = "fixed-inspect-grouped",
    feature = "fixed-inspect-groupless"
))]
pub mod inspect;
#[cfg(any(feature = "fixed-inspect-grouped", feature = "fixed-inspect-groupless"))]
pub mod fixed_inspect;
#[cfg(any(feature = "retain-grouped", feature = "retain-groupless"))]
pub mod retain;
#[cfg(any(feature = "route-grouped", feature = "route-groupless"))]
pub mod route;
#[cfg(any(feature = "scan-grouped", feature = "scan-groupless"))]
pub mod scan;
#[cfg(any(feature = "collect-grouped", feature = "collect-groupless"))]
pub mod collect;
#[cfg(any(feature = "survey-grouped", feature = "survey-groupless"))]
pub mod survey;
#[cfg(any(feature = "rewrite-grouped", feature = "rewrite-groupless"))]
pub mod rewrite;
#[cfg(any(
    feature = "inplace-grouped",
    feature = "inplace-groupless",
    feature = "fixed-inplace-grouped",
    feature = "fixed-inplace-groupless"
))]
pub mod inplace;
#[cfg(any(feature = "fixed-inplace-grouped", feature = "fixed-inplace-groupless"))]
pub mod fixed_inplace;
#[cfg(any(feature = "convert-grouped", feature = "convert-groupless"))]
pub mod convert;
#[cfg(any(feature = "splice-grouped", feature = "splice-groupless"))]
pub mod splice;
#[cfg(any(feature = "patch-grouped", feature = "patch-groupless"))]
pub mod patch;
#[cfg(any(feature = "fixed-patch-grouped", feature = "fixed-patch-groupless"))]
pub mod fixed_patch;
#[cfg(any(feature = "markup-grouped", feature = "markup-groupless"))]
pub mod markup;
#[cfg(any(feature = "adopt-grouped", feature = "adopt-groupless"))]
pub mod adopt;
#[cfg(any(feature = "draft-grouped", feature = "draft-groupless"))]
pub mod draft;
#[cfg(any(feature = "amend-grouped", feature = "amend-groupless"))]
pub mod amend;
#[cfg(any(feature = "review-grouped", feature = "review-groupless"))]
pub mod review;
#[cfg(any(feature = "intake-grouped", feature = "intake-groupless"))]
pub mod intake;
#[cfg(any(feature = "session-grouped", feature = "session-groupless"))]
pub mod session;
#[cfg(any(feature = "rewire-grouped", feature = "rewire-groupless"))]
pub mod rewire;
#[cfg(any(feature = "transcode-grouped", feature = "transcode-groupless"))]
pub mod transcode;
#[cfg(any(feature = "stream-adopt-grouped", feature = "stream-adopt-groupless"))]
pub mod stream_adopt;
#[cfg(any(feature = "stream-draft-grouped", feature = "stream-draft-groupless"))]
pub mod stream_draft;
#[cfg(any(feature = "stream-intake-grouped", feature = "stream-intake-groupless"))]
pub mod stream_intake;
#[cfg(any(feature = "replay-rewrite-grouped", feature = "replay-rewrite-groupless"))]
pub mod replay_rewrite;
#[cfg(any(feature = "replay-convert-grouped", feature = "replay-convert-groupless"))]
pub mod replay_convert;
#[cfg(any(feature = "replay-splice-grouped", feature = "replay-splice-groupless"))]
pub mod replay_splice;
#[cfg(any(feature = "overhaul-grouped", feature = "overhaul-groupless"))]
pub mod overhaul;
#[cfg(any(feature = "maintain-grouped", feature = "maintain-groupless"))]
pub mod maintain;
#[cfg(any(feature = "refit-grouped", feature = "refit-groupless"))]
pub mod refit;
#[cfg(any(feature = "commission-grouped", feature = "commission-groupless"))]
pub mod commission;
#[cfg(any(feature = "construct-grouped", feature = "construct-groupless"))]
pub mod construct;

pub use wire::{FieldNumber, Low3, PayloadLen};

mod span {
    /// A half-open byte range, always in the coordinates of a whole
    /// input; the using face names which input it indexes.
    ///
    /// Crate vocabulary, shared by the inspectors' and the edit
    /// sessions' span queries (the hex-view supply). Ordered by
    /// construction: `start <= end` is the type's invariant, so
    /// length and range projections cannot underflow.
    ///
    /// Coordinates inhabit the crate's input cap: a buffered
    /// machine admits at most `i32::MAX` input bytes — the top of
    /// the wire's LEN length class and the reference reader's
    /// single-message hard bound — so admitted coordinates fit
    /// `u32` and their arithmetic cannot wrap. The admission
    /// refusals across the crate (`Oversize`, `FeedOversize`,
    /// `TooLarge`) all name this one cap.
    ///
    /// # Examples
    ///
    /// ```
    /// use protobuf_edit::Span;
    ///
    /// let span = Span::new(3, 8);
    /// assert_eq!((span.start(), span.end(), span.len()), (3, 8, 5));
    /// let view = [0u8; 16];
    /// assert_eq!(view[span.as_range()].len(), 5);
    /// ```
    #[must_use]
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub struct Span {
        start: u32,
        end: u32,
    }

    impl Span {
        /// Builds the range.
        ///
        /// # Panics
        ///
        /// If `start > end` — an inverted range is a caller bug,
        /// judged here so the ordered-interval invariant holds in
        /// every build.
        #[inline]
        #[track_caller]
        pub const fn new(start: u32, end: u32) -> Self {
            assert!(start <= end, "Span::new: inverted range");
            Self { start, end }
        }

        /// Builds from an admitted coordinate and extent — ordered
        /// by construction (a width is non-negative) and wrap-free
        /// by the coordinate class: both arguments live in
        /// `0..=2^31 - 1`, so the sum is at most `2^32 - 2` and the
        /// u32 addition below carries no judgment — the evidence
        /// rides the argument types, stored through the callers'
        /// rows. Not for foreign input — the public door is
        /// [`Span::new`].
        #[cfg(any(
            feature = "select-grouped",
            feature = "select-groupless",
            feature = "inspect-grouped",
            feature = "inspect-groupless",
            feature = "fixed-inspect-grouped",
            feature = "fixed-inspect-groupless",
            feature = "retain-grouped",
            feature = "retain-groupless",
            feature = "collect-grouped",
            feature = "collect-groupless"
        ))]
        #[inline]
        pub(crate) const fn of(
            start: crate::admission::Coord,
            width: crate::admission::Extent,
        ) -> Self {
            Self { start: start.as_inner(), end: start.as_inner() + width.as_inner() }
        }

        /// Inclusive start.
        #[inline]
        #[must_use]
        pub const fn start(self) -> u32 {
            self.start
        }

        /// Exclusive end.
        #[inline]
        #[must_use]
        pub const fn end(self) -> u32 {
            self.end
        }

        /// Byte length.
        #[inline]
        #[must_use]
        pub const fn len(self) -> u32 {
            self.end - self.start
        }

        /// True when the range is empty.
        #[inline]
        #[must_use]
        pub const fn is_empty(self) -> bool {
            self.start == self.end
        }

        /// The range in slice-index form.
        #[inline]
        #[must_use]
        pub const fn as_range(self) -> core::ops::Range<usize> {
            crate::admission::usize_of(self.start)..crate::admission::usize_of(self.end)
        }
    }
}

pub use span::Span;

/// The class of a wire or admission refusal, judged by the repair
/// action: what has to change for the same feed to be accepted.
///
/// Every scenario machine's wire verdicts fall into exactly these
/// three classes, and the classifier is the fix's owner — the same
/// bytes may be refused by one machine and accepted by another,
/// and the class says what separates them.
///
/// The read-side fault vocabularies and the rule-driven writers
/// (splice, rewire, transcode) answer it through their `class()`
/// queries; the editing families (session, patch, and their kin)
/// split the classes into types instead — their `Fault` (grammar)
/// and `Refusal` (policy and capability) already dispatch
/// consumers by class.
#[must_use]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FaultClass {
    /// A grammar fault: no machine in this crate accepts the
    /// construct under any configuration — the fix belongs to the
    /// document's producer.
    Grammar,
    /// A policy refusal: lawful wire refused under a declared
    /// configuration value, accepted under another — a tolerant
    /// acceptance standard (`Standard::Tolerant`), a higher
    /// [`DepthLimit`], or a tolerant acceptance point.
    Policy,
    /// A capability refusal: lawful wire beyond the machine's
    /// capability — a group code (the twin dialect machine accepts
    /// it), a stream running past the addressable coordinate
    /// space, or a length declared out to that space's reserved
    /// ceiling (no machine here reaches further).
    Capability,
}

/// The declared acceptance standard (a configuration datum, not a
/// type parameter: the caller declares it at runtime, and the
/// verdict face reads "legal under X").
///
/// The value-level machines (scan, route, transcode, and the
/// eager read/rewrite faces that take it) match it once at entry
/// and run a monomorphized engine instance; the sibling-typed
/// faces (the `traverse`/`select` canonical twins, the editors)
/// fix one standard in the type itself — as `CanonicalCursor` and
/// `CanonicalMatches` do — and take no `Standard` argument.
///
/// # Examples
///
/// ```
/// # #[cfg(feature = "scan-groupless")] {
/// use protobuf_edit::scan::Standard;
/// use protobuf_edit::scan::groupless::{FaultKind, Validator};
///
/// // 150 continuation-padded to three bytes: reference-tolerant
/// // wire, refused only under the strict standard.
/// let padded = [0x08, 0x96, 0x81, 0x00];
///
/// let mut tolerant = Validator::new(Standard::Tolerant);
/// tolerant.feed(&padded).unwrap();
/// assert!(tolerant.finish().is_ok());
///
/// let mut strict = Validator::new(Standard::CanonicalMinimal);
/// let fault = strict.feed(&padded).unwrap_err();
/// assert!(matches!(
///     fault.kind(),
///     FaultKind::NonMinimalValue { field } if field.as_inner() == 1
/// ));
/// assert_eq!(fault.at(), 1);
/// # }
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Standard {
    /// Every construct that terminates inside its width window,
    /// stays inside its value class, and nests lawfully is accepted
    /// — padded varints pass. The reference reader's acceptance.
    Tolerant,
    /// Tolerant plus minimal width for every varint construct.
    CanonicalMinimal,
}

/// The construct a refused varint read was serving: a record head
/// holds at most these three varint sites, judged in this order.
///
/// The post-tag stages carry the record's field number — the head
/// tag has already revealed it; the tag stage carries none, since
/// no field exists yet.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Stage {
    /// The head tag word.
    Tag,
    /// The LEN length prefix.
    LenPrefix {
        /// The record's field number.
        field: FieldNumber,
    },
    /// A varint record's value.
    Value {
        /// The record's field number.
        field: FieldNumber,
    },
}

crate::_macro::define_valid_range_type! {
    /// A committed reader's total nesting bound.
    ///
    /// Crate vocabulary, not a wire fact: how deep containers (LEN
    /// and group alike) may nest before the reader refuses.
    /// Consumed with this one meaning by every committed-descent
    /// scenario: the readers (select, inspect, retain, scan,
    /// route), the writers (rewrite, rewire, convert, splice,
    /// transcode), and the one-shot editors (patch, adopt, amend,
    /// intake). The revisable editors (session, draft, markup,
    /// review) deliberately carry none — descent there is a
    /// per-record commitment with a resident verdict, not a policy
    /// refusal — and the bare traversal cursor deliberately
    /// carries none either: it hands LEN payloads to the consumer, so its
    /// own bound covers in-band groups only
    /// (`traverse::GroupDepth`, converted `From` this type).
    ///
    /// The domain is policy with official anchors: the C++ and
    /// Java reference readers unmarshal at depth 100
    /// ([`DepthLimit::REFERENCE`]) and Go at
    /// 10,000 — exactly this type's cap
    /// (<https://protobuf.dev/programming-guides/proto-limits/>);
    /// anything beyond is a configuration error, not a supported
    /// value. Zero is excluded: the bound guards against runaway
    /// nesting, it is not a "no tree" switch — flat presentation is
    /// the supply face's job (advise everything opaque), so
    /// [`DepthLimit::MIN`] (one) is the tightest usable bound.
    ///
    /// # Examples
    ///
    /// ```
    /// use protobuf_edit::DepthLimit;
    ///
    /// assert_eq!(DepthLimit::REFERENCE.as_inner(), 100);
    /// assert_eq!(DepthLimit::new(0), None); // not a "no tree" switch
    /// assert_eq!(DepthLimit::new(10_001), None); // past the Go cap
    /// ```
    #[must_use]
    pub struct DepthLimit(u16 as u16 in 1..=10_000) with min, max, new;
}

impl DepthLimit {
    /// The C++ and Java reference readers' recursion limit (100).
    pub const REFERENCE: Self = Self::new(100).unwrap();
}
