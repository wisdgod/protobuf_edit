//! The stream-ingest cells' shared test corpus: boundary documents
//! built record-by-record with emission-time geometry, so every
//! expectation is derived from construction rather than from a
//! second parser. Test-only.

use alloc::vec::Vec;

use crate::varint::{emit32_at, emit64_at, encoded_len32, encoded_len64};
use crate::wire::PayloadLen;

/// One record's body, with its exact spelling.
pub enum Body {
    /// A varint value at an explicit width (padded when wider than
    /// minimal).
    Varint { value: u64, width: u32 },
    /// A fixed 32-bit payload.
    I32(u32),
    /// A fixed 64-bit payload.
    I64(u64),
    /// A LEN record: an explicit prefix width over opaque payload
    /// bytes.
    Len { prefix_width: u32, payload: Vec<u8> },
}

/// One record: field, tag spelling, body.
pub struct Record {
    pub field: u32,
    pub tag_width: u32,
    pub body: Body,
}

impl Record {
    /// A minimally spelled record.
    pub fn minimal(field: u32, body: Body) -> Self {
        let body = Self::widen(body);
        let probe = Self { field, tag_width: 1, body };
        let tag_width = encoded_len32((field << 3) | probe.code());
        Self { tag_width, ..probe }
    }

    /// Normalizes declared widths that are below minimal (the
    /// builders pass 0 for "minimal").
    fn widen(body: Body) -> Body {
        match body {
            Body::Varint { value, width } => {
                Body::Varint { value, width: width.max(encoded_len64(value)) }
            }
            Body::Len { prefix_width, payload } => {
                let min = encoded_len32(u32::try_from(payload.len()).unwrap());
                Body::Len { prefix_width: prefix_width.max(min), payload }
            }
            fixed => fixed,
        }
    }

    const fn code(&self) -> u32 {
        match self.body {
            Body::Varint { .. } => 0,
            Body::I64(_) => 1,
            Body::Len { .. } => 2,
            Body::I32(_) => 5,
        }
    }
}

/// A record's expected geometry and projections, derived while
/// emitting.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Expected {
    pub field: u32,
    /// The wire code (0 varint, 1 i64, 2 len, 5 i32).
    pub code: u32,
    pub start: u32,
    pub end: u32,
    pub tag_width: u32,
    /// The LEN prefix width (zero for scalars).
    pub delim_width: u32,
    /// The varint value, where the record is one.
    pub value: Option<u64>,
    /// The payload extent (LEN body, or the fixed value bytes).
    pub payload_start: u32,
    pub payload_len: u32,
}

/// Emits `records` and returns the bytes beside their derived
/// geometry.
pub fn emit(records: &[Record]) -> (Vec<u8>, Vec<Expected>) {
    let mut bytes = Vec::new();
    let mut expected = Vec::new();
    for record in records {
        let start = u32::try_from(bytes.len()).unwrap();
        let word = (record.field << 3) | record.code();
        let mut window = [0u8; 5];
        emit32_at(word, record.tag_width, &mut window);
        bytes.extend_from_slice(&window[..record.tag_width as usize]);
        let value_at = u32::try_from(bytes.len()).unwrap();
        let (delim_width, value, payload_start, payload_len) = match &record.body {
            Body::Varint { value, width } => {
                let mut window = [0u8; 10];
                emit64_at(*value, *width, &mut window);
                bytes.extend_from_slice(&window[..*width as usize]);
                (0, Some(*value), value_at, *width)
            }
            Body::I32(bits) => {
                bytes.extend_from_slice(&bits.to_le_bytes());
                (0, None, value_at, 4)
            }
            Body::I64(bits) => {
                bytes.extend_from_slice(&bits.to_le_bytes());
                (0, None, value_at, 8)
            }
            Body::Len { prefix_width, payload } => {
                let len = u32::try_from(payload.len()).unwrap();
                assert!(PayloadLen::new(len).is_some());
                let mut window = [0u8; 5];
                emit32_at(len, *prefix_width, &mut window);
                bytes.extend_from_slice(&window[..*prefix_width as usize]);
                let body_at = u32::try_from(bytes.len()).unwrap();
                bytes.extend_from_slice(payload);
                (*prefix_width, None, body_at, len)
            }
        };
        let end = u32::try_from(bytes.len()).unwrap();
        expected.push(Expected {
            field: record.field,
            code: record.code(),
            start,
            end,
            tag_width: record.tag_width,
            delim_width,
            value,
            payload_start,
            payload_len,
        });
    }
    (bytes, expected)
}

/// The groupless boundary corpus: tag widths 1..=5, value widths
/// 1..=10, padding at every width, fixed edges, LEN prefix and
/// payload edges, zero-length LEN, nested LEN as opaque, and the
/// opacity item whose payload bytes look like malformed wire.
#[cfg(any(
    feature = "collect-groupless",
    feature = "stream-adopt-groupless",
    feature = "stream-draft-groupless",
    feature = "stream-intake-groupless"
))]
pub fn groupless_items() -> Vec<(Vec<u8>, Vec<Expected>)> {
    let mut items = Vec::new();
    // The empty document.
    items.push(emit(&[]));
    // Tag widths 1..=5 (padding at every width).
    for width in 1..=5 {
        items.push(emit(&[Record {
            field: 1,
            tag_width: width,
            body: Body::Varint { value: 42, width: 1 },
        }]));
    }
    // Value widths 1..=10, minimal at each step boundary.
    for width in 1..=10u32 {
        let value = if width == 1 { 1 } else { 1u64 << (7 * (width - 1)) };
        assert_eq!(encoded_len64(value), width);
        items.push(emit(&[Record::minimal(1, Body::Varint { value, width })]));
    }
    // Tolerant padding at every value width.
    for width in 2..=10 {
        items.push(emit(&[Record::minimal(1, Body::Varint { value: 1, width })]));
    }
    // The u64 class top.
    items.push(emit(&[Record::minimal(1, Body::Varint { value: u64::MAX, width: 10 })]));
    // Fixed payloads, both widths, extreme bit patterns.
    items.push(emit(&[Record::minimal(1, Body::I32(0x8000_0001))]));
    items.push(emit(&[Record::minimal(1, Body::I64(0x8000_0000_0000_0001))]));
    // LEN prefix widths 1..=5 over a small payload.
    for width in 1..=5 {
        items.push(emit(&[Record {
            field: 2,
            tag_width: 1,
            body: Body::Len { prefix_width: width, payload: alloc::vec![0x61, 0x62, 0x63] },
        }]));
    }
    // Zero-length LEN.
    items.push(emit(&[Record::minimal(2, Body::Len { prefix_width: 1, payload: Vec::new() })]));
    // Nested LEN as opaque: the payload is itself a valid record.
    let (inner, _) = emit(&[Record::minimal(1, Body::Varint { value: 7, width: 1 })]);
    items.push(emit(&[Record::minimal(3, Body::Len { prefix_width: 1, payload: inner })]));
    // The opacity item: payload bytes that look like malformed wire
    // (a group-open tag, then a varint cut short) must pass as
    // opaque payload, not be wire-judged.
    items.push(emit(&[Record::minimal(
        4,
        Body::Len { prefix_width: 1, payload: alloc::vec![0x0B, 0x80] },
    )]));
    // A mixed document crossing every kind and spelling.
    items.push(emit(&[
        Record::minimal(1, Body::Varint { value: 150, width: 2 }),
        Record { field: 2, tag_width: 3, body: Body::Varint { value: 0, width: 4 } },
        Record::minimal(3, Body::Len { prefix_width: 2, payload: alloc::vec![0xFF; 9] }),
        Record::minimal(4, Body::I32(0)),
        Record::minimal(5, Body::Len { prefix_width: 1, payload: Vec::new() }),
        Record::minimal(6, Body::I64(u64::MAX)),
        Record::minimal(64, Body::Varint { value: 1, width: 10 }),
    ]));
    // A long flat run: the chunk sweep crosses many record edges.
    let run: Vec<Record> = (0..64)
        .map(|i| {
            Record::minimal(1 + (i % 7), Body::Varint { value: u64::from(i), width: 1 + (i % 3) })
        })
        .collect();
    items.push(emit(&run));
    items
}

/// The chunkings every corpus item is fed under: whole, every
/// single split, byte-at-a-time, and byte-at-a-time with empty
/// chunks interspersed.
pub fn chunkings(bytes: &[u8]) -> Vec<Vec<Vec<u8>>> {
    let mut plans = Vec::new();
    plans.push(alloc::vec![bytes.to_vec()]);
    for split in 0..=bytes.len() {
        plans.push(alloc::vec![bytes[..split].to_vec(), bytes[split..].to_vec()]);
    }
    plans.push(bytes.iter().map(|&b| alloc::vec![b]).collect());
    let mut with_empties = Vec::new();
    with_empties.push(Vec::new());
    for &byte in bytes {
        with_empties.push(alloc::vec![byte]);
        with_empties.push(Vec::new());
    }
    plans.push(with_empties);
    plans
}

// The grouped-geometry half rides the grouped cells alone, and the
// groupless boundary corpus their groupless twins; under closures
// without them the items compile out, so `--all-targets` lib-test
// builds stay green.
/// One node of a grouped document: a leaf record or a group frame
/// with explicit tag spellings.
#[cfg(any(
    feature = "collect-grouped",
    feature = "stream-adopt-grouped",
    feature = "stream-draft-grouped",
    feature = "stream-intake-grouped"
))]
pub enum Node {
    /// A scalar or LEN record.
    Leaf(Record),
    /// A group frame around nested nodes.
    Group {
        /// The group's field number.
        field: u32,
        /// The open tag's spelling.
        tag_width: u32,
        /// The end tag's spelling.
        end_width: u32,
        /// The interior, in wire order.
        kids: Vec<Self>,
    },
}

#[cfg(any(
    feature = "collect-grouped",
    feature = "stream-adopt-grouped",
    feature = "stream-draft-grouped",
    feature = "stream-intake-grouped"
))]
impl Node {
    /// A minimally framed group.
    pub const fn group(field: u32, kids: Vec<Self>) -> Self {
        let width = encoded_len32((field << 3) | 3);
        Self::Group { field, tag_width: width, end_width: width, kids }
    }
}

/// A grouped record's expected geometry: the flat facts plus the
/// interior.
#[cfg(any(
    feature = "collect-grouped",
    feature = "stream-adopt-grouped",
    feature = "stream-draft-grouped",
    feature = "stream-intake-grouped"
))]
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ExpectedNode {
    /// The flat geometry (a group's `code` is 3; its payload extent
    /// is the interior between the frame tags, and `delim_width` is
    /// the end tag's spelling).
    pub row: Expected,
    /// The interior, in wire order (empty for leaves).
    pub kids: Vec<Self>,
}

/// Emits a grouped document and returns the bytes beside the
/// derived geometry tree.
#[cfg(any(
    feature = "collect-grouped",
    feature = "stream-adopt-grouped",
    feature = "stream-draft-grouped",
    feature = "stream-intake-grouped"
))]
pub fn emit_tree(nodes: &[Node]) -> (Vec<u8>, Vec<ExpectedNode>) {
    fn grow(bytes: &mut Vec<u8>, nodes: &[Node]) -> Vec<ExpectedNode> {
        let mut expected = Vec::new();
        for node in nodes {
            match node {
                Node::Leaf(record) => {
                    let (tail, rows) = emit(core::slice::from_ref(record));
                    let shift = u32::try_from(bytes.len()).unwrap();
                    bytes.extend_from_slice(&tail);
                    let row = rows[0];
                    expected.push(ExpectedNode {
                        row: Expected {
                            start: row.start + shift,
                            end: row.end + shift,
                            payload_start: row.payload_start + shift,
                            ..row
                        },
                        kids: Vec::new(),
                    });
                }
                Node::Group { field, tag_width, end_width, kids } => {
                    let start = u32::try_from(bytes.len()).unwrap();
                    let mut window = [0u8; 5];
                    emit32_at((field << 3) | 3, *tag_width, &mut window);
                    bytes.extend_from_slice(&window[..*tag_width as usize]);
                    let interior_start = u32::try_from(bytes.len()).unwrap();
                    let kids = grow(bytes, kids);
                    let interior_end = u32::try_from(bytes.len()).unwrap();
                    emit32_at((field << 3) | 4, *end_width, &mut window);
                    bytes.extend_from_slice(&window[..*end_width as usize]);
                    let end = u32::try_from(bytes.len()).unwrap();
                    expected.push(ExpectedNode {
                        row: Expected {
                            field: *field,
                            code: 3,
                            start,
                            end,
                            tag_width: *tag_width,
                            delim_width: *end_width,
                            value: None,
                            payload_start: interior_start,
                            payload_len: interior_end - interior_start,
                        },
                        kids,
                    });
                }
            }
        }
        expected
    }
    let mut bytes = Vec::new();
    let expected = grow(&mut bytes, nodes);
    (bytes, expected)
}

/// The grouped boundary corpus: the groupless items' shapes under
/// group frames, plus the frame-specific rows — empty, padded, and
/// nested frames, and group-looking bytes opaque inside a LEN.
#[cfg(any(
    feature = "collect-grouped",
    feature = "stream-adopt-grouped",
    feature = "stream-draft-grouped",
    feature = "stream-intake-grouped"
))]
pub fn grouped_items() -> Vec<(Vec<u8>, Vec<ExpectedNode>)> {
    let leaf = |field, body| Node::Leaf(Record::minimal(field, body));
    let mut items = alloc::vec![
        // The empty document, and an empty group.
        emit_tree(&[]),
        emit_tree(&[Node::group(1, Vec::new())]),
    ];
    // A group around each scalar kind.
    items.push(emit_tree(&[Node::group(
        1,
        alloc::vec![leaf(2, Body::Varint { value: 150, width: 2 })],
    )]));
    items.push(emit_tree(&[Node::group(1, alloc::vec![leaf(2, Body::I32(7))])]));
    items.push(emit_tree(&[Node::group(1, alloc::vec![leaf(2, Body::I64(7))])]));
    items.push(emit_tree(&[Node::group(
        1,
        alloc::vec![leaf(2, Body::Len { prefix_width: 1, payload: alloc::vec![0x61, 0x62] })],
    )]));
    // Padded frame tags at every width, both ends.
    for width in 1..=5 {
        items.push(emit_tree(&[Node::Group {
            field: 1,
            tag_width: width,
            end_width: 6 - width,
            kids: alloc::vec![leaf(2, Body::Varint { value: 1, width: 1 })],
        }]));
    }
    // A group around a padded varint value: tolerant cells seal it
    // byte-exactly, canonical cells refuse the value word.
    items.push(emit_tree(&[Node::group(
        1,
        alloc::vec![leaf(2, Body::Varint { value: 1, width: 2 })],
    )]));
    // Nested groups, deep and mixed.
    items.push(emit_tree(&[Node::group(
        1,
        alloc::vec![Node::group(2, alloc::vec![Node::group(3, Vec::new())])],
    )]));
    items.push(emit_tree(&[
        leaf(1, Body::Varint { value: 0, width: 1 }),
        Node::group(
            2,
            alloc::vec![
                leaf(3, Body::Varint { value: 300, width: 2 }),
                Node::group(4, alloc::vec![leaf(5, Body::I32(1))]),
                leaf(6, Body::Len { prefix_width: 2, payload: alloc::vec![0xFF; 3] }),
            ],
        ),
        leaf(7, Body::I64(2)),
        Node::group(2, Vec::new()),
    ]));
    // The opacity item inside a group: a LEN body that looks like
    // group wire must stay opaque.
    items.push(emit_tree(&[Node::group(
        1,
        alloc::vec![leaf(2, Body::Len { prefix_width: 1, payload: alloc::vec![0x0B, 0x14, 0x0C] })],
    )]));
    items
}

// The cut-stage judges ride the stream cells alone; under closures
// without them the items compile out, so `--all-targets` lib-test
// builds stay green.
/// Where a cut position lands inside its record: the stage the
/// truncation fault must name. Derived from emission-time geometry.
#[cfg(any(
    feature = "stream-adopt-grouped",
    feature = "stream-adopt-groupless",
    feature = "stream-draft-grouped",
    feature = "stream-draft-groupless",
    feature = "stream-intake-grouped",
    feature = "stream-intake-groupless"
))]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CutStage {
    /// On a record boundary: the prefix is a complete document.
    Boundary,
    /// Inside the head tag; the buffered coordinate is the record
    /// start.
    Tag { start: u32 },
    /// Inside a varint value; the buffered coordinate is the value
    /// offset.
    Value { field: u32, value_at: u32 },
    /// Inside a LEN length prefix.
    LenWord { field: u32, value_at: u32 },
    /// Inside a fixed or counted payload: the buffered coordinate
    /// is the payload start, with `need` claimed and `have` present.
    Payload { field: u32, at: u32, need: u32, have: u32 },
    /// Cleanly between records inside an open group: the innermost
    /// frame is unclosed; the buffered coordinate is its open tag.
    #[cfg(any(
        feature = "stream-adopt-grouped",
        feature = "stream-draft-grouped",
        feature = "stream-intake-grouped"
    ))]
    Unclosed { field: u32, at: u32 },
}

/// Classifies a cut position against the derived geometry.
#[cfg(any(
    feature = "stream-adopt-groupless",
    feature = "stream-draft-groupless",
    feature = "stream-intake-groupless"
))]
pub fn cut_stage(expected: &[Expected], cut: u32) -> CutStage {
    let Some(record) = expected.iter().find(|r| r.start < cut && cut < r.end) else {
        return CutStage::Boundary;
    };
    leaf_stage(record, cut)
}

/// The leaf classification a strictly interior cut receives.
#[cfg(any(
    feature = "stream-adopt-grouped",
    feature = "stream-adopt-groupless",
    feature = "stream-draft-grouped",
    feature = "stream-draft-groupless",
    feature = "stream-intake-grouped",
    feature = "stream-intake-groupless"
))]
const fn leaf_stage(record: &Expected, cut: u32) -> CutStage {
    let value_at = record.start + record.tag_width;
    if cut < value_at {
        return CutStage::Tag { start: record.start };
    }
    match record.code {
        0 => CutStage::Value { field: record.field, value_at },
        2 if cut < record.payload_start => CutStage::LenWord { field: record.field, value_at },
        _ => CutStage::Payload {
            field: record.field,
            at: record.payload_start,
            need: record.payload_len,
            have: cut - record.payload_start,
        },
    }
}

/// [`cut_stage`] over a grouped geometry tree: a cut inside a frame
/// tag truncates that tag; a cut between a group's interior records
/// leaves the innermost group unclosed.
#[cfg(any(
    feature = "stream-adopt-grouped",
    feature = "stream-draft-grouped",
    feature = "stream-intake-grouped"
))]
pub fn cut_stage_tree(expected: &[ExpectedNode], cut: u32) -> CutStage {
    for node in expected {
        if !(node.row.start < cut && cut < node.row.end) {
            continue;
        }
        if node.row.code != 3 {
            return leaf_stage(&node.row, cut);
        }
        // Inside a group frame: a partial open tag, a partial end
        // tag, a deeper story, or the group itself left unclosed.
        let open_end = node.row.start + node.row.tag_width;
        if cut < open_end {
            return CutStage::Tag { start: node.row.start };
        }
        let end_tag_at = node.row.end - node.row.delim_width;
        if cut > end_tag_at {
            return CutStage::Tag { start: end_tag_at };
        }
        return match cut_stage_tree(&node.kids, cut) {
            CutStage::Boundary => CutStage::Unclosed { field: node.row.field, at: node.row.start },
            deeper => deeper,
        };
    }
    CutStage::Boundary
}
