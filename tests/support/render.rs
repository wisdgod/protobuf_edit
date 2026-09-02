//! The `decode_raw` text simulation, shared by the corpus oracle
//! and the live-protoc harness. Every formatting rule — C-style
//! escaping, number formats, the braced container form — lives
//! here once; the renderer comes in two copies only because the
//! dialects' `Tree` types are distinct.

use std::fmt::Write as _;

/// protoc's C-style escaping for blob presentation: named escapes
/// (quote, apostrophe, backslash, LF, CR, TAB), printable-ASCII
/// passthrough, three-digit octal for everything else — byte-level,
/// never UTF-8-aware. Every arm is corpus-pinned by the
/// `len_escape_*` cases.
pub fn c_escape(bytes: &[u8]) -> String {
    let mut s = String::new();
    for &b in bytes {
        match b {
            b'"' => s.push_str("\\\""),
            b'\'' => s.push_str("\\'"),
            b'\\' => s.push_str("\\\\"),
            b'\n' => s.push_str("\\n"),
            b'\r' => s.push_str("\\r"),
            b'\t' => s.push_str("\\t"),
            0x20..=0x7E => s.push(b as char),
            _ => {
                let _ = write!(s, "\\{b:03o}");
            }
        }
    }
    s
}

#[cfg(feature = "inspect-grouped")]
pub mod grouped {
    use protobuf_edit::inspect::NodeId;
    use protobuf_edit::inspect::grouped::Tree;
    use protobuf_edit::wire::grouped::RecordKind;

    use super::c_escape;

    #[track_caller]
    pub fn render(tree: &Tree<'_>) -> String {
        let items: Vec<String> = tree.top().map(|id| record(tree, id)).collect();
        items.join(" ")
    }

    #[track_caller]
    fn record(tree: &Tree<'_>, id: NodeId) -> String {
        let field = tree.field(id).as_inner();
        match tree.kind(id) {
            RecordKind::Varint => format!("{field}: {}", tree.varint_word(id).unwrap()),
            RecordKind::I32 => format!("{field}: 0x{:08x}", tree.i32_bits(id).unwrap()),
            RecordKind::I64 => format!("{field}: 0x{:016x}", tree.i64_bits(id).unwrap()),
            RecordKind::Group => braced(field, tree, id),
            RecordKind::Len => {
                if tree.children(id).next().is_some() {
                    braced(field, tree, id)
                } else {
                    format!("{field}: \"{}\"", c_escape(tree.payload_bytes(id)))
                }
            }
        }
    }

    #[track_caller]
    fn braced(field: u32, tree: &Tree<'_>, id: NodeId) -> String {
        let children: Vec<String> = tree.children(id).map(|c| record(tree, c)).collect();
        if children.is_empty() {
            format!("{field} {{ }}")
        } else {
            format!("{field} {{ {} }}", children.join(" "))
        }
    }
}

#[cfg(feature = "inspect-groupless")]
pub mod groupless {
    use protobuf_edit::inspect::NodeId;
    use protobuf_edit::inspect::groupless::Tree;
    use protobuf_edit::wire::groupless::RecordKind;

    use super::c_escape;

    #[track_caller]
    pub fn render(tree: &Tree<'_>) -> String {
        let items: Vec<String> = tree.top().map(|id| record(tree, id)).collect();
        items.join(" ")
    }

    #[track_caller]
    fn record(tree: &Tree<'_>, id: NodeId) -> String {
        let field = tree.field(id).as_inner();
        match tree.kind(id) {
            RecordKind::Varint => format!("{field}: {}", tree.varint_word(id).unwrap()),
            RecordKind::I32 => format!("{field}: 0x{:08x}", tree.i32_bits(id).unwrap()),
            RecordKind::I64 => format!("{field}: 0x{:016x}", tree.i64_bits(id).unwrap()),
            RecordKind::Len => {
                let children: Vec<String> = tree.children(id).map(|c| record(tree, c)).collect();
                if !children.is_empty() {
                    format!("{field} {{ {} }}", children.join(" "))
                } else {
                    format!("{field}: \"{}\"", c_escape(tree.payload_bytes(id)))
                }
            }
        }
    }
}
