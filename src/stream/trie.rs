use crate::error::TreeError;
use crate::wire::Tag;

const TERMINAL_BIT: u16 = 1 << 15;
const COUNT_MASK: u16 = TERMINAL_BIT - 1;

/// Per-node lookup metadata: edge range start plus terminal/edge-count bits.
#[derive(Clone, Copy)]
pub(super) struct NodeEntry {
    edge_start: u16,
    /// bit15 = terminal (a complete path ends here), low 15 bits = outgoing edge count.
    meta: u16,
}

impl NodeEntry {
    const EMPTY: Self = Self { edge_start: 0, meta: 0 };
}

/// Borrowed view over a compiled trie; all queries are O(out-degree).
#[derive(Clone, Copy)]
pub(super) struct PathTrieRef {
    nodes: &'static [NodeEntry],
    edge_tag: &'static [u32],
    edge_to: &'static [u16],
}

/// Result of following one tag edge.
#[derive(Clone, Copy)]
pub(super) struct TrieStep {
    pub(super) node: u16,
    pub(super) terminal: bool,
    pub(super) has_children: bool,
}

impl PathTrieRef {
    /// Follows the `tag` edge out of `node`.
    ///
    /// Returns `None` when `node` is out of range (including the
    /// `NO_TRIE_NODE` sentinel) or has no edge labeled `tag`.
    #[inline]
    pub(super) fn step(self, node: u16, tag: Tag) -> Option<TrieStep> {
        let entry = *self.nodes.get(node as usize)?;
        let start = entry.edge_start as usize;
        let end = start + (entry.meta & COUNT_MASK) as usize;
        let raw = tag.get();

        let mut i = start;
        while i < end {
            if self.edge_tag[i] == raw {
                let to = self.edge_to[i];
                let target = self.nodes[to as usize];
                return Some(TrieStep {
                    node: to,
                    terminal: target.meta & TERMINAL_BIT != 0,
                    has_children: target.meta & COUNT_MASK != 0,
                });
            }
            i += 1;
        }
        None
    }
}

pub(super) const EMPTY_TRIE: PathTrieRef = PathTrieRef { nodes: &[], edge_tag: &[], edge_to: &[] };

/// Compile-time path trie storage.
///
/// `MAX_EDGES` counts only real tag transitions; terminal markers are free.
pub struct CompiledPathTrie<const MAX_NODES: usize, const MAX_EDGES: usize> {
    nodes: [NodeEntry; MAX_NODES],
    edge_tag: [u32; MAX_EDGES],
    edge_to: [u16; MAX_EDGES],
    node_count: u16,
    edge_count: u16,
}

impl<const MAX_NODES: usize, const MAX_EDGES: usize> CompiledPathTrie<MAX_NODES, MAX_EDGES> {
    pub const fn build(paths: &[&[Tag]]) -> Result<Self, TreeError> {
        if MAX_NODES == 0 {
            return Err(TreeError::CapacityExceeded);
        }
        if MAX_NODES > (u16::MAX as usize) {
            return Err(TreeError::CapacityExceeded);
        }
        if MAX_EDGES > (COUNT_MASK as usize) {
            return Err(TreeError::CapacityExceeded);
        }

        let mut out = Self {
            nodes: [NodeEntry::EMPTY; MAX_NODES],
            edge_tag: [0; MAX_EDGES],
            edge_to: [0; MAX_EDGES],
            node_count: 1,
            edge_count: 0,
        };
        // Insertion-order edge sources; consumed by the sort pass below.
        let mut edge_from = [0u16; MAX_EDGES];

        let mut path_idx = 0usize;
        while path_idx < paths.len() {
            let path = paths[path_idx];
            if path.is_empty() {
                return Err(TreeError::DecodeError);
            }

            let mut node = 0u16;
            let mut hop_idx = 0usize;
            while hop_idx < path.len() {
                let tag = path[hop_idx].get();

                let mut found = u16::MAX;
                let mut i = 0usize;
                while i < out.edge_count as usize {
                    if edge_from[i] == node && out.edge_tag[i] == tag {
                        found = out.edge_to[i];
                        break;
                    }
                    i += 1;
                }

                if found != u16::MAX {
                    node = found;
                } else {
                    if (out.node_count as usize) >= MAX_NODES {
                        return Err(TreeError::CapacityExceeded);
                    }
                    if (out.edge_count as usize) >= MAX_EDGES {
                        return Err(TreeError::CapacityExceeded);
                    }

                    let next = out.node_count;
                    out.node_count += 1;

                    let e = out.edge_count as usize;
                    edge_from[e] = node;
                    out.edge_tag[e] = tag;
                    out.edge_to[e] = next;
                    out.edge_count += 1;

                    node = next;
                }
                hop_idx += 1;
            }

            out.nodes[node as usize].meta |= TERMINAL_BIT;
            path_idx += 1;
        }

        // Insertion sort of the parallel edge arrays keyed by source node, so
        // each node owns one contiguous edge range.
        let edge_count = out.edge_count as usize;
        let mut i = 1usize;
        while i < edge_count {
            let key_from = edge_from[i];
            let key_tag = out.edge_tag[i];
            let key_to = out.edge_to[i];
            let mut j = i;
            while j > 0 && edge_from[j - 1] > key_from {
                edge_from[j] = edge_from[j - 1];
                out.edge_tag[j] = out.edge_tag[j - 1];
                out.edge_to[j] = out.edge_to[j - 1];
                j -= 1;
            }
            edge_from[j] = key_from;
            out.edge_tag[j] = key_tag;
            out.edge_to[j] = key_to;
            i += 1;
        }

        // Per-node edge ranges from the sorted array.
        let mut i = 0usize;
        while i < edge_count {
            let from = edge_from[i] as usize;
            let mut end = i + 1;
            while end < edge_count && edge_from[end] as usize == from {
                end += 1;
            }
            let count = (end - i) as u16;
            debug_assert!(count <= COUNT_MASK);
            out.nodes[from].edge_start = i as u16;
            out.nodes[from].meta |= count;
            i = end;
        }

        Ok(out)
    }

    #[inline]
    pub(super) const fn as_ref(&'static self) -> PathTrieRef {
        PathTrieRef { nodes: &self.nodes, edge_tag: &self.edge_tag, edge_to: &self.edge_to }
    }
}
