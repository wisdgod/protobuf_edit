use crate::document::TreeError;
use crate::wire::Tag;

#[derive(Clone, Copy)]
pub(super) struct PathTrieRef {
    edge_from: &'static [u16],
    edge_to: &'static [u16],
    edge_tag: &'static [Option<Tag>],
    edge_count: u16,
}

impl PathTrieRef {
    #[inline]
    pub(super) fn next(self, node: u16, tag: Tag) -> Option<u16> {
        let mut i = 0usize;
        let edge_count = self.edge_count as usize;
        while i < edge_count {
            if self.edge_from[i] == node
                && let Some(edge_tag) = self.edge_tag[i]
                && edge_tag.get() == tag.get()
            {
                return Some(self.edge_to[i]);
            }
            i += 1;
        }
        None
    }

    #[inline]
    pub(super) fn is_terminal(self, node: u16) -> bool {
        let mut i = 0usize;
        let edge_count = self.edge_count as usize;
        while i < edge_count {
            if self.edge_from[i] == node && self.edge_tag[i].is_none() {
                return true;
            }
            i += 1;
        }
        false
    }

    #[inline]
    pub(super) fn has_children(self, node: u16) -> bool {
        let mut i = 0usize;
        let edge_count = self.edge_count as usize;
        while i < edge_count {
            if self.edge_from[i] == node && self.edge_tag[i].is_some() {
                return true;
            }
            i += 1;
        }
        false
    }
}

const EMPTY_EDGE_U16: [u16; 0] = [];
const EMPTY_EDGE_TAG: [Option<Tag>; 0] = [];
pub(super) const EMPTY_TRIE: PathTrieRef = PathTrieRef {
    edge_from: &EMPTY_EDGE_U16,
    edge_to: &EMPTY_EDGE_U16,
    edge_tag: &EMPTY_EDGE_TAG,
    edge_count: 0,
};

pub struct CompiledPathTrie<const MAX_NODES: usize, const MAX_EDGES: usize> {
    edge_from: [u16; MAX_EDGES],
    edge_to: [u16; MAX_EDGES],
    edge_tag: [Option<Tag>; MAX_EDGES],
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
        if MAX_EDGES > (u16::MAX as usize) {
            return Err(TreeError::CapacityExceeded);
        }

        let mut out = Self {
            edge_from: [0; MAX_EDGES],
            edge_to: [0; MAX_EDGES],
            edge_tag: [None; MAX_EDGES],
            node_count: 1,
            edge_count: 0,
        };

        let mut path_idx = 0usize;
        while path_idx < paths.len() {
            let path = paths[path_idx];
            if path.is_empty() {
                return Err(TreeError::DecodeError);
            }

            let mut node = 0u16;
            let mut hop_idx = 0usize;
            while hop_idx < path.len() {
                let tag = path[hop_idx];
                if let Some(next) = out.find_child(node, tag) {
                    node = next;
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
                    out.edge_from[e] = node;
                    out.edge_to[e] = next;
                    out.edge_tag[e] = Some(tag);
                    out.edge_count += 1;

                    node = next;
                }
                hop_idx += 1;
            }

            if !out.has_terminal_suffix(node) {
                if (out.edge_count as usize) >= MAX_EDGES {
                    return Err(TreeError::CapacityExceeded);
                }

                // None-tag self-edge marks "this node is a complete path".
                let e = out.edge_count as usize;
                out.edge_from[e] = node;
                out.edge_to[e] = node;
                out.edge_tag[e] = None;
                out.edge_count += 1;
            }
            path_idx += 1;
        }

        Ok(out)
    }

    #[inline]
    pub(super) const fn as_ref(&'static self) -> PathTrieRef {
        PathTrieRef {
            edge_from: &self.edge_from,
            edge_to: &self.edge_to,
            edge_tag: &self.edge_tag,
            edge_count: self.edge_count,
        }
    }

    const fn find_child(&self, node: u16, tag: Tag) -> Option<u16> {
        let mut i = 0usize;
        let edge_count = self.edge_count as usize;
        while i < edge_count {
            if self.edge_from[i] == node
                && let Some(edge_tag) = self.edge_tag[i]
                && edge_tag.get() == tag.get()
            {
                return Some(self.edge_to[i]);
            }
            i += 1;
        }
        None
    }

    const fn has_terminal_suffix(&self, node: u16) -> bool {
        let mut i = 0usize;
        let edge_count = self.edge_count as usize;
        while i < edge_count {
            if self.edge_from[i] == node && self.edge_tag[i].is_none() {
                return true;
            }
            i += 1;
        }
        false
    }
}
