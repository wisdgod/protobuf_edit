use alloc::vec::Vec;

use crate::document::TreeError;
#[cfg(feature = "group")]
use crate::wire::FieldNumber;
use crate::wire::Tag;
use crate::Buf;

pub(super) const NO_TRIE_NODE: u16 = u16::MAX;
pub(super) const MAX_DECODE_DEPTH: usize = 100;

pub(super) enum InflightField {
    Len {
        tag: Tag,
        emit_self: bool,
        header_len: usize,
        payload_len: u32,
        payload_len_usize: usize,
        emitted: usize,
        child: Option<usize>,
    },
    #[cfg(feature = "group")]
    Group {
        tag: Tag,
        emit_self: bool,
        header_len: usize,
        emitted: usize,
        child: Option<usize>,
        scan_offset: usize,
        scan_stack: Vec<FieldNumber>,
    },
    #[cfg(feature = "group")]
    GroupCompletePending {
        tag: Tag,
        emit_self: bool,
        header_len: usize,
        end_start: usize,
        end_after: usize,
        child: Option<usize>,
    },
}

#[cfg(feature = "group")]
pub(super) enum GroupProgress {
    Incomplete { known_payload_end: usize },
    Complete { end_start: usize, end_after: usize },
}

pub(super) struct StreamState {
    pub(super) pending: Buf,
    pub(super) read_head: usize,
    pub(super) inflight: Option<InflightField>,
    pub(super) offset: u64,
    pub(super) path: Vec<Tag>,
    pub(super) trie_node: u16,
}

impl StreamState {
    #[inline]
    pub(super) fn root() -> Self {
        Self {
            pending: Buf::new(),
            read_head: 0,
            inflight: None,
            offset: 0,
            path: Vec::new(),
            trie_node: 0,
        }
    }

    #[inline]
    pub(super) fn child(
        parent_path: &[Tag],
        via_tag: Tag,
        trie_node: u16,
    ) -> Result<Self, TreeError> {
        let cap = parent_path.len().checked_add(1).ok_or(TreeError::CapacityExceeded)?;
        let mut path = Vec::new();
        path.try_reserve(cap).map_err(|_| TreeError::CapacityExceeded)?;
        path.extend_from_slice(parent_path);
        path.push(via_tag);
        Ok(Self { pending: Buf::new(), read_head: 0, inflight: None, offset: 0, path, trie_node })
    }

    #[inline]
    pub(super) fn reset(&mut self) {
        self.pending.clear();
        self.read_head = 0;
        self.inflight = None;
        self.offset = 0;
        self.path.clear();
        self.trie_node = 0;
    }

    #[inline]
    pub(super) fn unread_len(&self) -> usize {
        self.pending.len() as usize - self.read_head
    }
}
