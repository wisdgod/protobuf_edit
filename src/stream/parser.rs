use alloc::vec;
use alloc::vec::Vec;
use core::intrinsics::unlikely;

use crate::document::TreeError;
use crate::wire::{Tag, WireType};

use super::decode::{decode_tag_prefix, decode_varint32_prefix, decode_varint64_prefix};
#[cfg(feature = "group")]
use super::group::scan_group_progress_stateful;
use super::handler::WireHandler;
#[cfg(feature = "group")]
use super::state::GroupProgress;
use super::state::{InflightField, StreamState, MAX_DECODE_DEPTH, NO_TRIE_NODE};
use super::trie::{CompiledPathTrie, PathTrieRef, EMPTY_TRIE};

/// Stateful incremental parser over byte chunks.
pub struct ChunkStream {
    states: Vec<StreamState>,
    matcher: PathTrieRef,
    emit_partial_matches: bool,
}

impl Default for ChunkStream {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl ChunkStream {
    #[inline]
    pub fn new() -> Self {
        Self { states: vec![StreamState::root()], matcher: EMPTY_TRIE, emit_partial_matches: false }
    }

    #[inline]
    pub fn with_trie<const MAX_NODES: usize, const MAX_EDGES: usize>(
        trie: &'static CompiledPathTrie<MAX_NODES, MAX_EDGES>,
    ) -> Self {
        Self {
            states: vec![StreamState::root()],
            matcher: trie.as_ref(),
            emit_partial_matches: false,
        }
    }

    #[inline]
    pub fn set_trie<const MAX_NODES: usize, const MAX_EDGES: usize>(
        &mut self,
        trie: &'static CompiledPathTrie<MAX_NODES, MAX_EDGES>,
    ) {
        self.matcher = trie.as_ref();
        self.reset();
    }

    #[inline]
    pub fn clear_trie(&mut self) {
        self.matcher = EMPTY_TRIE;
        self.reset();
    }

    #[inline]
    pub fn set_emit_partial_matches(&mut self, enabled: bool) {
        self.emit_partial_matches = enabled;
    }

    #[inline]
    pub fn reset(&mut self) {
        self.states.truncate(1);
        self.states[0].reset();
    }

    #[inline]
    pub fn offset(&self) -> u64 {
        self.states[0].offset
    }

    pub fn feed<H: WireHandler + ?Sized>(
        &mut self,
        chunk: &[u8],
        handler: &mut H,
    ) -> Result<(), TreeError> {
        self.feed_state(0, chunk, handler)
    }

    #[inline]
    pub fn finish(&self) -> Result<(), TreeError> {
        if self.states.len() != 1 {
            return Err(TreeError::DecodeError);
        }
        self.finish_state(0)
    }

    fn feed_state<H: WireHandler + ?Sized>(
        &mut self,
        state_idx: usize,
        chunk: &[u8],
        handler: &mut H,
    ) -> Result<(), TreeError> {
        if chunk.is_empty() {
            return Ok(());
        }
        self.states[state_idx].pending.extend_from_slice(chunk)?;
        self.parse_with_work(state_idx, handler)
    }

    fn parse_with_work<H: WireHandler + ?Sized>(
        &mut self,
        root_state_idx: usize,
        handler: &mut H,
    ) -> Result<(), TreeError> {
        // Work-stack lets parent/child states make progress incrementally.
        let mut work = Vec::<usize>::new();
        self.schedule_state(&mut work, root_state_idx)?;

        while let Some(state_idx) = work.pop() {
            if state_idx >= self.states.len() {
                continue;
            }
            self.parse_pending_state(state_idx, &mut work, handler)?;
        }

        Ok(())
    }

    fn schedule_state(&self, work: &mut Vec<usize>, state_idx: usize) -> Result<(), TreeError> {
        work.try_reserve(1).map_err(|_| TreeError::CapacityExceeded)?;
        work.push(state_idx);
        Ok(())
    }

    fn parse_pending_state<H: WireHandler + ?Sized>(
        &mut self,
        state_idx: usize,
        work: &mut Vec<usize>,
        handler: &mut H,
    ) -> Result<(), TreeError> {
        let mut consumed = 0usize;

        loop {
            let data_len = self.state_data(state_idx, consumed)?.len();
            if data_len == 0 {
                break;
            }

            // Inflight tracks partially read Len/Group fields across chunk boundaries.
            if let Some(inflight) = self.states[state_idx].inflight.take() {
                match inflight {
                    InflightField::Len {
                        tag,
                        emit_self,
                        header_len,
                        payload_len,
                        payload_len_usize,
                        mut emitted,
                        child,
                    } => {
                        if unlikely(header_len > data_len) {
                            return Err(TreeError::DecodeError);
                        }

                        let available = (data_len - header_len).min(payload_len_usize);
                        let mut appended_to_child = false;
                        if available > emitted {
                            if let Some(child_idx) = child {
                                let delta_start = consumed
                                    .checked_add(header_len)
                                    .and_then(|n| n.checked_add(emitted))
                                    .ok_or(TreeError::CapacityExceeded)?;
                                let delta_end = consumed
                                    .checked_add(header_len)
                                    .and_then(|n| n.checked_add(available))
                                    .ok_or(TreeError::CapacityExceeded)?;
                                self.append_parent_range_to_child(
                                    state_idx,
                                    child_idx,
                                    delta_start,
                                    delta_end,
                                )?;
                                self.schedule_state(work, child_idx)?;
                                appended_to_child = true;
                            }

                            if emit_self
                                && self.emit_partial_matches
                                && available < payload_len_usize
                            {
                                self.push_path_tag(state_idx, tag);
                                let cb = {
                                    let state = &self.states[state_idx];
                                    let data =
                                        &state.pending.as_slice()[state.read_head + consumed..];
                                    handler.on_length_delimited(
                                        state.path.as_slice(),
                                        &data[header_len..header_len + available],
                                        payload_len,
                                        false,
                                    )
                                };
                                self.pop_path_tag(state_idx);
                                cb?;
                            }
                            emitted = available;
                        }

                        if available == payload_len_usize {
                            if let Some(child_idx) = child {
                                if appended_to_child {
                                    self.states[state_idx].inflight = Some(InflightField::Len {
                                        tag,
                                        emit_self,
                                        header_len,
                                        payload_len,
                                        payload_len_usize,
                                        emitted,
                                        child,
                                    });
                                    self.schedule_state(work, state_idx)?;
                                    self.schedule_state(work, child_idx)?;
                                    break;
                                }
                                self.finish_state(child_idx)?;
                                self.drop_child_state(child_idx)?;
                            }
                            if emit_self {
                                self.push_path_tag(state_idx, tag);
                                let cb = {
                                    let state = &self.states[state_idx];
                                    let data =
                                        &state.pending.as_slice()[state.read_head + consumed..];
                                    handler.on_length_delimited(
                                        state.path.as_slice(),
                                        &data[header_len..header_len + payload_len_usize],
                                        payload_len,
                                        true,
                                    )
                                };
                                self.pop_path_tag(state_idx);
                                cb?;
                            }

                            let field_len = header_len
                                .checked_add(payload_len_usize)
                                .ok_or(TreeError::CapacityExceeded)?;
                            consumed = consumed
                                .checked_add(field_len)
                                .ok_or(TreeError::CapacityExceeded)?;
                            continue;
                        }

                        self.states[state_idx].inflight = Some(InflightField::Len {
                            tag,
                            emit_self,
                            header_len,
                            payload_len,
                            payload_len_usize,
                            emitted,
                            child,
                        });
                        break;
                    }
                    #[cfg(feature = "group")]
                    InflightField::Group {
                        tag,
                        emit_self,
                        header_len,
                        mut emitted,
                        child,
                        mut scan_offset,
                        mut scan_stack,
                    } => {
                        let progress = {
                            let data = self.state_data(state_idx, consumed)?;
                            scan_group_progress_stateful(
                                data,
                                &mut scan_offset,
                                &mut scan_stack,
                                tag.field_number(),
                            )?
                        };

                        match progress {
                            GroupProgress::Incomplete { known_payload_end } => {
                                if unlikely(
                                    known_payload_end < header_len || known_payload_end > data_len,
                                ) {
                                    return Err(TreeError::DecodeError);
                                }

                                let known_payload_len = known_payload_end - header_len;
                                if known_payload_len > emitted {
                                    if let Some(child_idx) = child {
                                        let delta_start = consumed
                                            .checked_add(header_len)
                                            .and_then(|n| n.checked_add(emitted))
                                            .ok_or(TreeError::CapacityExceeded)?;
                                        let delta_end = consumed
                                            .checked_add(header_len)
                                            .and_then(|n| n.checked_add(known_payload_len))
                                            .ok_or(TreeError::CapacityExceeded)?;
                                        self.append_parent_range_to_child(
                                            state_idx,
                                            child_idx,
                                            delta_start,
                                            delta_end,
                                        )?;
                                        self.schedule_state(work, child_idx)?;
                                    }

                                    if emit_self && self.emit_partial_matches {
                                        self.push_path_tag(state_idx, tag);
                                        let cb = {
                                            let state = &self.states[state_idx];
                                            let data = &state.pending.as_slice()
                                                [state.read_head + consumed..];
                                            handler.on_group(
                                                state.path.as_slice(),
                                                &data[header_len..known_payload_end],
                                                false,
                                            )
                                        };
                                        self.pop_path_tag(state_idx);
                                        cb?;
                                    }
                                    emitted = known_payload_len;
                                }

                                self.states[state_idx].inflight = Some(InflightField::Group {
                                    tag,
                                    emit_self,
                                    header_len,
                                    emitted,
                                    child,
                                    scan_offset,
                                    scan_stack,
                                });
                                break;
                            }
                            GroupProgress::Complete { end_start, end_after } => {
                                if unlikely(end_start < header_len || end_after > data_len) {
                                    return Err(TreeError::DecodeError);
                                }

                                let payload_len = end_start - header_len;
                                let mut appended_to_child = false;
                                if payload_len > emitted
                                    && let Some(child_idx) = child
                                {
                                    let delta_start = consumed
                                        .checked_add(header_len)
                                        .and_then(|n| n.checked_add(emitted))
                                        .ok_or(TreeError::CapacityExceeded)?;
                                    let delta_end = consumed
                                        .checked_add(header_len)
                                        .and_then(|n| n.checked_add(payload_len))
                                        .ok_or(TreeError::CapacityExceeded)?;
                                    self.append_parent_range_to_child(
                                        state_idx,
                                        child_idx,
                                        delta_start,
                                        delta_end,
                                    )?;
                                    self.schedule_state(work, child_idx)?;
                                    appended_to_child = true;
                                }

                                if let Some(child_idx) = child {
                                    if appended_to_child {
                                        self.states[state_idx].inflight =
                                            Some(InflightField::GroupCompletePending {
                                                tag,
                                                emit_self,
                                                header_len,
                                                end_start,
                                                end_after,
                                                child,
                                            });
                                        self.schedule_state(work, state_idx)?;
                                        self.schedule_state(work, child_idx)?;
                                        break;
                                    }
                                    self.finish_state(child_idx)?;
                                    self.drop_child_state(child_idx)?;
                                }

                                if emit_self {
                                    self.push_path_tag(state_idx, tag);
                                    let cb = {
                                        let state = &self.states[state_idx];
                                        let data =
                                            &state.pending.as_slice()[state.read_head + consumed..];
                                        handler.on_group(
                                            state.path.as_slice(),
                                            &data[header_len..end_start],
                                            true,
                                        )
                                    };
                                    self.pop_path_tag(state_idx);
                                    cb?;
                                }

                                consumed = consumed
                                    .checked_add(end_after)
                                    .ok_or(TreeError::CapacityExceeded)?;
                                continue;
                            }
                        }
                    }
                    #[cfg(feature = "group")]
                    InflightField::GroupCompletePending {
                        tag,
                        emit_self,
                        header_len,
                        end_start,
                        end_after,
                        child,
                    } => {
                        if let Some(child_idx) = child {
                            self.finish_state(child_idx)?;
                            self.drop_child_state(child_idx)?;
                        }

                        if emit_self {
                            self.push_path_tag(state_idx, tag);
                            let cb = {
                                let state = &self.states[state_idx];
                                let data = &state.pending.as_slice()[state.read_head + consumed..];
                                handler.on_group(
                                    state.path.as_slice(),
                                    &data[header_len..end_start],
                                    true,
                                )
                            };
                            self.pop_path_tag(state_idx);
                            cb?;
                        }

                        consumed =
                            consumed.checked_add(end_after).ok_or(TreeError::CapacityExceeded)?;
                        continue;
                    }
                }
            }

            let Some((tag, tag_len)) = decode_tag_prefix(self.state_data(state_idx, consumed)?)?
            else {
                break;
            };

            let trie_node = self.states[state_idx].trie_node;
            let next_node =
                if trie_node == NO_TRIE_NODE { None } else { self.matcher.next(trie_node, tag) };
            let emit_self = next_node.is_some_and(|node| self.matcher.is_terminal(node));
            let child_node = next_node.filter(|&node| self.matcher.has_children(node));

            match tag.wire_type() {
                WireType::Varint => {
                    let data = self.state_data(state_idx, consumed)?;
                    let value_data = &data[tag_len..];
                    let Some((value, value_len)) = decode_varint64_prefix(value_data)? else {
                        break;
                    };

                    if emit_self {
                        self.push_path_tag(state_idx, tag);
                        let cb = {
                            let state = &self.states[state_idx];
                            handler.on_varint(state.path.as_slice(), value)
                        };
                        self.pop_path_tag(state_idx);
                        cb?;
                    }

                    consumed = consumed
                        .checked_add(tag_len)
                        .and_then(|n| n.checked_add(value_len))
                        .ok_or(TreeError::CapacityExceeded)?;
                }
                WireType::I32 => {
                    let data = self.state_data(state_idx, consumed)?;
                    let end = tag_len.checked_add(4).ok_or(TreeError::CapacityExceeded)?;
                    if data.len() < end {
                        break;
                    }
                    let mut value = [0u8; 4];
                    value.copy_from_slice(&data[tag_len..end]);

                    if emit_self {
                        self.push_path_tag(state_idx, tag);
                        let cb = {
                            let state = &self.states[state_idx];
                            handler.on_i32(state.path.as_slice(), value)
                        };
                        self.pop_path_tag(state_idx);
                        cb?;
                    }

                    consumed = consumed.checked_add(end).ok_or(TreeError::CapacityExceeded)?;
                }
                WireType::I64 => {
                    let data = self.state_data(state_idx, consumed)?;
                    let end = tag_len.checked_add(8).ok_or(TreeError::CapacityExceeded)?;
                    if data.len() < end {
                        break;
                    }
                    let mut value = [0u8; 8];
                    value.copy_from_slice(&data[tag_len..end]);

                    if emit_self {
                        self.push_path_tag(state_idx, tag);
                        let cb = {
                            let state = &self.states[state_idx];
                            handler.on_i64(state.path.as_slice(), value)
                        };
                        self.pop_path_tag(state_idx);
                        cb?;
                    }

                    consumed = consumed.checked_add(end).ok_or(TreeError::CapacityExceeded)?;
                }
                WireType::Len => {
                    let data = self.state_data(state_idx, consumed)?;
                    let len_data = &data[tag_len..];
                    let Some((payload_len, len_len)) = decode_varint32_prefix(len_data)? else {
                        break;
                    };
                    let header_len =
                        tag_len.checked_add(len_len).ok_or(TreeError::CapacityExceeded)?;
                    let payload_len_usize =
                        usize::try_from(payload_len).map_err(|_| TreeError::CapacityExceeded)?;

                    let child = if let Some(node) = child_node {
                        Some(self.push_child_state(state_idx, tag, node)?)
                    } else {
                        None
                    };

                    self.states[state_idx].inflight = Some(InflightField::Len {
                        tag,
                        emit_self,
                        header_len,
                        payload_len,
                        payload_len_usize,
                        emitted: 0,
                        child,
                    });
                }
                #[cfg(feature = "group")]
                WireType::SGroup => {
                    let child = if let Some(node) = child_node {
                        Some(self.push_child_state(state_idx, tag, node)?)
                    } else {
                        None
                    };

                    let mut scan_stack = Vec::new();
                    scan_stack.try_reserve(4).map_err(|_| TreeError::CapacityExceeded)?;

                    self.states[state_idx].inflight = Some(InflightField::Group {
                        tag,
                        emit_self,
                        header_len: tag_len,
                        emitted: 0,
                        child,
                        scan_offset: tag_len,
                        scan_stack,
                    });
                }
                #[cfg(feature = "group")]
                WireType::EGroup => return Err(TreeError::DecodeError),
            }
        }

        if consumed != 0 {
            self.consume_prefix_state(state_idx, consumed)?;
        }

        Ok(())
    }

    fn state_data(&self, state_idx: usize, consumed: usize) -> Result<&[u8], TreeError> {
        let state = &self.states[state_idx];
        let start = state.read_head.checked_add(consumed).ok_or(TreeError::CapacityExceeded)?;
        let slice = state.pending.as_slice();
        if unlikely(start > slice.len()) {
            return Err(TreeError::DecodeError);
        }
        Ok(&slice[start..])
    }

    fn consume_prefix_state(&mut self, state_idx: usize, consumed: usize) -> Result<(), TreeError> {
        let state = &mut self.states[state_idx];

        if unlikely(consumed > state.unread_len()) {
            return Err(TreeError::DecodeError);
        }

        state.offset =
            state.offset.checked_add(consumed as u64).ok_or(TreeError::CapacityExceeded)?;

        state.read_head =
            state.read_head.checked_add(consumed).ok_or(TreeError::CapacityExceeded)?;

        let total = state.pending.len() as usize;
        if state.read_head == total {
            state.pending.clear();
            state.read_head = 0;
            return Ok(());
        }

        if state.read_head >= 4096 || state.read_head * 2 >= total {
            let remaining = total - state.read_head;
            state.pending.as_mut_slice().copy_within(state.read_head..total, 0);
            state.pending.truncate(remaining as u32);
            state.read_head = 0;
        }

        Ok(())
    }

    fn push_child_state(
        &mut self,
        parent_idx: usize,
        via_tag: Tag,
        trie_node: u16,
    ) -> Result<usize, TreeError> {
        let child = {
            let parent = &self.states[parent_idx];
            let depth = parent.path.len().checked_add(1).ok_or(TreeError::CapacityExceeded)?;
            if depth > MAX_DECODE_DEPTH {
                return Err(TreeError::DecodeError);
            }
            StreamState::child(parent.path.as_slice(), via_tag, trie_node)?
        };
        self.states.push(child);
        Ok(self.states.len() - 1)
    }

    fn drop_child_state(&mut self, child_idx: usize) -> Result<(), TreeError> {
        if unlikely(child_idx + 1 != self.states.len()) {
            return Err(TreeError::DecodeError);
        }
        self.states.pop();
        Ok(())
    }

    fn finish_state(&self, state_idx: usize) -> Result<(), TreeError> {
        let state = &self.states[state_idx];
        if state.inflight.is_none() && state.unread_len() == 0 {
            Ok(())
        } else {
            Err(TreeError::DecodeError)
        }
    }

    fn append_parent_range_to_child(
        &mut self,
        parent_idx: usize,
        child_idx: usize,
        start: usize,
        end: usize,
    ) -> Result<(), TreeError> {
        if unlikely(start > end || parent_idx == child_idx) {
            return Err(TreeError::DecodeError);
        }

        if parent_idx < child_idx {
            let (left, right) = self.states.split_at_mut(child_idx);
            let parent = &left[parent_idx];
            let child = &mut right[0];

            let unread = parent.unread_len();
            if unlikely(end > unread) {
                return Err(TreeError::DecodeError);
            }

            let base = parent.read_head;
            let src = &parent.pending.as_slice()[base + start..base + end];
            child.pending.extend_from_slice(src)?;
            return Ok(());
        }

        let (left, right) = self.states.split_at_mut(parent_idx);
        let child = &mut left[child_idx];
        let parent = &right[0];

        let unread = parent.unread_len();
        if unlikely(end > unread) {
            return Err(TreeError::DecodeError);
        }

        let base = parent.read_head;
        let src = &parent.pending.as_slice()[base + start..base + end];
        child.pending.extend_from_slice(src)?;
        Ok(())
    }

    #[inline]
    fn push_path_tag(&mut self, state_idx: usize, tag: Tag) {
        self.states[state_idx].path.push(tag);
    }

    #[inline]
    fn pop_path_tag(&mut self, state_idx: usize) {
        let _ = self.states[state_idx].path.pop();
    }
}
