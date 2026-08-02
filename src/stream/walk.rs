//! Frame-stack wire walker shared by `Scanner` (one-shot) and `ChunkStream` (incremental).
//!
//! Model:
//! - complete data is the base case: fields whose bytes are fully available are
//!   emitted by borrowing from the input slice, with zero copying
//! - chunked input is the exception: only two things are ever buffered, the
//!   sub-unit fragment that straddles a chunk boundary (`tail`, < 15 bytes) and
//!   the bodies of terminal-matched fields that straddle a boundary (`rec`)
//! - nesting is a stack of frames over one logical byte stream; a frame is
//!   either byte-counted (`Len`) or terminated by a matching end-group tag

use alloc::vec::Vec;

use crate::buf::Buf;
use crate::error::TreeError;
use crate::wire::{Tag, WireType};

use super::decode::{decode_tag_prefix, decode_varint32_prefix, decode_varint64_prefix};
use super::handler::WireHandler;
use super::trie::{CompiledPathTrie, PathTrieRef, EMPTY_TRIE};

pub(super) const MAX_DECODE_DEPTH: usize = 100;

/// Trie sentinel for frames with no interesting descendants.
///
/// `CompiledPathTrie::build` caps node count at `u16::MAX - 1`, so this index
/// never resolves and every `step` from it returns `None`.
const DEAD_NODE: u16 = u16::MAX;

/// Upper bound of one header unit: tag varint (5) + value/len varint (10).
const MAX_UNIT: usize = 15;

/// One parsed field header plus any inline scalar value.
struct Unit {
    tag: Tag,
    kind: UnitKind,
}

enum UnitKind {
    Varint(u64),
    I32([u8; 4]),
    I64([u8; 8]),
    Len(u32),
    #[cfg(feature = "group")]
    GroupStart,
    #[cfg(feature = "group")]
    GroupEnd,
}

/// One open nesting level (a Len payload or a group body being walked).
struct Frame {
    tag: Tag,
    /// Trie position inside this frame; `DEAD_NODE` when nothing matches below.
    trie_node: u16,
    /// Emit the full body when this frame closes.
    terminal: bool,
    /// `Some(n)`: Len frame with `n` payload bytes left. `None`: group frame.
    remaining: Option<u32>,
    /// Consume payload bytes without parsing them (leaf payload or plain skip).
    opaque: bool,
    /// Fast path: body start offset in the current input slice. Never survives
    /// a `run` call; converted to `rec` on suspension.
    emit_start: Option<usize>,
    /// Slow path: body bytes accumulated across previous calls.
    rec: Option<Buf>,
    /// Offset in the current input slice where this frame's unseen body begins.
    seen_start: usize,
}

/// Resumable frame-stack walker over protobuf wire bytes.
pub(super) struct Walker {
    matcher: PathTrieRef,
    emit_partial: bool,
    frames: Vec<Frame>,
    /// Tags of all open frames, in order; `path[i] == frames[i].tag`.
    path: Vec<Tag>,
    /// Fragment of a header unit split across the previous chunk boundary.
    tail: Buf,
}

impl Walker {
    pub(super) const fn new(matcher: PathTrieRef) -> Self {
        Self {
            matcher,
            emit_partial: false,
            frames: Vec::new(),
            path: Vec::new(),
            tail: Buf::new(),
        }
    }

    pub(super) const fn set_matcher(&mut self, matcher: PathTrieRef) {
        self.matcher = matcher;
    }

    pub(super) const fn set_emit_partial(&mut self, enabled: bool) {
        self.emit_partial = enabled;
    }

    /// Whether no field is currently open or partially buffered.
    pub(super) const fn is_clean(&self) -> bool {
        self.frames.is_empty() && self.tail.is_empty()
    }

    /// Bytes of the boundary-straddling header fragment currently buffered.
    pub(super) const fn tail_len(&self) -> u32 {
        self.tail.len()
    }

    pub(super) fn reset(&mut self) {
        self.frames.clear();
        self.path.clear();
        self.tail.clear();
    }

    /// Parses as much of `data` as possible, emitting matched fields.
    ///
    /// With `complete == true` the input must hold whole fields up to the end;
    /// truncation is an error and nothing is buffered. With
    /// `complete == false` unfinished state is carried into the next call.
    /// Returns the number of structurally consumed bytes (bytes absorbed into
    /// `tail` are counted once their unit completes).
    pub(super) fn run<H: WireHandler + ?Sized>(
        &mut self,
        data: &[u8],
        complete: bool,
        handler: &mut H,
    ) -> Result<usize, TreeError> {
        for f in &mut self.frames {
            debug_assert!(f.emit_start.is_none());
            f.seen_start = 0;
        }

        let mut pos = 0usize;

        if !self.tail.is_empty() {
            match self.resume_tail(data, complete, handler)? {
                Some(next) => pos = next,
                None => return Ok(0),
            }
        }

        loop {
            // Close Len frames whose payload is fully consumed.
            while self.frames.last().is_some_and(|f| f.remaining == Some(0)) {
                self.pop_frame(data, pos, handler)?;
            }

            // Innermost opaque frame swallows raw payload bytes.
            let opaque_take = match self.frames.last() {
                Some(f) if f.opaque => {
                    let rem = f.remaining.expect("opaque frames are always byte-counted");
                    Some((rem as usize).min(data.len() - pos))
                }
                _ => None,
            };
            if let Some(take) = opaque_take {
                self.consume(take, pos)?;
                pos += take;
                if self.frames.last().is_some_and(|f| f.remaining == Some(0)) {
                    continue;
                }
                break;
            }

            if pos == data.len() {
                break;
            }

            let Some((unit, unit_len)) =
                parse_unit(&data[pos..], complete).map_err(|e| e.offset_by(pos))?
            else {
                debug_assert!(!complete);
                // Sub-unit fragment (< MAX_UNIT bytes) waits for the next chunk.
                self.tail
                    .extend_from_slice(&data[pos..])
                    .map_err(|_| TreeError::CapacityExceeded)?;
                break;
            };

            self.consume(unit_len, pos)?;
            #[cfg(feature = "group")]
            {
                pos = self.dispatch(data, pos + unit_len, &unit, unit_len, handler)?;
            }
            #[cfg(not(feature = "group"))]
            {
                pos = self.dispatch(data, pos + unit_len, &unit, handler)?;
            }
        }

        if complete {
            if !self.frames.is_empty() || !self.tail.is_empty() {
                return Err(TreeError::Truncated);
            }
            return Ok(pos);
        }

        self.suspend(data, pos, handler)?;
        Ok(pos)
    }

    /// Completes the header unit whose first bytes were buffered in `tail`.
    ///
    /// Returns the `data` offset to continue from, or `None` when all of
    /// `data` was absorbed and the unit is still incomplete.
    fn resume_tail<H: WireHandler + ?Sized>(
        &mut self,
        data: &[u8],
        complete: bool,
        handler: &mut H,
    ) -> Result<Option<usize>, TreeError> {
        let old_len = self.tail.len() as usize;
        debug_assert!(old_len > 0 && old_len < MAX_UNIT);

        let mut concat = [0u8; MAX_UNIT];
        concat[..old_len].copy_from_slice(self.tail.as_slice());
        let extra = (MAX_UNIT - old_len).min(data.len());
        concat[old_len..old_len + extra].copy_from_slice(&data[..extra]);

        let Some((unit, unit_len)) = parse_unit(&concat[..old_len + extra], complete)? else {
            debug_assert!(!complete);
            // MAX_UNIT bytes always resolve a unit, so `None` means `data` ran out.
            debug_assert_eq!(extra, data.len());
            self.tail.extend_from_slice(&data[..extra]).map_err(|_| TreeError::CapacityExceeded)?;
            return Ok(None);
        };
        debug_assert!(unit_len > old_len, "the buffered fragment alone could not parse");
        let from_data = unit_len - old_len;

        // The fragment is consumed now; it belongs to the recorded body of
        // every frame the unit is nested in. An end-group tag closes the
        // innermost frame, so its bytes lie outside that frame's own body.
        #[cfg(feature = "group")]
        let enclosing = match unit.kind {
            UnitKind::GroupEnd => self.frames.len().saturating_sub(1),
            _ => self.frames.len(),
        };
        #[cfg(not(feature = "group"))]
        let enclosing = self.frames.len();
        for f in &mut self.frames[..enclosing] {
            if let Some(rec) = f.rec.as_mut() {
                rec.extend_from_slice(&concat[..old_len])
                    .map_err(|_| TreeError::CapacityExceeded)?;
            }
        }
        self.tail.clear();

        // The unit began in a previous chunk; report boundary errors at the
        // start of the current input.
        self.consume(unit_len, 0)?;
        #[cfg(feature = "group")]
        let next = self.dispatch(data, from_data, &unit, unit_len, handler)?;
        #[cfg(not(feature = "group"))]
        let next = self.dispatch(data, from_data, &unit, handler)?;
        Ok(Some(next))
    }

    /// Applies one parsed unit; `next_pos` is the offset right after it and
    /// `hdr_len` (group builds only) its full header length, which may exceed
    /// `next_pos` when the header was resumed from `tail`. Returns the offset
    /// parsing continues from.
    fn dispatch<H: WireHandler + ?Sized>(
        &mut self,
        data: &[u8],
        next_pos: usize,
        unit: &Unit,
        #[cfg(feature = "group")] hdr_len: usize,
        handler: &mut H,
    ) -> Result<usize, TreeError> {
        let tag = unit.tag;
        let node = self.frames.last().map_or(0, |f| f.trie_node);
        let step = self.matcher.step(node, tag);
        let terminal = step.is_some_and(|s| s.terminal);
        let has_children = step.is_some_and(|s| s.has_children);

        match unit.kind {
            UnitKind::Varint(value) => {
                if terminal {
                    self.with_path_tag(tag, |path| handler.on_varint(path, value))?;
                }
                Ok(next_pos)
            }
            UnitKind::I32(value) => {
                if terminal {
                    self.with_path_tag(tag, |path| handler.on_i32(path, value))?;
                }
                Ok(next_pos)
            }
            UnitKind::I64(value) => {
                if terminal {
                    self.with_path_tag(tag, |path| handler.on_i64(path, value))?;
                }
                Ok(next_pos)
            }
            UnitKind::Len(len) => {
                let len_usize = usize::try_from(len).map_err(|_| TreeError::CapacityExceeded)?;
                let fully_available = data.len() - next_pos >= len_usize;

                if !terminal && !has_children {
                    // Uninteresting payload: skip wholesale, never parse inside.
                    if fully_available {
                        self.consume(len_usize, next_pos)?;
                        return Ok(next_pos + len_usize);
                    }
                    self.push_frame(Frame {
                        tag,
                        trie_node: DEAD_NODE,
                        terminal: false,
                        remaining: Some(len),
                        opaque: true,
                        emit_start: None,
                        rec: None,
                        seen_start: next_pos,
                    })?;
                    return Ok(next_pos);
                }

                if terminal && !has_children {
                    // Leaf payload: opaque bytes, emitted whole.
                    if fully_available {
                        self.consume(len_usize, next_pos)?;
                        let body = &data[next_pos..next_pos + len_usize];
                        self.with_path_tag(tag, |path| {
                            handler.on_length_delimited(path, body, len, true)
                        })?;
                        return Ok(next_pos + len_usize);
                    }
                    self.push_frame(Frame {
                        tag,
                        trie_node: DEAD_NODE,
                        terminal: true,
                        remaining: Some(len),
                        opaque: true,
                        emit_start: Some(next_pos),
                        rec: None,
                        seen_start: next_pos,
                    })?;
                    return Ok(next_pos);
                }

                // Interesting subtree: parse fields inside the payload.
                self.push_frame(Frame {
                    tag,
                    trie_node: step.expect("has_children implies a trie step").node,
                    terminal,
                    remaining: Some(len),
                    opaque: false,
                    emit_start: terminal.then_some(next_pos),
                    rec: None,
                    seen_start: next_pos,
                })?;
                Ok(next_pos)
            }
            #[cfg(feature = "group")]
            UnitKind::GroupStart => {
                // Groups have no length prefix; walk the body structurally even
                // when nothing inside can match.
                self.push_frame(Frame {
                    tag,
                    trie_node: match step {
                        Some(s) if s.has_children => s.node,
                        _ => DEAD_NODE,
                    },
                    terminal,
                    remaining: None,
                    opaque: false,
                    emit_start: terminal.then_some(next_pos),
                    rec: None,
                    seen_start: next_pos,
                })?;
                Ok(next_pos)
            }
            #[cfg(feature = "group")]
            UnitKind::GroupEnd => {
                let matches = self.frames.last().is_some_and(|f| {
                    f.remaining.is_none() && f.tag.field_number() == tag.field_number()
                });
                if !matches {
                    return Err(TreeError::malformed_at(next_pos.saturating_sub(hdr_len)));
                }
                // The body ends where this end-group tag begins. For a tag
                // resumed from `tail` the body ended in a previous call and is
                // already recorded, hence the saturation to 0.
                let body_end = next_pos.saturating_sub(hdr_len);
                self.pop_frame(data, body_end, handler)?;
                Ok(next_pos)
            }
        }
    }

    /// Closes the innermost frame; emits its body when terminal.
    fn pop_frame<H: WireHandler + ?Sized>(
        &mut self,
        data: &[u8],
        body_end: usize,
        handler: &mut H,
    ) -> Result<(), TreeError> {
        let f = self.frames.pop().expect("pop_frame requires an open frame");

        let result = if f.terminal {
            let mut rec = f.rec;
            let body: &[u8] = if let Some(start) = f.emit_start {
                &data[start..body_end]
            } else if let Some(rec) = rec.as_mut() {
                rec.extend_from_slice(&data[f.seen_start..body_end])
                    .map_err(|_| TreeError::CapacityExceeded)?;
                rec.as_slice()
            } else {
                &[]
            };

            match f.remaining {
                Some(rem) => {
                    debug_assert_eq!(rem, 0);
                    handler.on_length_delimited(&self.path, body, body.len() as u32, true)
                }
                #[cfg(feature = "group")]
                None => handler.on_group(&self.path, body, true),
                #[cfg(not(feature = "group"))]
                None => unreachable!("group frames require the group feature"),
            }
        } else {
            Ok(())
        };

        self.path.pop();
        result
    }

    /// Carries per-call state across a chunk boundary: converts fast-path
    /// borrows into recordings and emits partial matches.
    fn suspend<H: WireHandler + ?Sized>(
        &mut self,
        data: &[u8],
        frag_start: usize,
        handler: &mut H,
    ) -> Result<(), TreeError> {
        let Self { frames, path, emit_partial, .. } = self;
        let emit_partial = *emit_partial;

        for (i, f) in frames.iter_mut().enumerate() {
            let seen_from = f.emit_start.take().unwrap_or(f.seen_start);
            let grew = frag_start > seen_from;

            if f.terminal {
                let rec = f.rec.get_or_insert_with(Buf::new);
                rec.extend_from_slice(&data[seen_from..frag_start])
                    .map_err(|_| TreeError::CapacityExceeded)?;

                if grew && emit_partial {
                    let field_path = &path[..=i];
                    match f.remaining {
                        Some(rem) if rem > 0 => {
                            let total =
                                rec.len().checked_add(rem).ok_or(TreeError::CapacityExceeded)?;
                            handler.on_length_delimited(
                                field_path,
                                rec.as_slice(),
                                total,
                                false,
                            )?;
                        }
                        // Fully buffered payload waiting on an inner frame:
                        // the complete emission follows at pop.
                        Some(_) => {}
                        #[cfg(feature = "group")]
                        None => handler.on_group(field_path, rec.as_slice(), false)?,
                        #[cfg(not(feature = "group"))]
                        None => unreachable!("group frames require the group feature"),
                    }
                }
            }
            f.seen_start = frag_start;
        }
        Ok(())
    }

    /// Subtracts `n` consumed bytes from every open Len frame.
    ///
    /// Underflow means a field crosses its enclosing payload boundary; the
    /// error reports `at`, the input offset the consumed unit started at.
    fn consume(&mut self, n: usize, at: usize) -> Result<(), TreeError> {
        if n == 0 {
            return Ok(());
        }
        debug_assert!(u32::try_from(n).is_ok(), "consume steps are bounded by u32 payload sizes");
        for f in &mut self.frames {
            if let Some(rem) = f.remaining.as_mut() {
                *rem = rem.checked_sub(n as u32).ok_or_else(|| TreeError::malformed_at(at))?;
            }
        }
        Ok(())
    }

    fn push_frame(&mut self, frame: Frame) -> Result<(), TreeError> {
        if self.frames.len() + 1 > MAX_DECODE_DEPTH {
            return Err(TreeError::CapacityExceeded);
        }
        self.frames.try_reserve(1).map_err(|_| TreeError::CapacityExceeded)?;
        self.path.try_reserve(1).map_err(|_| TreeError::CapacityExceeded)?;
        self.path.push(frame.tag);
        self.frames.push(frame);
        Ok(())
    }

    /// Runs `f` with `tag` temporarily appended to the current path.
    fn with_path_tag<F>(&mut self, tag: Tag, f: F) -> Result<(), TreeError>
    where
        F: FnOnce(&[Tag]) -> Result<(), TreeError>,
    {
        self.path.try_reserve(1).map_err(|_| TreeError::CapacityExceeded)?;
        self.path.push(tag);
        let result = f(&self.path);
        self.path.pop();
        result
    }
}

/// Parses one field header (plus inline scalar value) from `bytes`.
///
/// Returns `Ok(None)` when `bytes` ends mid-unit and `complete` is false;
/// truncation with `complete == true` is `Malformed` at the unit start.
/// Error offsets are local to `bytes`; callers rebase via `offset_by`.
fn parse_unit(bytes: &[u8], complete: bool) -> Result<Option<(Unit, usize)>, TreeError> {
    #[inline]
    const fn incomplete(complete: bool) -> Result<Option<(Unit, usize)>, TreeError> {
        if complete { Err(TreeError::Malformed { offset: 0 }) } else { Ok(None) }
    }

    let Some((tag, tag_len)) = decode_tag_prefix(bytes)? else {
        return incomplete(complete);
    };
    let rest = &bytes[tag_len..];

    let (kind, extra) = match tag.wire_type() {
        WireType::Varint => {
            let Some((value, n)) =
                decode_varint64_prefix(rest).map_err(|e| e.offset_by(tag_len))?
            else {
                return incomplete(complete);
            };
            (UnitKind::Varint(value), n)
        }
        WireType::I32 => {
            if rest.len() < 4 {
                return incomplete(complete);
            }
            let value: [u8; 4] = rest[..4].try_into().expect("length checked above");
            (UnitKind::I32(value), 4)
        }
        WireType::I64 => {
            if rest.len() < 8 {
                return incomplete(complete);
            }
            let value: [u8; 8] = rest[..8].try_into().expect("length checked above");
            (UnitKind::I64(value), 8)
        }
        WireType::Len => {
            let Some((len, n)) = decode_varint32_prefix(rest).map_err(|e| e.offset_by(tag_len))?
            else {
                return incomplete(complete);
            };
            (UnitKind::Len(len), n)
        }
        #[cfg(feature = "group")]
        WireType::SGroup => (UnitKind::GroupStart, 0),
        #[cfg(feature = "group")]
        WireType::EGroup => (UnitKind::GroupEnd, 0),
    };

    Ok(Some((Unit { tag, kind }, tag_len + extra)))
}

/// One-shot zero-copy scanner over a complete message.
///
/// Callback payloads borrow from the input slice; nothing is buffered or
/// copied. For chunked input use `ChunkStream`.
#[derive(Clone, Copy)]
pub struct Scanner {
    matcher: PathTrieRef,
}

impl Default for Scanner {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl Scanner {
    /// Scanner with no match paths; `scan` only validates wire structure.
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self { matcher: EMPTY_TRIE }
    }

    #[inline]
    #[must_use]
    pub const fn with_trie<const MAX_NODES: usize, const MAX_EDGES: usize>(
        trie: &'static CompiledPathTrie<MAX_NODES, MAX_EDGES>,
    ) -> Self {
        Self { matcher: trie.as_ref() }
    }

    /// Walks `data` as one complete message, emitting matched fields.
    ///
    /// Errors with `Malformed`/`Truncated` on malformed or truncated input.
    pub fn scan<H: WireHandler + ?Sized>(
        &self,
        data: &[u8],
        handler: &mut H,
    ) -> Result<(), TreeError> {
        let mut walker = Walker::new(self.matcher);
        let consumed = walker.run(data, true, handler)?;
        debug_assert_eq!(consumed, data.len());
        Ok(())
    }
}
