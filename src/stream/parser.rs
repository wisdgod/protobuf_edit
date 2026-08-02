use crate::error::TreeError;

use super::handler::WireHandler;
use super::trie::{CompiledPathTrie, EMPTY_TRIE};
use super::walk::Walker;

/// Stateful incremental parser over byte chunks.
///
/// Thin buffering facade over the frame-stack `Walker`: chunks are parsed in
/// place and only boundary-straddling state is carried between feeds. For
/// complete input prefer `Scanner`.
pub struct ChunkStream {
    walker: Walker,
    /// Total bytes accepted across all feeds.
    fed: u64,
}

impl Default for ChunkStream {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl ChunkStream {
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self { walker: Walker::new(EMPTY_TRIE), fed: 0 }
    }

    #[inline]
    #[must_use]
    pub const fn with_trie<const MAX_NODES: usize, const MAX_EDGES: usize>(
        trie: &'static CompiledPathTrie<MAX_NODES, MAX_EDGES>,
    ) -> Self {
        Self { walker: Walker::new(trie.as_ref()), fed: 0 }
    }

    #[inline]
    pub fn set_trie<const MAX_NODES: usize, const MAX_EDGES: usize>(
        &mut self,
        trie: &'static CompiledPathTrie<MAX_NODES, MAX_EDGES>,
    ) {
        self.walker.set_matcher(trie.as_ref());
        self.reset();
    }

    #[inline]
    pub fn clear_trie(&mut self) {
        self.walker.set_matcher(EMPTY_TRIE);
        self.reset();
    }

    #[inline]
    pub const fn set_emit_partial_matches(&mut self, enabled: bool) {
        self.walker.set_emit_partial(enabled);
    }

    #[inline]
    pub fn reset(&mut self) {
        self.walker.reset();
        self.fed = 0;
    }

    /// Stream position right after the last fully parsed wire unit.
    #[inline]
    #[must_use]
    pub fn offset(&self) -> u64 {
        self.fed - u64::from(self.walker.tail_len())
    }

    pub fn feed<H: WireHandler + ?Sized>(
        &mut self,
        chunk: &[u8],
        handler: &mut H,
    ) -> Result<(), TreeError> {
        self.walker.run(chunk, false, handler)?;
        self.fed = self.fed.checked_add(chunk.len() as u64).ok_or(TreeError::CapacityExceeded)?;
        Ok(())
    }

    /// Errors with `Truncated` if any field or nesting level is unfinished.
    #[inline]
    pub const fn finish(&self) -> Result<(), TreeError> {
        if self.walker.is_clean() { Ok(()) } else { Err(TreeError::Truncated) }
    }
}
