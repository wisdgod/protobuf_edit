//! Protobuf wire walkers with trie-based path matching.
//!
//! Design:
//! - compile interested paths once with `const_trie!`
//! - `Scanner` walks one complete buffer, zero-copy
//! - `ChunkStream` accepts byte chunks incrementally
//! - both emit callbacks only for matched paths
//!
//! Typical flow:
//! ```text
//! let trie = const_trie!(..., ..., [&PATH_A, &PATH_B]);
//! Scanner::with_trie(trie).scan(whole_message, &mut handler)?;
//! // or, when data arrives in pieces:
//! let mut stream = ChunkStream::with_trie(trie);
//! stream.feed(chunk_a, &mut handler)?;
//! stream.feed(chunk_b, &mut handler)?;
//! stream.finish()?;
//! ```

mod decode;
mod handler;
mod parser;
mod trie;
mod walk;

pub use handler::WireHandler;
pub use parser::ChunkStream;
pub use trie::CompiledPathTrie;
pub use walk::Scanner;

#[macro_export]
#[allow_internal_unstable(panic_internals)]
macro_rules! const_trie {
    ($nodes:expr, $edges:expr, [$($path:expr),+ $(,)?]) => {{
        const TRIE: $crate::stream::CompiledPathTrie<$nodes, $edges> =
            match $crate::stream::CompiledPathTrie::build(&[$($path),+]) {
                Ok(v) => v,
                Err(_) => ::core::panicking::panic("invalid compile-time trie"),
            };
        &TRIE
    }};
}

#[cfg(test)]
mod tests;
