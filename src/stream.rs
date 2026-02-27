//! Incremental protobuf wire parser with trie-based path matching.
//!
//! Design:
//! - compile interested paths once with `const_trie!`
//! - feed byte chunks incrementally
//! - emit callbacks only for matched paths
//!
//! Typical flow:
//! ```text
//! let trie = const_trie!(..., ..., [&PATH_A, &PATH_B]);
//! let mut stream = ChunkStream::with_trie(trie);
//! stream.feed(chunk_a, &mut handler)?;
//! stream.feed(chunk_b, &mut handler)?;
//! stream.finish()?;
//! ```

mod decode;
#[cfg(feature = "group")]
mod group;
mod handler;
mod parser;
mod state;
mod trie;

pub use handler::WireHandler;
pub use parser::ChunkStream;
pub use trie::CompiledPathTrie;

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
