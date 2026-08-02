#![cfg_attr(not(feature = "__std"), no_std)]
#![feature(core_intrinsics)]
#![feature(const_trait_impl)]
#![feature(panic_internals)]
#![feature(allow_internal_unsafe)]
#![feature(allow_internal_unstable)]
#![allow(internal_features)]
#![allow(unsafe_op_in_unsafe_fn)]

//! Low-level, schema-less protobuf inspection and editing utilities.
//!
//! `protobuf_edit` intentionally exposes more than one editing model:
//! - `Document` is an arena-backed structured editor for one message. It eagerly decodes
//!   wire fields into typed slots and maintains raw caches; edits update those caches
//!   immediately.
//! - `Patch` is a span-based patcher for one message. It eagerly scans wire fields and
//!   records byte spans into the original source buffer; payload edits are tracked
//!   lazily and materialized on `Patch::save()` by copying unchanged spans verbatim.
//!
//! Public modules are organized by concern:
//! - `buf`: shared owned/borrowed byte storage
//! - `error`: shared error type used across editing and parsing APIs
//! - `document`: arena-backed structured editing model
//! - `patch`: span-based editing model
//! - `wire`: protobuf tag primitives and the zero-allocation `FieldCursor`
//! - `encode`: borrowed message encoder with single-allocation output
//! - `varint`: varint and zigzag codecs
//! - `stream`: incremental wire parser
//!
//! The crate root re-exports only the shared vocabulary (`Buf`, `TreeError`,
//! tag primitives) and each model's entry type; everything else lives in its
//! module.

extern crate alloc;

#[macro_use]
mod _macro;
mod fx;
pub mod buf;
pub mod encode;
pub mod error;
pub mod varint;
pub mod wire;
pub mod stream;
pub mod document;
pub mod patch;

pub use buf::{Buf, BufAllocError};
pub use document::{BorrowedDocument, Document};
pub use error::TreeError;
pub use patch::{BorrowedPatch, Patch};
pub use wire::{FieldNumber, Tag, WireType};
