mod app;
mod bytes;
mod components;
mod decode;
mod envelope;
mod error;
mod fx;
mod hex_view;
mod idb;
mod messages;
mod page_cache;
mod state;
mod toast;
mod web;
mod workspace;

use leptos::prelude::*;
use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen(start)]
pub fn main() {
    let _ = tracing_subscriber::fmt()
        .with_writer(
            tracing_subscriber_wasm::MakeConsoleWriter::default()
                .map_trace_level_to(tracing::Level::DEBUG),
        )
        .without_time()
        .try_init();
    mount_to_body(|| view! { <app::App /> });
}
