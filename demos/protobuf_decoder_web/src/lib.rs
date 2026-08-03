mod app;
mod bytes;
mod components;
mod decode;
mod envelope;
mod error;
mod hex_copy;
mod hex_view;
mod idb;
mod messages;
mod page_cache;
mod services;
mod state;
mod toast;
mod web;
mod workspace;

use leptos::prelude::*;
use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen(start)]
pub fn main() {
    mount_to_body(|| view! { <app::App /> });
}
