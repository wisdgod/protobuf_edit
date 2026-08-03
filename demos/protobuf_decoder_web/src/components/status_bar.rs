use std::fmt::Write as _;

use crate::hex_copy::CopyFormat;
use crate::services::{EnvelopeService, ExportService, MessageService, WorkspaceService};
use crate::state::{MessageCatalogState, UiState, WorkspaceState};
use leptos::html;
use leptos::oco::Oco;
use leptos::prelude::*;
use protobuf_edit::WireType;
use wasm_bindgen::JsCast;

/// Byte/row/field/highlight counts for the workspace in context.
#[component]
pub(crate) fn StatusCounts() -> impl IntoView {
    let workspace = expect_context::<WorkspaceState>();
    let locale = expect_context::<UiState>().locale;
    let bytes_count = workspace.bytes_count;
    let root_field_count = workspace.root_field_count;
    let highlight_range_count = workspace.highlight_range_count;

    view! {
        <div>
            {move || {
                let t = locale.get().t();
                let Some(bytes) = bytes_count.get() else {
                    return Oco::Borrowed(t.no_data);
                };
                let rows = bytes.div_ceil(16);
                let fields = root_field_count.get().unwrap_or(0);
                let highlights = highlight_range_count.get();
                Oco::from(format!(
                    "{bytes} {} | {rows} {} | {fields} {} | {highlights} {}",
                    t.bytes_unit, t.rows_unit, t.root_fields_unit, t.highlights_unit,
                ))
            }}
        </div>
    }
}

/// One-line meta for the selected field: number, wire type, spans, payload.
///
/// Lives in the status bar (not the inspector) so it stays visible in
/// read-only mode and in the envelope preview.
#[component]
pub(crate) fn SelectionMeta() -> impl IntoView {
    let workspace = expect_context::<WorkspaceState>();
    let locale = expect_context::<UiState>().locale;
    let patch_state = workspace.patch_state;
    let selected = workspace.selected;

    let meta = Memo::new(move |_| {
        let fid = selected.get()?;
        patch_state.with(|p| {
            let patch = p.as_ref()?;
            let tag = patch.field_tag(fid).ok()?;
            let local = patch.field_spans(fid).ok().flatten().map(|s| s.field);
            let root = patch.field_root_spans(fid).ok().flatten().map(|s| s.field);
            let payload_len = match tag.wire_type() {
                WireType::Varint => {
                    patch.varint(fid).ok().map(|v| protobuf_edit::varint::encoded_len64(v) as u32)
                }
                WireType::Len => patch.bytes(fid).ok().map(|b| b.len() as u32),
                WireType::I32 => Some(4),
                WireType::I64 => Some(8),
            };
            Some((tag.field_number().as_inner(), tag.wire_type(), local, root, payload_len))
        })
    });

    view! {
        <div>
            {move || {
                let t = locale.get().t();
                let Some((n, wt, local, root, payload)) = meta.get() else {
                    return Oco::Borrowed(t.no_selection);
                };
                let mut out = format!("{} {n} ({wt:?})", t.field);
                for (label, span) in [(t.span, local), (t.root_span, root)] {
                    match span {
                        Some(s) => {
                            let _ = write!(out, " | {label} {}..{}", s.start(), s.end());
                        }
                        None => {
                            let _ = write!(out, " | {label} \u{2014}");
                        }
                    }
                }
                match payload {
                    Some(len) => {
                        let _ = write!(out, " | {} {len} {}", t.payload, t.bytes_unit);
                    }
                    None => {
                        let _ = write!(out, " | {} \u{2014}", t.payload);
                    }
                }
                Oco::from(out)
            }}
        </div>
    }
}

/// Slim status bar for read-only previews: counts + selection meta only.
#[component]
pub(crate) fn PreviewStatusBar() -> impl IntoView {
    view! {
        <div class="status-bar">
            <div class="status-left">
                <StatusCounts />
            </div>
            <div class="status-center">
                <SelectionMeta />
            </div>
        </div>
    }
}

#[component]
pub(crate) fn StatusBar() -> impl IntoView {
    let export_svc = expect_context::<ExportService>();
    let ws_svc = expect_context::<WorkspaceService>();
    let msg_svc = expect_context::<MessageService>();
    let env_svc = expect_context::<EnvelopeService>();
    let workspace = expect_context::<WorkspaceState>();
    let messages = expect_context::<MessageCatalogState>();
    let ui = expect_context::<UiState>();
    let locale = ui.locale;
    let read_only = ui.read_only;

    let has_current_message = move || messages.current_message_id.get().is_some();

    let export_open = RwSignal::new(false);
    let menu_ref = NodeRef::<html::Div>::new();

    // `Show` re-runs its children, so the save handler must be constructible
    // more than once; Copy handles avoid moving the services out.
    let save_ws_svc = StoredValue::new_local(ws_svc.clone());
    let save_msg_svc = StoredValue::new_local(msg_svc);
    let on_view_frames = move |_| env_svc.view_frames();

    view! {
        <div class="status-bar">
            <div class="status-left">
                <StatusCounts />
            </div>

            <div class="status-center">
                <SelectionMeta />

                <div class="status-dirty">
                    <span class="status-dirty-dot" class:hidden=move || workspace.dirty_count.get() == 0>
                        "●"
                    </span>
                    {move || {
                        let t = locale.get().t();
                        let n = workspace.dirty_count.get();
                        if n == 0 {
                            Oco::Borrowed(t.zero_edits)
                        } else {
                            Oco::from(format!("{n} {}", t.edits_pending))
                        }
                    }}
                </div>
            </div>

            <div class="status-actions">
                <button
                    class="btn btn--secondary btn--small"
                    on:click=on_view_frames
                    disabled=move || !has_current_message()
                >
                    {move || locale.get().t().frames}
                </button>
                <div class="dropdown" node_ref=menu_ref>
                    <button
                        class="btn btn--secondary btn--small"
                        on:click=move |_| export_open.update(|v| *v = !*v)
                        disabled=move || !has_current_message()
                    >
                        {move || {
                            let t = locale.get().t();
                            let arrow = if export_open.get() { '\u{25B4}' } else { '\u{25BE}' };
                            format!("{} {arrow}", t.export)
                        }}
                    </button>
                    <Show when=move || export_open.get() fallback=|| ()>
                        <ExportDropdown
                            export_svc=export_svc.clone()
                            ws_svc=ws_svc.clone()
                            on_close=Callback::new(move |()| export_open.set(false))
                            menu_ref=menu_ref
                        />
                    </Show>
                </div>
                <Show when=move || !read_only.get() fallback=|| ()>
                    <button
                        class="btn btn--primary btn--small"
                        on:click=move |_| {
                            if workspace.dirty_count.get() != 0 {
                                let _ = save_ws_svc.with_value(WorkspaceService::save_reparse);
                            } else {
                                save_msg_svc.with_value(MessageService::bump_modified);
                            }
                        }
                        disabled=move || {
                            if workspace.dirty_count.get() == 0 {
                                !has_current_message()
                            } else {
                                workspace.patch_state.with(std::option::Option::is_none)
                            }
                        }
                    >
                        {move || {
                            let t = locale.get().t();
                            if workspace.dirty_count.get() == 0 {
                                t.bump_reorder
                            } else {
                                t.save_reparse
                            }
                        }}
                    </button>
                </Show>
            </div>
        </div>
    }
}

/// Export menu: copy formats, share URL, download, expand defaults.
#[component]
fn ExportDropdown(
    export_svc: ExportService,
    ws_svc: WorkspaceService,
    on_close: Callback<()>,
    menu_ref: NodeRef<html::Div>,
) -> impl IntoView {
    let locale = expect_context::<UiState>().locale;

    let _dismiss = leptos_use::use_event_listener(
        web_sys::window().expect("window"),
        leptos::ev::mousedown,
        move |ev: web_sys::MouseEvent| {
            let Some(el) = menu_ref.get() else { return };
            let Some(target) = ev.target() else { return };
            let target: web_sys::Node = target.unchecked_into();
            let container: &web_sys::Node = el.as_ref();
            if !container.contains(Some(&target)) {
                on_close.run(());
            }
        },
    );

    let _esc = leptos_use::use_event_listener(
        web_sys::window().expect("window"),
        leptos::ev::keydown,
        move |ev: web_sys::KeyboardEvent| {
            if ev.key() == "Escape" {
                on_close.run(());
            }
        },
    );

    let url_svc = export_svc.clone();
    let dl_svc = export_svc.clone();

    view! {
        <div class="dropdown__menu">
            <div class="dropdown__group-label">{move || locale.get().t().copy_as}</div>
            {CopyFormat::ALL.iter().map(|&fmt| {
                let svc = export_svc.clone();
                view! {
                    <button
                        class="dropdown__item"
                        on:click=move |_| {
                            svc.copy_as(fmt);
                            on_close.run(());
                        }
                    >
                        {fmt.label()}
                    </button>
                }
            }).collect::<Vec<_>>()}
            <div class="dropdown__separator"></div>
            <button
                class="dropdown__item"
                on:click=move |_| {
                    url_svc.copy_share_url();
                    on_close.run(());
                }
            >
                {move || locale.get().t().copy_share_url}
            </button>
            <button
                class="dropdown__item"
                on:click=move |_| {
                    dl_svc.download_bin();
                    on_close.run(());
                }
            >
                {move || locale.get().t().download_bin}
            </button>
            <div class="dropdown__separator"></div>
            <button
                class="dropdown__item"
                on:click=move |_| {
                    ws_svc.save_expand_defaults();
                    on_close.run(());
                }
            >
                {move || locale.get().t().save_expand_defaults}
            </button>
        </div>
    }
}
