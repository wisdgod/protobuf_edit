use crate::hex_copy::CopyFormat;
use crate::services::{ExportService, MessageService, WorkspaceService};
use crate::state::{MessageCatalogState, WorkspaceState};
use leptos::html;
use leptos::oco::Oco;
use leptos::prelude::*;
use wasm_bindgen::JsCast;

#[component]
pub(crate) fn StatusBar() -> impl IntoView {
    let export_svc = expect_context::<ExportService>();
    let ws_svc = expect_context::<WorkspaceService>();
    let msg_svc = expect_context::<MessageService>();
    let workspace = expect_context::<WorkspaceState>();
    let messages = expect_context::<MessageCatalogState>();

    let has_current_message = move || messages.current_message_id.get().is_some();

    let copy_open = RwSignal::new(false);
    let menu_ref = NodeRef::<html::Div>::new();

    let save_ws_svc = ws_svc.clone();
    let save_msg_svc = msg_svc.clone();
    let dropdown_svc = export_svc.clone();
    let url_svc = export_svc.clone();
    let dl_svc = export_svc.clone();

    view! {
        <div class="status-bar">
            <div class="status-left">
                <div>
                    {move || workspace.bytes_count.get().unwrap_or(0)}
                    " bytes | "
                    {move || workspace.bytes_count.get().unwrap_or(0).saturating_add(15) / 16}
                    " rows | "
                    {move || workspace.field_count.get().unwrap_or(0)}
                    " field(s)"
                    " | "
                    {move || workspace.highlight_range_count.get()}
                    " highlight(s)"
                </div>
            </div>

            <div class="status-center">
                <div>
                    {move || match workspace.selected.get() {
                        None => Oco::Borrowed("No selection"),
                        Some(fid) => Oco::from(format!("FieldId={fid:?} selected")),
                    }}
                </div>

                <div class="status-dirty">
                    <span class="status-dirty-dot" class:hidden=move || workspace.dirty_count.get() == 0>
                        "●"
                    </span>
                    {move || {
                        let n = workspace.dirty_count.get();
                        if n == 0 {
                            Oco::Borrowed("0 edits")
                        } else {
                            Oco::from(format!("{n} edit(s) pending"))
                        }
                    }}
                </div>
            </div>

            <div class="status-actions">
                <div class="dropdown" node_ref=menu_ref>
                    <button
                        class="btn btn--secondary"
                        on:click=move |_| copy_open.update(|v| *v = !*v)
                        disabled=move || !has_current_message()
                    >
                        {move || if copy_open.get() { "Copy \u{25B4}" } else { "Copy \u{25BE}" }}
                    </button>
                    <Show when=move || copy_open.get() fallback=|| ()>
                        <CopyDropdown
                            export_svc=dropdown_svc.clone()
                            on_close=Callback::new(move |()| copy_open.set(false))
                            menu_ref=menu_ref
                        />
                    </Show>
                </div>
                <button
                    class="btn btn--secondary"
                    on:click=move |_| url_svc.copy_share_url()
                    disabled=move || !has_current_message()
                >
                    "Share URL"
                </button>
                <button
                    class="btn btn--secondary"
                    on:click=move |_| dl_svc.download_bin()
                    disabled=move || !has_current_message()
                >
                    "Download .bin"
                </button>
                <button
                    class="btn btn--secondary"
                    on:click=move |_| ws_svc.save_expand_defaults()
                    disabled=move || {
                        !has_current_message()
                            || workspace.read_only.get()
                            || workspace.patch_state.with(|p| p.is_none())
                    }
                >
                    "Save Expand"
                </button>
                <button
                    class="btn btn--primary"
                    on:click=move |_| {
                        if workspace.dirty_count.get() != 0 {
                            let _ = save_ws_svc.save_reparse();
                        } else {
                            save_msg_svc.bump_modified();
                        }
                    }
                    disabled=move || {
                        if workspace.dirty_count.get() == 0 {
                            !has_current_message()
                        } else {
                            workspace.read_only.get()
                                || workspace.patch_state.with(|p| p.is_none())
                        }
                    }
                >
                    {move || {
                        if workspace.dirty_count.get() == 0 {
                            "Bump (reorder)"
                        } else {
                            "Save & Reparse"
                        }
                    }}
                </button>
            </div>
        </div>
    }
}

#[component]
fn CopyDropdown(
    export_svc: ExportService,
    on_close: Callback<()>,
    menu_ref: NodeRef<html::Div>,
) -> impl IntoView {
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

    view! {
        <div class="dropdown__menu">
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
        </div>
    }
}
