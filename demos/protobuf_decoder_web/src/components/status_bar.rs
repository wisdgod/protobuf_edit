use crate::hex_copy::CopyFormat;
use crate::services::{EnvelopeService, ExportService, MessageService, WorkspaceService};
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
    let env_svc = expect_context::<EnvelopeService>();
    let workspace = expect_context::<WorkspaceState>();
    let messages = expect_context::<MessageCatalogState>();

    let has_current_message = move || messages.current_message_id.get().is_some();

    let export_open = RwSignal::new(false);
    let menu_ref = NodeRef::<html::Div>::new();

    let save_ws_svc = ws_svc.clone();
    let save_msg_svc = msg_svc;
    let on_view_frames = move |_| env_svc.view_frames();

    view! {
        <div class="status-bar">
            <div class="status-left">
                <div>
                    {move || {
                        let Some(bytes) = workspace.bytes_count.get() else {
                            return Oco::Borrowed("no data");
                        };
                        let rows = bytes.div_ceil(16);
                        let fields = workspace.root_field_count.get().unwrap_or(0);
                        let highlights = workspace.highlight_range_count.get();
                        Oco::from(format!(
                            "{bytes} bytes | {rows} rows | {fields} root field(s) | \
                             {highlights} highlight(s)"
                        ))
                    }}
                </div>
            </div>

            <div class="status-center">
                <div>
                    {move || {
                        workspace.selected.get().map_or(Oco::Borrowed("No selection"), |fid| {
                            Oco::from(format!("FieldId={fid:?} selected"))
                        })
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
                <button
                    class="btn btn--secondary btn--small"
                    on:click=on_view_frames
                    disabled=move || !has_current_message()
                >
                    "Frames"
                </button>
                <div class="dropdown" node_ref=menu_ref>
                    <button
                        class="btn btn--secondary btn--small"
                        on:click=move |_| export_open.update(|v| *v = !*v)
                        disabled=move || !has_current_message()
                    >
                        {move || if export_open.get() { "Export \u{25B4}" } else { "Export \u{25BE}" }}
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
                <button
                    class="btn btn--primary btn--small"
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
                            workspace.patch_state.with(std::option::Option::is_none)
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

/// Export menu: copy formats, share URL, download, expand defaults.
#[component]
fn ExportDropdown(
    export_svc: ExportService,
    ws_svc: WorkspaceService,
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

    let url_svc = export_svc.clone();
    let dl_svc = export_svc.clone();

    view! {
        <div class="dropdown__menu">
            <div class="dropdown__group-label">"Copy as"</div>
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
                "Copy share URL"
            </button>
            <button
                class="dropdown__item"
                on:click=move |_| {
                    dl_svc.download_bin();
                    on_close.run(());
                }
            >
                "Download .bin"
            </button>
            <div class="dropdown__separator"></div>
            <button
                class="dropdown__item"
                on:click=move |_| {
                    ws_svc.save_expand_defaults();
                    on_close.run(());
                }
            >
                "Save expand defaults"
            </button>
        </div>
    }
}
