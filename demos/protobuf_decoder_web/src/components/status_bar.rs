use crate::services::{ExportService, MessageService, WorkspaceService};
use crate::state::{MessageCatalogState, WorkspaceState};
use leptos::oco::Oco;
use leptos::prelude::*;

#[component]
pub(crate) fn StatusBar() -> impl IntoView {
    let export_svc = expect_context::<ExportService>();
    let ws_svc = expect_context::<WorkspaceService>();
    let msg_svc = expect_context::<MessageService>();
    let workspace = expect_context::<WorkspaceState>();
    let messages = expect_context::<MessageCatalogState>();

    let has_current_message = move || messages.current_message_id.get().is_some();

    let hex_svc = export_svc.clone();
    let b64_svc = export_svc.clone();
    let url_svc = export_svc.clone();
    let dl_svc = export_svc.clone();
    let expand_svc = ws_svc.clone();
    let save_ws_svc = ws_svc.clone();
    let save_msg_svc = msg_svc.clone();

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
                <button
                    class="btn btn--secondary"
                    on:click=move |_| hex_svc.copy_hex()
                    disabled=move || !has_current_message()
                >
                    "Copy Hex"
                </button>
                <button
                    class="btn btn--secondary"
                    on:click=move |_| b64_svc.copy_base64()
                    disabled=move || !has_current_message()
                >
                    "Copy Base64"
                </button>
                <button
                    class="btn btn--secondary"
                    on:click=move |_| url_svc.copy_share_url()
                    disabled=move || !has_current_message()
                >
                    "Copy URL"
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
                    on:click=move |_| expand_svc.save_expand_defaults()
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
