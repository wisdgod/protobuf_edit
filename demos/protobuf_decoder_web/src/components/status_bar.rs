use crate::state::{MessageCatalogState, StatusBarActions, WorkspaceState};
use leptos::prelude::*;

#[component]
pub(crate) fn StatusBar(actions: StatusBarActions) -> impl IntoView {
    let workspace = expect_context::<WorkspaceState>();
    let messages = expect_context::<MessageCatalogState>();
    let StatusBarActions {
        on_copy_hex,
        on_copy_base64,
        on_copy_share_url,
        on_download_bin,
        on_save_expand_defaults,
        on_save_reparse,
        on_bump_modified,
    } = actions;

    let has_current_message = move || messages.current_message_id.get().is_some();

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
                        None => "No selection".to_string(),
                        Some(fid) => format!("FieldId={fid:?} selected"),
                    }}
                </div>

                <div class="status-dirty">
                    <span class="status-dirty-dot" class:hidden=move || workspace.dirty_count.get() == 0>
                        "●"
                    </span>
                    {move || {
                        let n = workspace.dirty_count.get();
                        if n == 0 { "0 edits".to_string() } else { format!("{n} edit(s) pending") }
                    }}
                </div>
            </div>

            <div class="status-actions">
                <button
                    class="btn btn--secondary"
                    on:click=move |_| on_copy_hex.run(())
                    disabled=move || !has_current_message()
                >
                    "Copy Hex"
                </button>
                <button
                    class="btn btn--secondary"
                    on:click=move |_| on_copy_base64.run(())
                    disabled=move || !has_current_message()
                >
                    "Copy Base64"
                </button>
                <button
                    class="btn btn--secondary"
                    on:click=move |_| on_copy_share_url.run(())
                    disabled=move || !has_current_message()
                >
                    "Copy URL"
                </button>
                <button
                    class="btn btn--secondary"
                    on:click=move |_| on_download_bin.run(())
                    disabled=move || !has_current_message()
                >
                    "Download .bin"
                </button>
                <button
                    class="btn btn--secondary"
                    on:click=move |_| on_save_expand_defaults.run(())
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
                            on_save_reparse.run(());
                        } else {
                            on_bump_modified.run(());
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
