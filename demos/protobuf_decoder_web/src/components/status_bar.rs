use crate::messages::MessageId;
use leptos::prelude::*;
use protobuf_edit::{FieldId, Patch};

#[component]
pub(crate) fn StatusBar(
    bytes_count: Memo<Option<usize>>,
    field_count: Memo<Option<usize>>,
    highlight_range_count: Memo<usize>,
    selected: RwSignal<Option<FieldId>>,
    dirty_count: Memo<usize>,
    current_message_id: RwSignal<Option<MessageId>>,
    read_only: Memo<bool>,
    patch_state: RwSignal<Option<Patch>, LocalStorage>,
    on_copy_hex: UnsyncCallback<()>,
    on_copy_base64: UnsyncCallback<()>,
    on_copy_share_url: UnsyncCallback<()>,
    on_download_bin: UnsyncCallback<()>,
    on_save_expand_defaults: UnsyncCallback<()>,
    on_save_reparse: UnsyncCallback<()>,
    on_bump_modified: UnsyncCallback<()>,
) -> impl IntoView {
    let has_current_message = move || current_message_id.get().is_some();

    view! {
        <div class="status-bar">
            <div class="status-left">
                <div>
                    {move || bytes_count.get().unwrap_or(0)}
                    " bytes | "
                    {move || bytes_count.get().unwrap_or(0).saturating_add(15) / 16}
                    " rows | "
                    {move || field_count.get().unwrap_or(0)}
                    " field(s)"
                    " | "
                    {move || highlight_range_count.get()}
                    " highlight(s)"
                </div>
            </div>

            <div class="status-center">
                <div>
                    {move || match selected.get() {
                        None => "No selection".to_string(),
                        Some(fid) => format!("FieldId={fid:?} selected"),
                    }}
                </div>

                <div class="status-dirty">
                    <span class="status-dirty-dot" class:hidden=move || dirty_count.get() == 0>
                        "●"
                    </span>
                    {move || {
                        let n = dirty_count.get();
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
                    disabled=move || !has_current_message() || read_only.get() || patch_state.with(|p| p.is_none())
                >
                    "Save Expand"
                </button>
                <button
                    class="btn btn--primary"
                    on:click=move |_| {
                        if dirty_count.get() != 0 {
                            on_save_reparse.run(());
                        } else {
                            on_bump_modified.run(());
                        }
                    }
                    disabled=move || {
                        if dirty_count.get() == 0 {
                            !has_current_message()
                        } else {
                            read_only.get() || patch_state.with(|p| p.is_none())
                        }
                    }
                >
                    {move || if dirty_count.get() == 0 { "Bump (reorder)" } else { "Save & Reparse" }}
                </button>
            </div>
        </div>
    }
}
