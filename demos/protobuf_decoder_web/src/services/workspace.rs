use crate::bytes::ByteView;
use crate::messages;
use crate::state::{MessageCatalogState, WorkspaceState};
use crate::toast::{ToastKind, ToastManager};
use crate::workspace::{
    build_selection_path, confirm_discard_edits as confirm_workspace_discard_edits,
    encode_selection_path, load_patch_from_view as load_patch_into_session,
    revert_pending_edits as revert_workspace_edits, save_and_reparse as save_workspace_and_reparse,
    SaveReparseInfo,
};
use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;

/// Thin service layer over the `workspace::commands` functions, adding
/// message-catalog awareness (e.g. persisting bytes to IDB after save).
#[derive(Clone)]
pub(crate) struct WorkspaceService {
    ws: WorkspaceState,
    catalog: MessageCatalogState,
    toast: ToastManager,
}

impl WorkspaceService {
    pub(crate) fn new(
        ws: WorkspaceState,
        catalog: MessageCatalogState,
        toast: ToastManager,
    ) -> Self {
        Self { ws, catalog, toast }
    }

    /// Save pending edits, reparse the protobuf, and persist updated bytes
    /// to IDB for the current message. Returns the save info on success so
    /// callers can decide whether to refresh the message list.
    pub(crate) fn save_reparse(&self) -> Result<SaveReparseInfo, protobuf_edit::TreeError> {
        let before_len = self.ws.bytes_count.get_untracked().unwrap_or(0);
        let message_id = self.catalog.current_message_id.get_untracked();
        let toast = self.toast;

        match save_workspace_and_reparse(&self.ws) {
            Ok(info) => {
                let bytes_len = info.bytes_len;
                let field_count = info.field_count;
                let elapsed_ms = info.elapsed_ms;

                if let Some(id) = message_id {
                    let bytes_value = js_sys::Uint8Array::from(info.bytes.as_slice());
                    spawn_local(async move {
                        if let Err(msg) =
                            messages::update_message_bytes(id, bytes_len, bytes_value).await
                        {
                            toast.show(ToastKind::Error, msg);
                        }
                    });
                }

                toast.show(
                    ToastKind::Success,
                    format!(
                        "Saved & reparsed: {bytes_len} bytes (was {before_len}), {field_count} field(s) in {elapsed_ms:.1}ms."
                    ),
                );
                Ok(info)
            }
            Err(err) => {
                toast.show(ToastKind::Error, format!("Save & reparse failed: {err:?}"));
                Err(err)
            }
        }
    }

    /// Revert all pending field edits, restoring the patch to its last saved state.
    pub(crate) fn revert_edits(&self) {
        let pending = self.ws.dirty_fields.with_untracked(|state| state.len());
        if pending == 0 {
            return;
        }

        match revert_workspace_edits(&self.ws) {
            Ok(()) => {
                self.toast.show(ToastKind::Success, format!("Reverted {pending} pending edit(s)."))
            }
            Err(err) => self.toast.show(ToastKind::Error, format!("Undo failed: {err:?}")),
        }
    }

    /// Persist the currently expanded tree paths as auto-expand defaults
    /// for the active message's class.
    pub(crate) fn save_expand_defaults(&self) {
        let toast = self.toast;
        let current_message_id = self.catalog.current_message_id;
        let messages_list = self.catalog.messages_list;
        let patch_state = self.ws.patch_state;
        let expanded = self.ws.expanded;
        let read_only = self.ws.read_only;

        let Some(id) = current_message_id.get_untracked() else {
            toast.show(ToastKind::Error, "No message selected.");
            return;
        };
        if read_only.get_untracked() {
            toast.show(
                ToastKind::Error,
                "Cannot save expand defaults while viewing envelope frames.",
            );
            return;
        }

        let Some(mut paths) = patch_state.with_untracked(|p| {
            let patch = p.as_ref()?;
            Some(expanded.with_untracked(|expanded| {
                let mut paths = Vec::new();
                for &fid in expanded {
                    let Some(path) = build_selection_path(patch, fid) else {
                        continue;
                    };
                    paths.push(encode_selection_path(&path));
                }
                paths
            }))
        }) else {
            toast.show(ToastKind::Error, "No protobuf message loaded.");
            return;
        };

        paths.sort_unstable();
        paths.dedup();
        let count = paths.len();

        let class_id = messages_list
            .with_untracked(|list| list.iter().find(|m| m.id == id).map(|m| m.class_id))
            .unwrap_or(id);
        spawn_local(async move {
            if let Err(msg) = messages::store_auto_expand_paths(class_id, &paths).await {
                toast.show(ToastKind::Error, msg);
                return;
            }

            if count == 0 {
                toast.show(ToastKind::Success, "Cleared auto-expand defaults.");
            } else {
                toast.show(ToastKind::Success, format!("Saved {count} auto-expand path(s)."));
            }
        });
    }

    /// Load a protobuf patch (or fall back to raw bytes) into the workspace.
    pub(crate) fn load_patch(&self, label: &str, bytes: ByteView, auto_expand_paths: Vec<String>) {
        load_patch_into_session(&self.ws, label, bytes, auto_expand_paths, &self.toast);
    }

    /// If there are pending edits, ask the user to confirm discarding them.
    /// Returns `true` when there are no edits or the user accepts.
    pub(crate) fn confirm_discard(&self, action: &str) -> bool {
        confirm_workspace_discard_edits(&self.ws, action)
    }
}
