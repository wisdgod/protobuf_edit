use crate::decode::{encode_base64, encode_base64_url};
use crate::messages;
use crate::state::{MessageCatalogState, WorkspaceState};
use crate::toast::{ToastKind, ToastManager};
use crate::web::{build_share_url, clipboard_write_text, download_bytes};
use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;

/// Handles clipboard export and binary download operations.
///
/// Each method reads bytes from the current patch or raw-bytes signal first,
/// falling back to loading from IDB when neither is available.
#[derive(Clone)]
pub(crate) struct ExportService {
    ws: WorkspaceState,
    catalog: MessageCatalogState,
    toast: ToastManager,
}

impl ExportService {
    pub(crate) fn new(
        ws: WorkspaceState,
        catalog: MessageCatalogState,
        toast: ToastManager,
    ) -> Self {
        Self { ws, catalog, toast }
    }

    /// Copy the current message bytes as uppercase hex to the clipboard.
    pub(crate) fn copy_hex(&self) {
        let this = self.clone();
        let patch_state = this.ws.patch_state;
        let raw_bytes = this.ws.raw_bytes;
        let dirty_count = this.ws.dirty_count;
        let toast = this.toast;
        let current_message_id = this.catalog.current_message_id;

        let bytes_from_patch = patch_state.with(|p| {
            p.as_ref().map(|patch| {
                let bytes = patch.root_bytes();
                (hex::encode_upper(bytes), bytes.len())
            })
        });
        let bytes_from_raw = raw_bytes.with(|b| {
            b.as_ref().map(|v| {
                let bytes = v.as_slice();
                (hex::encode_upper(bytes), bytes.len())
            })
        });

        let Some((text, len)) = bytes_from_patch.or(bytes_from_raw) else {
            let Some(id) = current_message_id.get_untracked() else {
                toast.show(ToastKind::Error, "No message selected.");
                return;
            };
            spawn_local(async move {
                let loaded = match messages::load_message_bytes(id).await {
                    Ok(v) => v,
                    Err(msg) => {
                        toast.show(ToastKind::Error, msg);
                        return;
                    }
                };
                let bytes = loaded.bytes.as_slice();
                let text = hex::encode_upper(bytes);
                let len = bytes.len();
                match clipboard_write_text(&text) {
                    Ok(_promise) => {
                        let pending = dirty_count.get_untracked();
                        let msg = if pending == 0 {
                            format!("Copy hex requested: {len} bytes.")
                        } else {
                            format!("Copy hex requested: {len} bytes. ({pending} edit(s) pending.)")
                        };
                        toast.show(ToastKind::Success, msg);
                    }
                    Err(msg) => toast.show(ToastKind::Error, msg),
                }
            });
            return;
        };

        match clipboard_write_text(&text) {
            Ok(_promise) => {
                let pending = dirty_count.get_untracked();
                let msg = if pending == 0 {
                    format!("Copy hex requested: {len} bytes.")
                } else {
                    format!("Copy hex requested: {len} bytes. ({pending} edit(s) pending.)")
                };
                toast.show(ToastKind::Success, msg);
            }
            Err(msg) => toast.show(ToastKind::Error, msg),
        }
    }

    /// Copy the current message bytes as base64 to the clipboard.
    pub(crate) fn copy_base64(&self) {
        let this = self.clone();
        let patch_state = this.ws.patch_state;
        let raw_bytes = this.ws.raw_bytes;
        let dirty_count = this.ws.dirty_count;
        let toast = this.toast;
        let current_message_id = this.catalog.current_message_id;

        let bytes_from_patch = patch_state.with(|p| {
            p.as_ref().map(|patch| {
                let bytes = patch.root_bytes();
                (encode_base64(bytes), bytes.len())
            })
        });
        let bytes_from_raw = raw_bytes.with(|b| {
            b.as_ref().map(|v| {
                let bytes = v.as_slice();
                (encode_base64(bytes), bytes.len())
            })
        });

        let Some((text, len)) = bytes_from_patch.or(bytes_from_raw) else {
            let Some(id) = current_message_id.get_untracked() else {
                toast.show(ToastKind::Error, "No message selected.");
                return;
            };
            spawn_local(async move {
                let loaded = match messages::load_message_bytes(id).await {
                    Ok(v) => v,
                    Err(msg) => {
                        toast.show(ToastKind::Error, msg);
                        return;
                    }
                };
                let bytes = loaded.bytes.as_slice();
                let text = encode_base64(bytes);
                let len = bytes.len();
                match clipboard_write_text(&text) {
                    Ok(_promise) => {
                        let pending = dirty_count.get_untracked();
                        let msg = if pending == 0 {
                            format!("Copy base64 requested: {len} bytes.")
                        } else {
                            format!(
                                "Copy base64 requested: {len} bytes. ({pending} edit(s) pending.)"
                            )
                        };
                        toast.show(ToastKind::Success, msg);
                    }
                    Err(msg) => toast.show(ToastKind::Error, msg),
                }
            });
            return;
        };

        match clipboard_write_text(&text) {
            Ok(_promise) => {
                let pending = dirty_count.get_untracked();
                let msg = if pending == 0 {
                    format!("Copy base64 requested: {len} bytes.")
                } else {
                    format!("Copy base64 requested: {len} bytes. ({pending} edit(s) pending.)")
                };
                toast.show(ToastKind::Success, msg);
            }
            Err(msg) => toast.show(ToastKind::Error, msg),
        }
    }

    /// Build a shareable URL with base64-encoded bytes and copy it to the clipboard.
    pub(crate) fn copy_share_url(&self) {
        let this = self.clone();
        let patch_state = this.ws.patch_state;
        let raw_bytes = this.ws.raw_bytes;
        let toast = this.toast;
        let current_message_id = this.catalog.current_message_id;

        let bytes_from_patch = patch_state.with(|p| {
            p.as_ref().map(|patch| {
                let bytes = patch.root_bytes();
                (encode_base64_url(bytes), bytes.len())
            })
        });
        let bytes_from_raw = raw_bytes.with(|b| {
            b.as_ref().map(|v| {
                let bytes = v.as_slice();
                (encode_base64_url(bytes), bytes.len())
            })
        });

        let Some((b64, len)) = bytes_from_patch.or(bytes_from_raw) else {
            let Some(id) = current_message_id.get_untracked() else {
                toast.show(ToastKind::Error, "No message selected.");
                return;
            };
            spawn_local(async move {
                let loaded = match messages::load_message_bytes(id).await {
                    Ok(v) => v,
                    Err(msg) => {
                        toast.show(ToastKind::Error, msg);
                        return;
                    }
                };
                let bytes = loaded.bytes.as_slice();
                let b64 = encode_base64_url(bytes);
                let len = bytes.len();

                let hash = format!("base64={b64}");
                let url = match build_share_url(&hash) {
                    Ok(v) => v,
                    Err(msg) => {
                        toast.show(ToastKind::Error, msg);
                        return;
                    }
                };

                match clipboard_write_text(&url) {
                    Ok(_promise) => {
                        let msg = format!("Copy URL requested: {len} bytes.");
                        toast.show(ToastKind::Success, msg);
                    }
                    Err(msg) => toast.show(ToastKind::Error, msg),
                }
            });
            return;
        };

        let hash = format!("base64={b64}");
        let url = match build_share_url(&hash) {
            Ok(v) => v,
            Err(msg) => {
                toast.show(ToastKind::Error, msg);
                return;
            }
        };

        match clipboard_write_text(&url) {
            Ok(_promise) => {
                let msg = format!("Copy URL requested: {len} bytes.");
                toast.show(ToastKind::Success, msg);
            }
            Err(msg) => toast.show(ToastKind::Error, msg),
        }
    }

    /// Trigger a binary file download of the current message bytes.
    pub(crate) fn download_bin(&self) {
        let this = self.clone();
        let patch_state = this.ws.patch_state;
        let raw_bytes = this.ws.raw_bytes;
        let dirty_count = this.ws.dirty_count;
        let toast = this.toast;
        let current_message_id = this.catalog.current_message_id;
        let message_name_text = this.catalog.message_name_text;

        let Some(id) = current_message_id.get_untracked() else {
            toast.show(ToastKind::Error, "No message selected.");
            return;
        };

        let filename = messages::download_filename(&message_name_text.get_untracked(), id);

        let from_patch = patch_state.with(|p| {
            p.as_ref().map(|patch| {
                let bytes = patch.root_bytes();
                (download_bytes(&filename, bytes), bytes.len())
            })
        });
        let from_raw = raw_bytes.with(|b| {
            b.as_ref().map(|v| {
                let bytes = v.as_slice();
                (download_bytes(&filename, bytes), bytes.len())
            })
        });

        let Some((res, len)) = from_patch.or(from_raw) else {
            spawn_local(async move {
                let loaded = match messages::load_message_bytes(id).await {
                    Ok(v) => v,
                    Err(msg) => {
                        toast.show(ToastKind::Error, msg);
                        return;
                    }
                };
                let bytes = loaded.bytes.as_slice();
                let len = bytes.len();
                match download_bytes(&filename, bytes) {
                    Ok(()) => {
                        let pending = dirty_count.get_untracked();
                        let msg = if pending == 0 {
                            format!("Started download: {filename} ({len} bytes).")
                        } else {
                            format!(
                                "Started download: {filename} ({len} bytes). ({pending} edit(s) pending.)"
                            )
                        };
                        toast.show(ToastKind::Success, msg);
                    }
                    Err(msg) => toast.show(ToastKind::Error, msg),
                }
            });
            return;
        };

        match res {
            Ok(()) => {
                let pending = dirty_count.get_untracked();
                let msg = if pending == 0 {
                    format!("Started download: {filename} ({len} bytes).")
                } else {
                    format!(
                        "Started download: {filename} ({len} bytes). ({pending} edit(s) pending.)"
                    )
                };
                toast.show(ToastKind::Success, msg);
            }
            Err(msg) => toast.show(ToastKind::Error, msg),
        }
    }
}
