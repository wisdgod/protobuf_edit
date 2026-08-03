use crate::hex_copy::CopyFormat;
use crate::messages;
use crate::state::{MessageCatalogState, TabsState, WorkspaceState};
use crate::toast::{ToastKind, ToastManager};
use crate::web::{build_share_url, clipboard_write_text, download_bytes};
use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;

use crate::decode::encode_base64_url;

#[derive(Clone)]
pub(crate) struct ExportService {
    tabs: TabsState,
    catalog: MessageCatalogState,
    toast: ToastManager,
}

impl ExportService {
    pub(crate) const fn new(
        tabs: TabsState,
        catalog: MessageCatalogState,
        toast: ToastManager,
    ) -> Self {
        Self { tabs, catalog, toast }
    }

    fn active_dirty_count(&self) -> usize {
        self.tabs.active_ws_untracked().map_or(0, |ws| ws.dirty_count.get_untracked())
    }

    /// Runs `f` over a workspace's displayed bytes without copying them.
    ///
    /// Prefers the patch's byte mirror, then raw bytes; `None` means nothing
    /// is loaded in the workspace.
    fn with_bytes_of<R>(ws: &WorkspaceState, f: impl FnOnce(&[u8]) -> R) -> Option<R> {
        if ws.patch_bytes.with_untracked(Option::is_some) {
            return ws.patch_bytes.with_untracked(|b| b.as_ref().map(|v| f(v.as_slice())));
        }
        ws.raw_bytes.with_untracked(|b| b.as_ref().map(|v| f(v.as_slice())))
    }

    /// `with_bytes_of` against the active tab's message workspace (callers
    /// fall back to IndexedDB when `None`).
    fn with_current_bytes<R>(&self, f: impl FnOnce(&[u8]) -> R) -> Option<R> {
        let ws = self.tabs.active_ws_untracked()?;
        Self::with_bytes_of(&ws, f)
    }

    fn show_copied(toast: ToastManager, pending: usize, label: &str, len: usize) {
        let msg = if pending == 0 {
            format!("Copied {label}: {len} bytes.")
        } else {
            format!("Copied {label}: {len} bytes. ({pending} edit(s) pending.)")
        };
        toast.show(ToastKind::Success, msg);
    }

    fn copy_and_toast(toast: ToastManager, pending: usize, label: &str, len: usize, text: &str) {
        match clipboard_write_text(text) {
            Ok(_) => Self::show_copied(toast, pending, label, len),
            Err(msg) => toast.show(ToastKind::Error, msg),
        }
    }

    fn copy_share_url_text(toast: ToastManager, b64: &str, len: usize) {
        let hash = format!("base64={b64}");
        let url = match build_share_url(&hash) {
            Ok(v) => v,
            Err(msg) => {
                toast.show(ToastKind::Error, msg);
                return;
            }
        };
        match clipboard_write_text(&url) {
            Ok(_) => toast.show(ToastKind::Success, format!("Copy URL requested: {len} bytes.")),
            Err(msg) => toast.show(ToastKind::Error, msg),
        }
    }

    fn show_download_result(
        toast: ToastManager,
        pending: usize,
        filename: &str,
        len: usize,
        res: Result<(), crate::error::UiError>,
    ) {
        match res {
            Ok(()) => {
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

    pub(crate) fn copy_as(&self, fmt: CopyFormat) {
        let toast = self.toast;
        let dirty = self.active_dirty_count();

        if let Some((text, len)) = self.with_current_bytes(|bytes| (fmt.format(bytes), bytes.len()))
        {
            Self::copy_and_toast(toast, dirty, fmt.label(), len, &text);
            return;
        }

        let Some(id) = self.tabs.active_message_id_untracked() else {
            toast.show(ToastKind::Error, "No message open.");
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
            let text = fmt.format(bytes);
            Self::copy_and_toast(toast, dirty, fmt.label(), bytes.len(), &text);
        });
    }

    /// Copy a byte range from a specific workspace (the hex grid passes its
    /// own, so this also works inside the read-only envelope preview).
    pub(crate) fn copy_range_as(
        &self,
        ws: &WorkspaceState,
        start: usize,
        end: usize,
        fmt: CopyFormat,
    ) {
        let toast = self.toast;

        let copied = Self::with_bytes_of(ws, |bytes| {
            let slice = &bytes[start.min(bytes.len())..end.min(bytes.len())];
            (fmt.format(slice), slice.len())
        });

        let Some((text, len)) = copied else {
            toast.show(ToastKind::Error, "No data loaded.");
            return;
        };

        match clipboard_write_text(&text) {
            Ok(_) => {
                toast.show(ToastKind::Success, format!("Copied {}: {len} byte(s).", fmt.label()));
            }
            Err(msg) => toast.show(ToastKind::Error, msg),
        }
    }

    pub(crate) fn copy_share_url(&self) {
        let toast = self.toast;

        if let Some((b64, len)) =
            self.with_current_bytes(|bytes| (encode_base64_url(bytes), bytes.len()))
        {
            Self::copy_share_url_text(toast, &b64, len);
            return;
        }

        let Some(id) = self.tabs.active_message_id_untracked() else {
            toast.show(ToastKind::Error, "No message open.");
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
            Self::copy_share_url_text(toast, &encode_base64_url(bytes), bytes.len());
        });
    }

    pub(crate) fn download_bin(&self) {
        let toast = self.toast;
        let message_name_text = self.catalog.message_name_text;
        let dirty = self.active_dirty_count();

        let Some(id) = self.tabs.active_message_id_untracked() else {
            toast.show(ToastKind::Error, "No message open.");
            return;
        };

        let filename = messages::download_filename(&message_name_text.get_untracked(), id);

        if let Some((res, len)) =
            self.with_current_bytes(|bytes| (download_bytes(&filename, bytes), bytes.len()))
        {
            Self::show_download_result(toast, dirty, &filename, len, res);
            return;
        }

        spawn_local(async move {
            let loaded = match messages::load_message_bytes(id).await {
                Ok(v) => v,
                Err(msg) => {
                    toast.show(ToastKind::Error, msg);
                    return;
                }
            };
            let bytes = loaded.bytes.as_slice();
            let res = download_bytes(&filename, bytes);
            Self::show_download_result(toast, dirty, &filename, bytes.len(), res);
        });
    }
}
