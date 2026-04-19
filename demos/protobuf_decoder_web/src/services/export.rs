use crate::hex_copy::CopyFormat;
use crate::messages;
use crate::state::{MessageCatalogState, WorkspaceState};
use crate::toast::{ToastKind, ToastManager};
use crate::web::{build_share_url, clipboard_write_text, download_bytes};
use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;

use crate::decode::encode_base64_url;

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

    fn read_bytes(&self) -> Option<(Vec<u8>, usize)> {
        let from_patch = self.ws.patch_state.with(|p| {
            p.as_ref().map(|patch| {
                let bytes = patch.root_bytes();
                (bytes.to_vec(), bytes.len())
            })
        });
        from_patch.or_else(|| {
            self.ws.raw_bytes.with(|b| {
                b.as_ref().map(|v| {
                    let bytes = v.as_slice();
                    (bytes.to_vec(), bytes.len())
                })
            })
        })
    }

    pub(crate) fn copy_as(&self, fmt: CopyFormat) {
        let dirty_count = self.ws.dirty_count;
        let toast = self.toast;
        let current_message_id = self.catalog.current_message_id;

        if let Some((bytes, len)) = self.read_bytes() {
            let text = fmt.format(&bytes);
            match clipboard_write_text(&text) {
                Ok(_) => {
                    let pending = dirty_count.get_untracked();
                    let label = fmt.label();
                    let msg = if pending == 0 {
                        format!("Copied {label}: {len} bytes.")
                    } else {
                        format!("Copied {label}: {len} bytes. ({pending} edit(s) pending.)")
                    };
                    toast.show(ToastKind::Success, msg);
                }
                Err(msg) => toast.show(ToastKind::Error, msg),
            }
            return;
        }

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
            let len = bytes.len();
            let text = fmt.format(bytes);
            match clipboard_write_text(&text) {
                Ok(_) => {
                    let pending = dirty_count.get_untracked();
                    let label = fmt.label();
                    let msg = if pending == 0 {
                        format!("Copied {label}: {len} bytes.")
                    } else {
                        format!("Copied {label}: {len} bytes. ({pending} edit(s) pending.)")
                    };
                    toast.show(ToastKind::Success, msg);
                }
                Err(msg) => toast.show(ToastKind::Error, msg),
            }
        });
    }

    pub(crate) fn copy_range_as(&self, start: usize, end: usize, fmt: CopyFormat) {
        let toast = self.toast;

        let bytes = self.ws.patch_state.with(|p| {
            p.as_ref().map(|patch| {
                let b = patch.root_bytes();
                b[start..end.min(b.len())].to_vec()
            })
        });
        let bytes = bytes.or_else(|| {
            self.ws.raw_bytes.with(|b| {
                b.as_ref().map(|v| {
                    let b = v.as_slice();
                    b[start..end.min(b.len())].to_vec()
                })
            })
        });

        let Some(bytes) = bytes else {
            toast.show(ToastKind::Error, "No data loaded.");
            return;
        };

        let len = bytes.len();
        let text = fmt.format(&bytes);
        match clipboard_write_text(&text) {
            Ok(_) => {
                let label = fmt.label();
                toast.show(ToastKind::Success, format!("Copied {label}: {len} byte(s)."));
            }
            Err(msg) => toast.show(ToastKind::Error, msg),
        }
    }

    pub(crate) fn copy_share_url(&self) {
        let toast = self.toast;
        let current_message_id = self.catalog.current_message_id;

        let b64_and_len = self.ws.patch_state.with(|p| {
            p.as_ref().map(|patch| {
                let bytes = patch.root_bytes();
                (encode_base64_url(bytes), bytes.len())
            })
        });
        let b64_and_len = b64_and_len.or_else(|| {
            self.ws.raw_bytes.with(|b| {
                b.as_ref().map(|v| {
                    let bytes = v.as_slice();
                    (encode_base64_url(bytes), bytes.len())
                })
            })
        });

        let Some((b64, len)) = b64_and_len else {
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
                    Ok(_) => {
                        toast.show(ToastKind::Success, format!("Copy URL requested: {len} bytes."))
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
            Ok(_) => toast.show(ToastKind::Success, format!("Copy URL requested: {len} bytes.")),
            Err(msg) => toast.show(ToastKind::Error, msg),
        }
    }

    pub(crate) fn download_bin(&self) {
        let dirty_count = self.ws.dirty_count;
        let toast = self.toast;
        let current_message_id = self.catalog.current_message_id;
        let message_name_text = self.catalog.message_name_text;

        let Some(id) = current_message_id.get_untracked() else {
            toast.show(ToastKind::Error, "No message selected.");
            return;
        };

        let filename = messages::download_filename(&message_name_text.get_untracked(), id);

        let from_patch = self.ws.patch_state.with(|p| {
            p.as_ref().map(|patch| {
                let bytes = patch.root_bytes();
                (download_bytes(&filename, bytes), bytes.len())
            })
        });
        let from_raw = from_patch.or_else(|| {
            self.ws.raw_bytes.with(|b| {
                b.as_ref().map(|v| {
                    let bytes = v.as_slice();
                    (download_bytes(&filename, bytes), bytes.len())
                })
            })
        });

        let Some((res, len)) = from_raw else {
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
