use crate::bytes::ByteView;
use crate::decode::{decode_base64_url, decode_user_input};
use crate::messages::{self, LoadedBytesMode, MessageId};
use crate::services::WorkspaceService;
use crate::state::{MessageCatalogState, Tab, TabId, TabsState, WorkspaceState};
use crate::toast::{ToastKind, ToastManager};
use crate::web::get_url_hash;
use leptos::prelude::*;
use std::sync::Arc;
use wasm_bindgen_futures::spawn_local;

/// Manages the message catalog and the open working set: creating, deleting,
/// renaming, importing, and opening messages as tabs.
#[derive(Clone)]
pub(crate) struct MessageService {
    tabs: TabsState,
    catalog: MessageCatalogState,
    toast: ToastManager,
    ws_svc: WorkspaceService,
}

impl MessageService {
    pub(crate) const fn new(
        tabs: TabsState,
        catalog: MessageCatalogState,
        toast: ToastManager,
        ws_svc: WorkspaceService,
    ) -> Self {
        Self { tabs, catalog, toast, ws_svc }
    }

    // ------------------------------------------------------------------
    // Refresh
    // ------------------------------------------------------------------

    /// Reload the message list from IndexedDB.
    pub(crate) async fn refresh_inner(&self) {
        let toast = self.toast;
        let messages_list = self.catalog.messages_list;

        let list = match messages::list_messages().await {
            Ok(v) => v,
            Err(msg) => {
                toast.show(ToastKind::Alert, format!("Failed to load messages: {msg}"));
                Vec::new()
            }
        };
        messages_list.set(list);
    }

    // ------------------------------------------------------------------
    // Open (tab focus or create)
    // ------------------------------------------------------------------

    fn tab_is_empty(ws: &WorkspaceState) -> bool {
        ws.session.with_untracked(Option::is_none)
            && ws.raw_bytes.with_untracked(Option::is_none)
    }

    /// Open a message: focus its existing tab, or create a new tab and load
    /// the bytes into it.
    pub(crate) fn switch_to(&self, id: MessageId) {
        let tab = self.tabs.find_message(id).unwrap_or_else(|| self.tabs.push_message_tab(id));
        self.tabs.activate(tab.id);
        if tab.message_ws().is_some_and(|ws| Self::tab_is_empty(&ws)) {
            self.load_into(&tab);
        }
    }

    /// Async-load a message tab's bytes into its workspace, guarded by the
    /// tab's nonce (stale loads and closed tabs are dropped).
    fn load_into(&self, tab: &Tab) {
        let Some(ws) = tab.message_ws() else {
            return;
        };
        let id = tab.message_id;
        let nonce = tab.load_nonce.get_untracked().wrapping_add(1);
        tab.load_nonce.set(nonce);
        ws.clear_loaded_data();

        let messages_list = self.catalog.messages_list;
        let name = messages_list
            .with_untracked(|list| list.iter().find(|m| m.id == id).map(|m| m.name.clone()))
            .unwrap_or_else(|| Arc::<str>::from(format!("Message {id}")));
        let label = format!("message \"{name}\"");
        let class_id = messages_list
            .with_untracked(|list| list.iter().find(|m| m.id == id).map(|m| m.class_id))
            .unwrap_or(id);

        let tabs = self.tabs.clone();
        let ws_svc = self.ws_svc.clone();
        let toast = self.toast;
        let tab = tab.clone();
        spawn_local(async move {
            let stale = move || tab.load_nonce.get_untracked() != nonce || !tabs.contains(tab.id);
            match messages::load_message_bytes(id).await {
                Ok(loaded) => {
                    if stale() {
                        return;
                    }
                    match loaded.mode {
                        LoadedBytesMode::Protobuf => {
                            let auto_expand = match messages::load_auto_expand_paths(class_id).await
                            {
                                Ok(v) => v,
                                Err(msg) => {
                                    toast.show(ToastKind::Alert, msg);
                                    Vec::new()
                                }
                            };
                            if stale() {
                                return;
                            }
                            ws_svc.load_document_into(&ws, &label, loaded.bytes, auto_expand);
                        }
                        LoadedBytesMode::Raw => {
                            ws.show_root_raw_bytes(loaded.bytes);
                            if let Some(note) = loaded.note {
                                toast.show(ToastKind::Notice, note);
                            }
                        }
                    }
                }
                Err(msg) => {
                    if stale() {
                        return;
                    }
                    toast.show(ToastKind::Alert, format!("Failed to load message bytes: {msg}"));
                }
            }
        });
    }

    /// Open a brand-new message (bytes already in hand) as an active tab,
    /// skipping the IndexedDB round-trip.
    fn open_new_with_bytes(&self, id: MessageId, label: &str, bytes: Vec<u8>) {
        let tab = self.tabs.push_message_tab(id);
        self.tabs.activate(tab.id);
        if let Some(ws) = tab.message_ws() {
            self.ws_svc.load_document_into(&ws, label, ByteView::from_vec(bytes), Vec::new());
        }
    }

    /// Close a tab; dirty message tabs require confirmation.
    pub(crate) fn close_tab(&self, tab_id: TabId) {
        let Some(tab) = self.tabs.get(tab_id) else {
            return;
        };
        if let Some(ws) = tab.message_ws()
            && ws.dirty_fields.with_untracked(|s| !s.is_empty())
            && !self.ws_svc.confirm_discard_ws(&ws, "close this tab")
        {
            return;
        }
        self.tabs.close(tab_id);
    }

    // ------------------------------------------------------------------
    // Create / Delete / Rename
    // ------------------------------------------------------------------

    /// Create a new empty message and open it in a new tab.
    pub(crate) fn create(&self) {
        let this = self.clone();
        let name = "New message";
        let bytes_value = js_sys::Uint8Array::new_with_length(0);
        let toast = self.toast;
        spawn_local(async move {
            match messages::create_message(name, 0, bytes_value).await {
                Ok(id) => {
                    this.refresh_inner().await;
                    this.open_new_with_bytes(
                        id,
                        &format!("new \u{2192} message \"{name}\""),
                        Vec::new(),
                    );
                }
                Err(msg) => toast.show(ToastKind::Alert, msg),
            }
        });
    }

    /// Delete the given message IDs after user confirmation; open tabs for
    /// deleted messages are closed.
    pub(crate) fn delete(&self, ids: Vec<MessageId>) {
        let mut ids = ids;
        ids.sort_unstable();
        ids.dedup();
        if ids.is_empty() {
            return;
        }

        let toast = self.toast;

        // Deleting a message also closes its envelope tab, if any.
        let open_tabs: Vec<TabId> = self.tabs.tabs.with_untracked(|v| {
            v.iter().filter(|t| ids.contains(&t.message_id)).map(|t| t.id).collect()
        });

        let Some(window) = web_sys::window() else {
            return;
        };
        let msg = if open_tabs.is_empty() {
            format!("Delete {} message(s)?", ids.len())
        } else {
            format!(
                "Delete {} message(s)? Open tab(s) for deleted messages will be closed.",
                ids.len()
            )
        };
        let confirmed = window.confirm_with_message(&msg).unwrap_or(false);
        if !confirmed {
            return;
        }

        // Deletion supersedes any pending edits; close without asking again.
        for tab_id in open_tabs {
            self.tabs.close(tab_id);
        }

        let this = self.clone();
        spawn_local(async move {
            let (deleted, failed) = match messages::delete_messages(&ids).await {
                Ok(counts) => counts,
                Err(msg) => {
                    toast.show(ToastKind::Alert, msg);
                    return;
                }
            };
            if failed != 0 {
                toast.show(ToastKind::Alert, format!("Failed to delete {failed} message(s)."));
            }

            this.refresh_inner().await;
            toast.show(ToastKind::Notice, format!("Deleted {deleted} message(s)."));
        });
    }

    /// Rename a single message by ID.
    pub(crate) fn rename(&self, id: MessageId, name: Arc<str>) {
        if name.is_empty() {
            return;
        }
        let this = self.clone();
        let toast = self.toast;
        spawn_local(async move {
            if let Err(msg) = messages::rename_message(id, &name).await {
                toast.show(ToastKind::Alert, msg);
                return;
            }
            this.refresh_inner().await;
        });
    }

    /// Rename an entire class of messages.
    pub(crate) fn rename_class(&self, class_id: MessageId, name: Arc<str>) {
        if name.is_empty() {
            return;
        }
        let this = self.clone();
        let toast = self.toast;
        spawn_local(async move {
            if let Err(msg) = messages::rename_class(class_id, &name).await {
                toast.show(ToastKind::Alert, msg);
                return;
            }
            this.refresh_inner().await;
        });
    }

    // ------------------------------------------------------------------
    // Import
    // ------------------------------------------------------------------

    /// Decode user-provided text (hex / base64 / raw), create a new message,
    /// and open it in a new tab.
    pub(crate) fn import_text(&self, label: &str, input: &str, name_prefix: &str) {
        let toast = self.toast;
        let import_name_text = self.catalog.import_name_text;
        match decode_user_input(input) {
            Ok(bytes) => {
                let label = Arc::<str>::from(label);
                let name = import_name_text.get_untracked();
                let name: Arc<str> = if name.trim().is_empty() {
                    Arc::<str>::from(format!("{name_prefix} ({}B)", bytes.len()))
                } else {
                    Arc::<str>::from(name.trim())
                };
                let bytes_len = bytes.len();
                let bytes_value = js_sys::Uint8Array::from(bytes.as_slice());
                let this = self.clone();
                spawn_local(async move {
                    match messages::create_message(&name, bytes_len, bytes_value).await {
                        Ok(id) => {
                            this.refresh_inner().await;
                            this.open_new_with_bytes(
                                id,
                                &format!("{label} \u{2192} message \"{name}\""),
                                bytes,
                            );
                        }
                        Err(msg) => toast.show(ToastKind::Alert, msg),
                    }
                });
            }
            Err(msg) => toast.show(ToastKind::Alert, format!("Failed to decode {label}: {msg}")),
        }
    }

    /// Handle the "Import" button click: store the frame name template and
    /// import raw input text as a new protobuf message.
    pub(crate) fn on_import_click(&self) {
        let frame_name_template_text = self.catalog.frame_name_template_text;
        if let Err(msg) =
            messages::store_frame_name_template(&frame_name_template_text.get_untracked())
        {
            self.toast.show(ToastKind::Alert, msg);
        }
        let input = self.catalog.raw_input.get_untracked();
        self.import_text("input", &input, "Import");
    }

    // ------------------------------------------------------------------
    // Upload
    // ------------------------------------------------------------------

    /// Handle a file upload `<input>` change event.
    pub(crate) fn upload(&self, ev: &leptos::ev::Event) {
        let input: web_sys::HtmlInputElement = event_target(ev);
        let Some(file) = input.files().and_then(|files| files.get(0)) else {
            return;
        };
        self.import_file(file);
    }

    /// Read a file (upload input or drag-and-drop) as bytes, create a new
    /// message, and open it in a new tab.
    pub(crate) fn import_file(&self, file: web_sys::File) {
        let filename = file.name();

        // Blob::array_buffer is promise-based, so no FileReader callback (and
        // no leaked Closure) is needed.
        let this = self.clone();
        spawn_local(async move {
            let Ok(result) = wasm_bindgen_futures::JsFuture::from(file.array_buffer()).await else {
                this.toast.show(ToastKind::Alert, "Failed to read file contents.");
                return;
            };
            let u8_array = js_sys::Uint8Array::new(&result);
            let mut bytes = vec![0u8; u8_array.length() as usize];
            u8_array.copy_to(&mut bytes);

            let toast = this.toast;
            let import_name = this.catalog.import_name_text.get_untracked();
            let name: Arc<str> = if import_name.trim().is_empty() {
                Arc::<str>::from(format!("Upload: {filename}"))
            } else {
                Arc::<str>::from(import_name.trim())
            };
            let bytes_len = bytes.len();
            let bytes_value = js_sys::Uint8Array::from(bytes.as_slice());

            match messages::create_message(&name, bytes_len, bytes_value).await {
                Ok(id) => {
                    this.refresh_inner().await;
                    this.open_new_with_bytes(
                        id,
                        &format!("upload \u{2192} message \"{name}\""),
                        bytes,
                    );
                }
                Err(msg) => toast.show(ToastKind::Alert, msg),
            }
        });
    }

    // ------------------------------------------------------------------
    // Bump modified timestamp
    // ------------------------------------------------------------------

    /// Touch the modified timestamp of the active message so it reorders
    /// in the list.
    pub(crate) fn bump_modified(&self) {
        let toast = self.toast;
        let Some(id) = self.tabs.active_message_id_untracked() else {
            toast.show(ToastKind::Alert, "No message open.");
            return;
        };
        let this = self.clone();
        spawn_local(async move {
            if let Err(msg) = messages::bump_message_modified(id).await {
                toast.show(ToastKind::Alert, msg);
                return;
            }
            this.refresh_inner().await;
            toast.show(ToastKind::Notice, "Updated modified time (reordered messages).");
        });
    }

    // ------------------------------------------------------------------
    // Bootstrap
    // ------------------------------------------------------------------

    /// Run the one-time bootstrap sequence: load preferences, refresh the
    /// message list, restore the persisted working set, and optionally
    /// import a `#base64=...` URL hash as a new tab.
    pub(crate) fn bootstrap(&self) {
        let this = self.clone();
        let frame_name_template_text = self.catalog.frame_name_template_text;
        let raw_input = self.catalog.raw_input;
        let toast = self.toast;

        spawn_local(async move {
            match messages::load_frame_name_template() {
                Ok(v) => frame_name_template_text.set(v),
                Err(msg) => toast.show(ToastKind::Alert, msg),
            }

            this.refresh_inner().await;

            let hash = match get_url_hash() {
                Ok(h) => h,
                Err(msg) => {
                    toast.show(ToastKind::Alert, msg);
                    return;
                }
            };

            let Some(b64) = hash.strip_prefix("#base64=").or_else(|| hash.strip_prefix("#b64="))
            else {
                this.restore_working_set();
                return;
            };
            if b64.is_empty() {
                this.restore_working_set();
                return;
            }

            match decode_base64_url(b64) {
                Ok(bytes) => {
                    raw_input.set(b64.to_string());
                    let name = format!("From URL hash ({}B)", bytes.len());
                    let bytes_len = bytes.len();
                    let bytes_value = js_sys::Uint8Array::from(bytes.as_slice());
                    match messages::create_message(&name, bytes_len, bytes_value).await {
                        Ok(id) => {
                            this.refresh_inner().await;
                            this.restore_working_set();
                            this.open_new_with_bytes(
                                id,
                                &format!("URL hash \u{2192} message \"{name}\""),
                                bytes,
                            );
                            toast.show(
                                ToastKind::Notice,
                                format!("Imported URL hash as message \"{name}\"."),
                            );
                        }
                        Err(msg) => toast.show(ToastKind::Alert, msg),
                    }
                }
                Err(msg) => toast.show(ToastKind::Alert, msg),
            }
        });
    }

    /// Recreate tabs for the persisted working set; the previously active
    /// tab is focused and loaded, the rest load lazily on activation.
    fn restore_working_set(&self) {
        let existing: Vec<MessageId> =
            self.catalog.messages_list.with_untracked(|l| l.iter().map(|m| m.id).collect());

        let saved = messages::open_tabs().unwrap_or_default();
        for entry in saved {
            if !existing.contains(&entry.message_id()) {
                continue;
            }
            match entry {
                messages::PersistedTab::Message(id) => {
                    if self.tabs.find_message(id).is_none() {
                        let _ = self.tabs.push_message_tab(id);
                    }
                }
                messages::PersistedTab::Envelope(id) => {
                    if self.tabs.find_envelope(id).is_none() {
                        let _ = self.tabs.push_envelope_tab(id);
                    }
                }
            }
        }

        match messages::active_tab().ok().flatten() {
            Some(messages::PersistedTab::Message(mid)) if self.tabs.find_message(mid).is_some() => {
                self.switch_to(mid);
            }
            Some(messages::PersistedTab::Envelope(mid)) => {
                // Envelope tab bodies load themselves on mount.
                if let Some(tab) = self.tabs.find_envelope(mid) {
                    self.tabs.activate(tab.id);
                }
            }
            _ => {}
        }
    }
}
