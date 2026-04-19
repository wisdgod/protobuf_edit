use crate::bytes::ByteView;
use crate::decode::{decode_base64_url, decode_user_input};
use crate::messages::{self, LoadedBytesMode, MessageId};
use crate::services::WorkspaceService;
use crate::state::{MessageCatalogState, WorkspaceState};
use crate::toast::{ToastKind, ToastManager};
use crate::web::get_url_hash;
use leptos::prelude::*;
use std::sync::Arc;
use wasm_bindgen::closure::Closure;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::spawn_local;

/// Manages the message catalog: creating, deleting, renaming, switching,
/// importing bytes, uploading files, and bootstrapping from a URL hash.
#[derive(Clone)]
pub(crate) struct MessageService {
    ws: WorkspaceState,
    catalog: MessageCatalogState,
    toast: ToastManager,
    ws_svc: WorkspaceService,
    load_nonce: RwSignal<u64>,
}

impl MessageService {
    pub(crate) fn new(
        ws: WorkspaceState,
        catalog: MessageCatalogState,
        toast: ToastManager,
        ws_svc: WorkspaceService,
        load_nonce: RwSignal<u64>,
    ) -> Self {
        Self { ws, catalog, toast, ws_svc, load_nonce }
    }

    // ------------------------------------------------------------------
    // Refresh
    // ------------------------------------------------------------------

    /// Inner async implementation of message list reload.
    pub(crate) async fn refresh_inner(&self) {
        let toast = self.toast;
        let messages_list = self.catalog.messages_list;
        let current_message_id = self.catalog.current_message_id;
        let message_name_text = self.catalog.message_name_text;

        let list = match messages::list_messages().await {
            Ok(v) => v,
            Err(msg) => {
                toast.show(ToastKind::Error, format!("Failed to load messages: {msg}"));
                Vec::new()
            }
        };

        let mut current = match messages::current_message() {
            Ok(v) => v,
            Err(msg) => {
                toast.show(ToastKind::Error, format!("Failed to read current message: {msg}"));
                None
            }
        };

        if current.is_some() && !list.iter().any(|m| Some(m.id) == current) {
            current = None;
        }

        if current.is_none() && !list.is_empty() {
            current = Some(list[0].id);
            let _ = messages::set_current_message(current);
        }

        let name = current
            .and_then(|id| list.iter().find(|m| m.id == id).map(|m| m.name.as_ref()))
            .unwrap_or("");
        let needs_update = message_name_text.with_untracked(|s| s.as_str() != name);
        if needs_update {
            message_name_text.update(|s| {
                s.clear();
                s.push_str(name);
            });
        }

        messages_list.set(list);
        current_message_id.set(current);
    }

    // ------------------------------------------------------------------
    // Switch
    // ------------------------------------------------------------------

    /// Switch the workspace to show a specific message by ID.
    pub(crate) fn switch_to(&self, id: MessageId) {
        let this = self.clone();
        let current_message_id = self.catalog.current_message_id;
        let messages_list = self.catalog.messages_list;
        let message_name_text = self.catalog.message_name_text;
        let dirty_fields = self.ws.dirty_fields;
        let load_nonce = self.load_nonce;
        let toast = self.toast;

        let already_current = current_message_id.get_untracked() == Some(id);
        if dirty_fields.with_untracked(|s| !s.is_empty())
            && !this.ws_svc.confirm_discard("switch messages")
        {
            return;
        }

        if !already_current && let Err(msg) = messages::set_current_message(Some(id)) {
            toast.show(ToastKind::Error, msg);
            return;
        }

        current_message_id.set(Some(id));

        let name = messages_list
            .with_untracked(|list| list.iter().find(|m| m.id == id).map(|m| m.name.clone()))
            .unwrap_or_else(|| Arc::<str>::from(format!("Message {id}")));
        message_name_text.update(|s| {
            s.clear();
            s.push_str(name.as_ref());
        });

        this.ws.clear_loaded_data();

        let nonce = load_nonce.get_untracked().wrapping_add(1);
        load_nonce.set(nonce);

        let label = format!("message \"{name}\"");
        let class_id = messages_list
            .with_untracked(|list| list.iter().find(|m| m.id == id).map(|m| m.class_id))
            .unwrap_or(id);
        let ws_svc = this.ws_svc.clone();
        let ws = this.ws.clone();
        spawn_local(async move {
            match messages::load_message_bytes(id).await {
                Ok(loaded) => {
                    if load_nonce.get_untracked() != nonce
                        || current_message_id.get_untracked() != Some(id)
                    {
                        return;
                    }
                    match loaded.mode {
                        LoadedBytesMode::Protobuf => {
                            let auto_expand = match messages::load_auto_expand_paths(class_id).await
                            {
                                Ok(v) => v,
                                Err(msg) => {
                                    toast.show(ToastKind::Error, msg);
                                    Vec::new()
                                }
                            };
                            ws_svc.load_patch(&label, loaded.bytes, auto_expand);
                        }
                        LoadedBytesMode::Raw => {
                            ws.show_root_raw_bytes(loaded.bytes);
                            if let Some(note) = loaded.note {
                                toast.show(ToastKind::Success, note);
                            }
                        }
                    }
                }
                Err(msg) => {
                    if load_nonce.get_untracked() != nonce
                        || current_message_id.get_untracked() != Some(id)
                    {
                        return;
                    }
                    toast.show(ToastKind::Error, format!("Failed to load message bytes: {msg}"));
                }
            }
        });
    }

    // ------------------------------------------------------------------
    // Create / Delete / Rename
    // ------------------------------------------------------------------

    /// Create a new empty message and switch to it.
    pub(crate) fn create(&self) {
        if !self.ws_svc.confirm_discard("create a new message") {
            return;
        }
        let this = self.clone();
        let name = "New message";
        let bytes_value = js_sys::Uint8Array::new_with_length(0);
        let current_message_id = this.catalog.current_message_id;
        let message_name_text = this.catalog.message_name_text;
        let toast = this.toast;
        spawn_local(async move {
            match messages::create_message(name, 0, bytes_value).await {
                Ok(id) => {
                    this.refresh_inner().await;
                    current_message_id.set(Some(id));
                    message_name_text.update(|s| {
                        s.clear();
                        s.push_str(name);
                    });
                    this.ws_svc.load_patch(
                        &format!("new \u{2192} message \"{name}\""),
                        ByteView::from_vec(Vec::new()),
                        Vec::new(),
                    );
                }
                Err(msg) => toast.show(ToastKind::Error, msg),
            }
        });
    }

    /// Delete the given message IDs after user confirmation.
    pub(crate) fn delete(&self, ids: Vec<MessageId>) {
        let mut ids = ids;
        ids.sort_unstable();
        ids.dedup();
        if ids.is_empty() {
            return;
        }

        let current_message_id = self.catalog.current_message_id;
        let dirty_fields = self.ws.dirty_fields;
        let patch_state = self.ws.patch_state;
        let patch_bytes = self.ws.patch_bytes;
        let raw_bytes = self.ws.raw_bytes;
        let envelope_view = self.ws.envelope_view;
        let toast = self.toast;

        let current = current_message_id.get_untracked();
        let deleting_current = current.is_some_and(|cur| ids.contains(&cur));

        if deleting_current
            && dirty_fields.with_untracked(|s| !s.is_empty())
            && !self.ws_svc.confirm_discard("delete selected messages")
        {
            return;
        }

        let Some(window) = web_sys::window() else {
            return;
        };
        let msg = if deleting_current {
            format!("Delete {} message(s) (including the current message)?", ids.len())
        } else {
            format!("Delete {} message(s)?", ids.len())
        };
        let confirmed = window.confirm_with_message(&msg).unwrap_or(false);
        if !confirmed {
            return;
        }

        if deleting_current {
            patch_state.set(None);
            patch_bytes.set(None);
            raw_bytes.set(None);
            envelope_view.set(None);
            self.ws.reset_ui_state();
        }

        let this = self.clone();
        spawn_local(async move {
            let mut deleted: usize = 0;
            for id in ids {
                match messages::delete_message(id).await {
                    Ok(()) => deleted = deleted.saturating_add(1),
                    Err(msg) => toast.show(ToastKind::Error, msg),
                }
            }

            this.refresh_inner().await;
            if deleting_current && let Some(next_id) = current_message_id.get_untracked() {
                this.switch_to(next_id);
            }

            toast.show(ToastKind::Success, format!("Deleted {deleted} message(s)."));
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
                toast.show(ToastKind::Error, msg);
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
                toast.show(ToastKind::Error, msg);
                return;
            }
            this.refresh_inner().await;
        });
    }

    // ------------------------------------------------------------------
    // Import
    // ------------------------------------------------------------------

    /// Decode user-provided text (hex / base64 / raw), create a new message,
    /// and load it into the workspace.
    pub(crate) fn import_text(&self, label: &str, input: &str, name_prefix: &str) {
        if !self.ws_svc.confirm_discard("import new bytes") {
            return;
        }
        let toast = self.toast;
        let import_name_text = self.catalog.import_name_text;
        let current_message_id = self.catalog.current_message_id;
        let message_name_text = self.catalog.message_name_text;
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
                            current_message_id.set(Some(id));
                            this.ws_svc.load_patch(
                                &format!("{label} \u{2192} message \"{name}\""),
                                ByteView::from_vec(bytes),
                                Vec::new(),
                            );
                            message_name_text.update(|s| {
                                s.clear();
                                s.push_str(name.as_ref());
                            });
                        }
                        Err(msg) => toast.show(ToastKind::Error, msg),
                    }
                });
            }
            Err(msg) => toast.show(ToastKind::Error, format!("Failed to decode {label}: {msg}")),
        }
    }

    /// Handle the "Import" button click: store the frame name template and
    /// import raw input text as a new protobuf message.
    pub(crate) fn on_import_click(&self) {
        let frame_name_template_text = self.catalog.frame_name_template_text;
        if let Err(msg) =
            messages::store_frame_name_template(&frame_name_template_text.get_untracked())
        {
            self.toast.show(ToastKind::Error, msg);
        }
        let input = self.catalog.raw_input.get_untracked();
        self.import_text("input", &input, "Import");
    }

    // ------------------------------------------------------------------
    // Upload
    // ------------------------------------------------------------------

    /// Handle a file upload `<input>` change event: read the file as an
    /// `ArrayBuffer`, create a new message, and load it.
    pub(crate) fn upload(&self, ev: leptos::ev::Event) {
        let input: web_sys::HtmlInputElement = event_target(&ev);
        let Some(files) = input.files() else {
            return;
        };
        let Some(file) = files.get(0) else {
            return;
        };
        let filename = file.name();

        let reader = match web_sys::FileReader::new() {
            Ok(r) => r,
            Err(_) => {
                self.toast.show(ToastKind::Error, "Failed to create FileReader.");
                return;
            }
        };
        let reader_for_cb = reader.clone();
        let this = self.clone();

        let onload = Closure::<dyn FnMut(web_sys::ProgressEvent)>::new(move |_| {
            let result = match reader_for_cb.result() {
                Ok(v) => v,
                Err(_) => {
                    this.toast.show(ToastKind::Error, "Failed to read file contents.");
                    return;
                }
            };
            let u8_array = js_sys::Uint8Array::new(&result);
            let mut bytes = vec![0u8; u8_array.length() as usize];
            u8_array.copy_to(&mut bytes);

            let import_name_text = this.catalog.import_name_text;
            let current_message_id = this.catalog.current_message_id;
            let message_name_text = this.catalog.message_name_text;
            let toast = this.toast;
            let import_name = import_name_text.get_untracked();
            let name: Arc<str> = if import_name.trim().is_empty() {
                Arc::<str>::from(format!("Upload: {filename}"))
            } else {
                Arc::<str>::from(import_name.trim())
            };
            let bytes_len = bytes.len();
            let bytes_value = js_sys::Uint8Array::from(bytes.as_slice());
            let inner = this.clone();
            spawn_local(async move {
                match messages::create_message(&name, bytes_len, bytes_value).await {
                    Ok(id) => {
                        inner.refresh_inner().await;
                        current_message_id.set(Some(id));
                        inner.ws_svc.load_patch(
                            &format!("upload \u{2192} message \"{name}\""),
                            ByteView::from_vec(bytes),
                            Vec::new(),
                        );
                        message_name_text.update(|s| {
                            s.clear();
                            s.push_str(name.as_ref());
                        });
                    }
                    Err(msg) => toast.show(ToastKind::Error, msg),
                }
            });
        });

        reader.set_onload(Some(onload.as_ref().unchecked_ref()));
        onload.forget();

        if reader.read_as_array_buffer(&file).is_err() {
            self.toast.show(ToastKind::Error, "Failed to start reading file.");
        }
    }

    // ------------------------------------------------------------------
    // Name change (debounced from sidebar input)
    // ------------------------------------------------------------------

    /// Called when the current message name text changes.
    pub(crate) fn on_message_name_change(&self, name: Arc<str>) {
        let current_message_id = self.catalog.current_message_id;
        let Some(id) = current_message_id.get_untracked() else {
            return;
        };
        if name.is_empty() {
            return;
        }
        let this = self.clone();
        let toast = self.toast;
        spawn_local(async move {
            if let Err(msg) = messages::rename_message(id, &name).await {
                toast.show(ToastKind::Error, msg);
                return;
            }
            this.refresh_inner().await;
        });
    }

    // ------------------------------------------------------------------
    // Bump modified timestamp
    // ------------------------------------------------------------------

    /// Touch the modified timestamp of the current message so it reorders
    /// in the list.
    pub(crate) fn bump_modified(&self) {
        let current_message_id = self.catalog.current_message_id;
        let toast = self.toast;
        let Some(id) = current_message_id.get_untracked() else {
            toast.show(ToastKind::Error, "No message selected.");
            return;
        };
        let this = self.clone();
        spawn_local(async move {
            if let Err(msg) = messages::bump_message_modified(id).await {
                toast.show(ToastKind::Error, msg);
                return;
            }
            this.refresh_inner().await;
            toast.show(ToastKind::Success, "Updated modified time (reordered messages).");
        });
    }

    // ------------------------------------------------------------------
    // Bootstrap
    // ------------------------------------------------------------------

    /// Run the one-time bootstrap sequence: load preferences, refresh the
    /// message list, and optionally import a `#base64=...` URL hash.
    /// Should be called from an `Effect` guarded by a `did_bootstrap` flag.
    pub(crate) fn bootstrap(&self) {
        let this = self.clone();
        let frame_name_template_text = self.catalog.frame_name_template_text;
        let current_message_id = self.catalog.current_message_id;
        let raw_input = self.catalog.raw_input;
        let message_name_text = self.catalog.message_name_text;
        let toast = self.toast;

        spawn_local(async move {
            match messages::load_frame_name_template() {
                Ok(v) => frame_name_template_text.set(v),
                Err(msg) => toast.show(ToastKind::Error, msg),
            }

            this.refresh_inner().await;

            let hash = match get_url_hash() {
                Ok(h) => h,
                Err(msg) => {
                    toast.show(ToastKind::Error, msg);
                    return;
                }
            };

            let Some(b64) = hash.strip_prefix("#base64=").or_else(|| hash.strip_prefix("#b64="))
            else {
                if let Some(id) = current_message_id.get_untracked() {
                    this.switch_to(id);
                }
                return;
            };
            if b64.is_empty() {
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
                            current_message_id.set(Some(id));
                            this.ws_svc.load_patch(
                                &format!("URL hash \u{2192} message \"{name}\""),
                                ByteView::from_vec(bytes),
                                Vec::new(),
                            );
                            toast.show(
                                ToastKind::Success,
                                format!("Imported URL hash as message \"{name}\"."),
                            );
                            message_name_text.update(|s| {
                                s.clear();
                                s.push_str(name.as_ref());
                            });
                        }
                        Err(msg) => toast.show(ToastKind::Error, msg),
                    }
                }
                Err(msg) => toast.show(ToastKind::Error, msg),
            }
        });
    }
}
