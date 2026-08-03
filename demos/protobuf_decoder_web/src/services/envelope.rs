use crate::decode::decode_user_input;
use crate::envelope::{parse_envelope_frames, EnvelopeFrameMeta};
use crate::messages::{self, MessageId};
use crate::page_cache;
use crate::services::MessageService;
use crate::state::{EnvelopeTabState, MessageCatalogState, Tab, TabsState};
use crate::toast::{ToastKind, ToastManager};
use crate::workspace::{
    format_frame_name_template, open_envelope_frame as open_workspace_envelope_frame,
    show_envelope_browser,
};
use leptos::prelude::*;
use std::sync::Arc;
use wasm_bindgen_futures::spawn_local;

/// Manages envelope framing operations: browsing frames in envelope tabs,
/// extracting/decompressing frames into messages, and importing
/// envelope-formatted bytes.
#[derive(Clone)]
pub(crate) struct EnvelopeService {
    tabs: TabsState,
    catalog: MessageCatalogState,
    toast: ToastManager,
    msg_svc: MessageService,
}

impl EnvelopeService {
    pub(crate) const fn new(
        tabs: TabsState,
        catalog: MessageCatalogState,
        toast: ToastManager,
        msg_svc: MessageService,
    ) -> Self {
        Self { tabs, catalog, toast, msg_svc }
    }

    fn active_envelope(&self) -> Option<(Tab, EnvelopeTabState)> {
        let tab = self.tabs.active_tab_untracked()?;
        let env = tab.envelope()?;
        Some((tab, env))
    }

    // ------------------------------------------------------------------
    // Open envelope tabs
    // ------------------------------------------------------------------

    /// "Frames" action from a message tab: open (or focus) the envelope tab
    /// for the active message.
    pub(crate) fn view_frames(&self) {
        let Some(tab) = self.tabs.active_tab_untracked() else {
            self.toast.show(ToastKind::Error, "No message open.");
            return;
        };
        self.open_envelope_tab(tab.message_id);
    }

    /// Focus the envelope tab for a source message, creating it if needed.
    /// Loading happens lazily when the tab body mounts.
    pub(crate) fn open_envelope_tab(&self, source_id: MessageId) {
        let tab = self
            .tabs
            .find_envelope(source_id)
            .unwrap_or_else(|| self.tabs.push_envelope_tab(source_id));
        self.tabs.activate(tab.id);
    }

    /// Load the active envelope tab's frames if not loaded yet. Called from
    /// the envelope tab view on mount, which covers every activation path
    /// (open, tab click, session restore).
    pub(crate) fn ensure_active_loaded(&self) {
        let Some((tab, env)) = self.active_envelope() else {
            return;
        };
        if env.view.with_untracked(Option::is_some) {
            return;
        }
        self.load_envelope_into(&tab, &env);
    }

    fn load_envelope_into(&self, tab: &Tab, env: &EnvelopeTabState) {
        let toast = self.toast;
        let tabs = self.tabs.clone();
        let source_id = tab.message_id;
        let nonce = tab.load_nonce.get_untracked().wrapping_add(1);
        tab.load_nonce.set(nonce);

        let tab = tab.clone();
        let env = env.clone();
        spawn_local(async move {
            let stale = {
                let tabs = tabs.clone();
                let tab = tab.clone();
                move || tab.load_nonce.get_untracked() != nonce || !tabs.contains(tab.id)
            };
            // Errors close the tab again: an envelope tab without frames is
            // dead weight.
            let fail = |msg: String| {
                toast.show(ToastKind::Error, msg);
                tabs.close(tab.id);
            };

            let loaded = match messages::load_message_bytes(source_id).await {
                Ok(value) => value,
                Err(msg) => {
                    if !stale() {
                        fail(msg.to_string());
                    }
                    return;
                }
            };
            if stale() {
                return;
            }

            let bytes_view = loaded.bytes;
            let bytes = bytes_view.bytes_rc();
            if bytes_view.len() != bytes.len() {
                fail("View Frames is not supported for sliced messages.".to_string());
                return;
            }

            page_cache::store_message_bytes(source_id, loaded.revision, bytes.clone());
            let frames = match parse_envelope_frames(bytes_view.as_slice()) {
                Ok(value) => value,
                Err(msg) => {
                    fail(msg.to_string());
                    return;
                }
            };
            if frames.is_empty() {
                fail("Envelope did not contain any frames.".to_string());
                return;
            }

            let frames_len = frames.len();
            let selected = frames
                .iter()
                .position(|frame| !frame.is_compressed() && !frame.is_json())
                .or_else(|| frames.iter().position(|frame| !frame.is_compressed()))
                .unwrap_or(0);

            let meta = vec![EnvelopeFrameMeta::default(); frames_len];
            show_envelope_browser(&env, source_id, bytes, frames, meta);
            open_workspace_envelope_frame(&env, selected, &toast);
            toast.show(ToastKind::Success, format!("Loaded envelope view: {frames_len} frame(s)."));
        });
    }

    // ------------------------------------------------------------------
    // Open / Close frame
    // ------------------------------------------------------------------

    /// Preview a specific envelope frame by index in the active envelope tab.
    pub(crate) fn open_frame(&self, idx: usize) {
        let Some((_tab, env)) = self.active_envelope() else {
            return;
        };
        open_workspace_envelope_frame(&env, idx, &self.toast);
    }

    /// Close the active envelope tab.
    pub(crate) fn close_frames(&self) {
        let Some((tab, _env)) = self.active_envelope() else {
            return;
        };
        self.tabs.close(tab.id);
    }

    // ------------------------------------------------------------------
    // Decompress selected frame
    // ------------------------------------------------------------------

    /// Create a new message from the currently selected (compressed) envelope
    /// frame, then open it in a message tab.
    pub(crate) fn decompress_selected_frame(&self) {
        let toast = self.toast;
        let Some((_tab, env)) = self.active_envelope() else {
            toast.show(ToastKind::Error, "No envelope view loaded.");
            return;
        };
        let message_name_text = self.catalog.message_name_text;
        let frame_name_template_text = self.catalog.frame_name_template_text;

        let Some((source_id, idx, frame)) = env.view.with_untracked(|state| {
            let view = state.as_ref()?;
            let idx = env.selected.get_untracked();
            let frame = view.frames.get(idx).copied()?;
            Some((view.source_id, idx, frame))
        }) else {
            toast.show(ToastKind::Error, "No envelope view loaded.");
            return;
        };

        if !frame.is_compressed() {
            toast.show(ToastKind::Error, "Selected envelope frame is not compressed.");
            return;
        }

        let source_name = message_name_text.get_untracked();
        let payload_len = frame.payload_len;
        let template = frame_name_template_text.get_untracked();
        let mut name = format_frame_name_template(&template, &source_name, idx, payload_len);
        name.push_str(" (compressed)");
        if frame.is_json() {
            name.push_str(" (json)");
        }

        let this = self.clone();
        spawn_local(async move {
            let id = match messages::create_envelope_frame_ref_in_same_class(
                source_id,
                &name,
                frame.payload_offset,
                frame.payload_len,
                frame.flags,
                true,
            )
            .await
            {
                Ok(id) => id,
                Err(msg) => {
                    toast.show(ToastKind::Error, msg);
                    return;
                }
            };

            this.msg_svc.refresh_inner().await;
            this.msg_svc.switch_to(id);
            toast.show(
                ToastKind::Success,
                format!("Opened frame {idx} as message \"{name}\" ({id})."),
            );
        });
    }

    // ------------------------------------------------------------------
    // Extract single frame
    // ------------------------------------------------------------------

    /// Extract a single envelope frame by index into a new message (without
    /// opening it).
    pub(crate) fn extract_frame(&self, idx: usize) {
        let toast = self.toast;
        let Some((_tab, env)) = self.active_envelope() else {
            toast.show(ToastKind::Error, "No envelope view loaded.");
            return;
        };
        let message_name_text = self.catalog.message_name_text;
        let frame_name_template_text = self.catalog.frame_name_template_text;

        let Some((source_id, frame)) = env.view.with_untracked(|state| {
            let view = state.as_ref()?;
            let frame = view.frames.get(idx).copied()?;
            Some((view.source_id, frame))
        }) else {
            toast.show(ToastKind::Error, "No envelope view loaded.");
            return;
        };

        let source_name = message_name_text.get_untracked();
        let payload_len = frame.payload_len;
        let template = frame_name_template_text.get_untracked();
        let mut name = format_frame_name_template(&template, &source_name, idx, payload_len);
        if frame.is_compressed() {
            name.push_str(" (compressed)");
        }
        if frame.is_json() {
            name.push_str(" (json)");
        }

        let this = self.clone();
        spawn_local(async move {
            let id = match messages::create_envelope_frame_ref_in_same_class(
                source_id,
                &name,
                frame.payload_offset,
                frame.payload_len,
                frame.flags,
                frame.is_compressed(),
            )
            .await
            {
                Ok(id) => id,
                Err(msg) => {
                    toast.show(ToastKind::Error, msg);
                    return;
                }
            };

            this.msg_svc.refresh_inner().await;
            toast.show(
                ToastKind::Success,
                format!("Extracted frame {idx} as message \"{name}\" ({id})."),
            );
        });
    }

    // ------------------------------------------------------------------
    // Extract all frames
    // ------------------------------------------------------------------

    /// Extract every frame in the active envelope tab into new messages.
    pub(crate) fn extract_all_frames(&self) {
        let toast = self.toast;
        let Some((_tab, env)) = self.active_envelope() else {
            toast.show(ToastKind::Error, "No envelope view loaded.");
            return;
        };
        let message_name_text = self.catalog.message_name_text;
        let frame_name_template_text = self.catalog.frame_name_template_text;

        let source_name = message_name_text.get_untracked();
        let Some((source_id, frames)) = env.view.with_untracked(|state| {
            let view = state.as_ref()?;
            Some((view.source_id, view.frames.clone()))
        }) else {
            toast.show(ToastKind::Error, "No envelope view loaded.");
            return;
        };
        if frames.is_empty() {
            toast.show(ToastKind::Error, "Envelope did not contain any frames.");
            return;
        }

        let Some(window) = web_sys::window() else {
            return;
        };
        let confirmed = window
            .confirm_with_message(&format!(
                "Extract {} frame(s) from \"{source_name}\" into new messages?\n\nCompressed frames will be auto-decompressed when possible.",
                frames.len()
            ))
            .unwrap_or(false);
        if !confirmed {
            return;
        }

        let template = frame_name_template_text.get_untracked();
        let this = self.clone();
        spawn_local(async move {
            let mut created: usize = 0;
            let mut compressed: usize = 0;
            let mut json: usize = 0;

            for (idx, frame) in frames.iter().copied().enumerate() {
                let payload_len = frame.payload_len;
                let mut name =
                    format_frame_name_template(&template, &source_name, idx, payload_len);
                if frame.is_compressed() {
                    compressed = compressed.saturating_add(1);
                    name.push_str(" (compressed)");
                }
                if frame.is_json() {
                    json = json.saturating_add(1);
                    name.push_str(" (json)");
                }

                match messages::create_envelope_frame_ref_in_same_class(
                    source_id,
                    &name,
                    frame.payload_offset,
                    frame.payload_len,
                    frame.flags,
                    frame.is_compressed(),
                )
                .await
                {
                    Ok(_id) => created = created.saturating_add(1),
                    Err(msg) => {
                        toast.show(ToastKind::Error, msg);
                        return;
                    }
                }
            }

            this.msg_svc.refresh_inner().await;

            let msg = match (compressed, json) {
                (0, 0) => format!("Extracted {created} frame(s) into new messages."),
                (_, 0) => format!(
                    "Extracted {created} frame(s) into new messages. ({compressed} compressed.)"
                ),
                (0, _) => {
                    format!("Extracted {created} frame(s) into new messages. ({json} json.)")
                }
                (_, _) => format!(
                    "Extracted {created} frame(s) into new messages. ({compressed} compressed, {json} json.)"
                ),
            };
            toast.show(ToastKind::Success, msg);
        });
    }

    // ------------------------------------------------------------------
    // Import envelope from raw input
    // ------------------------------------------------------------------

    /// Handle the "Import Envelope" action: decode user input, create a
    /// source message, and open it as an envelope tab.
    pub(crate) fn import_envelope(&self) {
        let toast = self.toast;
        let raw_input = self.catalog.raw_input;
        let import_name_text = self.catalog.import_name_text;
        let frame_name_template_text = self.catalog.frame_name_template_text;

        let input = raw_input.get_untracked();
        let bytes = match decode_user_input(&input) {
            Ok(v) => v,
            Err(msg) => {
                toast.show(ToastKind::Error, format!("Failed to decode input: {msg}"));
                return;
            }
        };
        if let Err(msg) =
            messages::store_frame_name_template(&frame_name_template_text.get_untracked())
        {
            toast.show(ToastKind::Error, msg);
        }

        let import_name = import_name_text.get_untracked();
        let source_name: Arc<str> = if import_name.trim().is_empty() {
            Arc::<str>::from(format!("Envelope import ({}B)", bytes.len()))
        } else {
            Arc::<str>::from(import_name.trim())
        };
        let bytes_len = bytes.len();
        let bytes_value = js_sys::Uint8Array::from(bytes.as_slice());
        let this = self.clone();
        spawn_local(async move {
            let source_id =
                match messages::create_message(&source_name, bytes_len, bytes_value).await {
                    Ok(v) => v,
                    Err(msg) => {
                        toast.show(ToastKind::Error, msg);
                        return;
                    }
                };
            this.msg_svc.refresh_inner().await;
            this.open_envelope_tab(source_id);
            toast.show(
                ToastKind::Success,
                format!("Imported envelope as message \"{source_name}\"."),
            );
        });
    }
}
