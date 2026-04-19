use crate::decode::decode_user_input;
use crate::envelope::{parse_envelope_frames, EnvelopeFrameMeta};
use crate::messages::{self, MessageId};
use crate::page_cache;
use crate::services::MessageService;
use crate::state::{MessageCatalogState, WorkspaceState};
use crate::toast::{ToastKind, ToastManager};
use crate::workspace::{
    close_envelope_browser, confirm_discard_edits as confirm_workspace_discard_edits,
    format_frame_name_template, open_envelope_frame as open_workspace_envelope_frame,
    show_envelope_browser,
};
use leptos::prelude::*;
use std::rc::Rc;
use std::sync::Arc;
use wasm_bindgen_futures::spawn_local;

/// Manages envelope framing operations: viewing, extracting, decompressing,
/// and importing envelope-formatted bytes.
#[derive(Clone)]
pub(crate) struct EnvelopeService {
    ws: WorkspaceState,
    catalog: MessageCatalogState,
    toast: ToastManager,
    msg_svc: MessageService,
}

impl EnvelopeService {
    pub(crate) fn new(
        ws: WorkspaceState,
        catalog: MessageCatalogState,
        toast: ToastManager,
        msg_svc: MessageService,
    ) -> Self {
        Self { ws, catalog, toast, msg_svc }
    }

    // ------------------------------------------------------------------
    // View frames
    // ------------------------------------------------------------------

    /// Load the current message as an envelope, parse its frames, and open
    /// the envelope browser panel.
    pub(crate) fn view_frames(&self) {
        let toast = self.toast;
        let current_message_id = self.catalog.current_message_id;
        let ws = self.ws.clone();

        let Some(source_id) = current_message_id.get_untracked() else {
            toast.show(ToastKind::Error, "No message selected.");
            return;
        };
        if !confirm_workspace_discard_edits(&ws, "view envelope frames") {
            return;
        }

        let this = self.clone();
        spawn_local(async move {
            let loaded = match messages::load_message_bytes(source_id).await {
                Ok(value) => value,
                Err(msg) => {
                    toast.show(ToastKind::Error, msg);
                    return;
                }
            };

            let bytes_view = loaded.bytes;
            let bytes = bytes_view.bytes_rc();
            if bytes_view.len() != bytes.len() {
                toast.show(ToastKind::Error, "View Frames is not supported for sliced messages.");
                return;
            }

            page_cache::store_message_bytes(source_id, loaded.revision, bytes.clone());
            let frames = match parse_envelope_frames(bytes_view.as_slice()) {
                Ok(value) => value,
                Err(msg) => {
                    toast.show(ToastKind::Error, msg);
                    return;
                }
            };
            if frames.is_empty() {
                toast.show(ToastKind::Error, "Envelope did not contain any frames.");
                return;
            }

            let frames_len = frames.len();
            let selected = frames
                .iter()
                .position(|frame| !frame.is_compressed() && !frame.is_json())
                .or_else(|| frames.iter().position(|frame| !frame.is_compressed()))
                .unwrap_or(0);

            let meta = vec![EnvelopeFrameMeta::default(); frames_len];
            show_envelope_browser(&ws, source_id, bytes, frames, meta);
            this.open_frame(selected);
            toast.show(ToastKind::Success, format!("Loaded envelope view: {frames_len} frame(s)."));
        });
    }

    // ------------------------------------------------------------------
    // Open / Close frame
    // ------------------------------------------------------------------

    /// Open a specific envelope frame by index in the workspace.
    pub(crate) fn open_frame(&self, idx: usize) {
        open_workspace_envelope_frame(&self.ws, idx, &self.toast);
    }

    /// Close the envelope browser and show the raw envelope bytes.
    pub(crate) fn close_frames(&self) {
        close_envelope_browser(&self.ws, &self.toast);
    }

    // ------------------------------------------------------------------
    // Decompress selected frame
    // ------------------------------------------------------------------

    /// Create a new message from the currently selected (compressed) envelope
    /// frame, then switch to it.
    pub(crate) fn decompress_selected_frame(&self) {
        let toast = self.toast;
        let envelope_view = self.ws.envelope_view;
        let envelope_selected = self.ws.envelope_selected;
        let message_name_text = self.catalog.message_name_text;
        let frame_name_template_text = self.catalog.frame_name_template_text;

        let Some((source_id, idx, frame)) = envelope_view.with_untracked(|state| {
            let view = state.as_ref()?;
            let idx = envelope_selected.get_untracked();
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
    /// switching to it).
    pub(crate) fn extract_frame(&self, idx: usize) {
        let toast = self.toast;
        let envelope_view = self.ws.envelope_view;
        let message_name_text = self.catalog.message_name_text;
        let frame_name_template_text = self.catalog.frame_name_template_text;

        let Some((source_id, frame)) = envelope_view.with_untracked(|state| {
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

            let _ = messages::set_current_message(Some(source_id));
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

    /// Extract every frame in the envelope browser into new messages.
    pub(crate) fn extract_all_frames(&self) {
        let toast = self.toast;
        let envelope_view = self.ws.envelope_view;
        let message_name_text = self.catalog.message_name_text;
        let frame_name_template_text = self.catalog.frame_name_template_text;

        let source_name = message_name_text.get_untracked();
        let Some((source_id, frames)) = envelope_view.with_untracked(|state| {
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

            let _ = messages::set_current_message(Some(source_id));
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
    // Extract envelope bytes (shared helper)
    // ------------------------------------------------------------------

    /// Parse raw bytes as an envelope, create a new message for each frame,
    /// cache the source bytes, and switch to the best candidate frame.
    pub(crate) fn extract_envelope_bytes(
        &self,
        source_id: MessageId,
        source_name: Arc<str>,
        bytes: Vec<u8>,
    ) {
        let ws = self.ws.clone();
        ws.clear_loaded_data();

        let bytes = Rc::new(bytes);
        let template = self.catalog.frame_name_template_text.get_untracked();
        let toast = self.toast;
        let this = self.clone();
        spawn_local(async move {
            let revision = match messages::message_modified_ms(source_id).await {
                Ok(v) => v,
                Err(msg) => {
                    toast.show(ToastKind::Error, msg);
                    0
                }
            };
            page_cache::store_message_bytes(source_id, revision, bytes.clone());

            let frames = match parse_envelope_frames(bytes.as_slice()) {
                Ok(v) => v,
                Err(msg) => {
                    toast.show(ToastKind::Error, msg);
                    return;
                }
            };

            let mut created: usize = 0;
            let mut compressed: usize = 0;
            let mut json: usize = 0;
            let mut open_id: Option<MessageId> = None;
            let mut open_score: u8 = 0;

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
                    Ok(v) => v,
                    Err(msg) => {
                        toast.show(ToastKind::Error, msg);
                        return;
                    }
                };
                created = created.saturating_add(1);

                let score = if !frame.is_json() && !frame.is_compressed() {
                    3
                } else if !frame.is_json() {
                    2
                } else {
                    1
                };
                if open_id.is_none() || score > open_score {
                    open_id = Some(id);
                    open_score = score;
                }
            }

            let Some(open_id) = open_id else {
                toast.show(ToastKind::Error, "Envelope did not contain any frames.");
                return;
            };

            this.msg_svc.refresh_inner().await;
            this.msg_svc.switch_to(open_id);
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

    /// Handle the "Import Envelope" button: decode user input, create a
    /// source message, then extract its envelope frames.
    pub(crate) fn import_envelope(&self) {
        let toast = self.toast;
        let raw_input = self.catalog.raw_input;
        let import_name_text = self.catalog.import_name_text;
        let frame_name_template_text = self.catalog.frame_name_template_text;

        if !confirm_workspace_discard_edits(&self.ws, "import envelope bytes") {
            return;
        }
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
            this.extract_envelope_bytes(source_id, source_name, bytes);
        });
    }
}
