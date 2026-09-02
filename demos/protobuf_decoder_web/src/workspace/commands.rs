use super::{
    build_selection_path, decode_selection_path, resolve_selection_path, selection_if_shown,
    shown_children,
};
use crate::bytes::ByteView;
use crate::envelope::{parse_envelope_frames, EnvelopeView};
use crate::error::shared_error;
use crate::messages::MessageId;
use crate::state::{EnvelopeTabState, WorkspaceState};
use crate::toast::{ToastKind, ToastManager};
use leptos::prelude::*;
use protobuf_edit::session::grouped::{Descent, OpenFault, Session};
use protobuf_edit::session::Handle;
use rustc_hash::FxHashSet;
use std::rc::Rc;

pub(crate) struct SaveReparseInfo {
    pub bytes: ByteView,
    pub bytes_len: usize,
    pub field_count: usize,
    pub elapsed_ms: f64,
}

/// Opens an owned editing session over `view`'s bytes; the session
/// copies them into its own sealed carrier, so the `ByteView` and the
/// session live independently.
fn open_session(view: &ByteView) -> Result<Session, OpenFault> {
    Session::open_copy(view.as_slice())
}

/// Descends `handle` without notifying `session` subscribers.
///
/// A descend only materializes the container's interior; what becomes
/// visible is driven by the `expanded`/`selected` signals. A tracked
/// update here would recompute every session-dependent memo in the
/// app for a cache-only mutation.
pub(crate) fn descend_untracked(
    session_state: RwSignal<Option<Session>, LocalStorage>,
    handle: Handle,
) -> Result<(), String> {
    session_state
        .try_update_untracked(|state| {
            let session = state.as_mut().ok_or_else(|| "no document loaded".to_string())?;
            match session.descend(handle) {
                Ok(Descent::Opened { .. }) => Ok(()),
                Ok(Descent::Faulted(fault)) => Err(fault.to_string()),
                Ok(Descent::Refused(refusal)) => Err(refusal.to_string()),
                Err(fault) => Err(fault.to_string()),
            }
        })
        .unwrap_or_else(|| Err("no document loaded".to_string()))
}

pub(crate) fn confirm_discard_edits(ws: &WorkspaceState, action: &str) -> bool {
    let pending = ws.dirty_fields.with_untracked(FxHashSet::len);
    if pending == 0 {
        return true;
    }
    let Some(window) = web_sys::window() else {
        return false;
    };
    window
        .confirm_with_message(&format!("You have {pending} pending edit(s). Discard and {action}?"))
        .unwrap_or(false)
}

pub(crate) fn load_session_from_view(
    ws: &WorkspaceState,
    label: &str,
    bytes: ByteView,
    auto_expand_paths: Vec<String>,
    toast: &ToastManager,
) {
    match open_session(&bytes) {
        Ok(mut session) => {
            let bytes_len = bytes.len();
            let field_count = shown_children(&session, None).count();

            let mut expanded_by_default: FxHashSet<Handle> = FxHashSet::default();
            for raw in auto_expand_paths {
                let Some(path) = decode_selection_path(&raw) else {
                    continue;
                };
                let Some((_handle, expanded)) = resolve_selection_path(&mut session, &path, true)
                else {
                    continue;
                };
                expanded_by_default.extend(expanded);
            }

            ws.show_root_session(session, bytes, None, expanded_by_default);
            toast.show(
                ToastKind::Notice,
                format!("Loaded {label}: {bytes_len} bytes, {field_count} field(s)."),
            );
        }
        Err(err) => {
            let frames = parse_envelope_frames(bytes.as_slice()).ok();
            ws.show_root_raw_bytes(bytes);
            let msg = match frames {
                Some(frames) if !frames.is_empty() => format!(
                    "Failed to load {label}: {err}. Bytes match envelope framing ({} frame(s)). Use \"View Frames\", \"Import Envelope\", or \"Extract Frames\".",
                    frames.len()
                ),
                _ => format!("Failed to load {label}: {err}"),
            };
            toast.show(ToastKind::Alert, msg);
        }
    }
}

/// Fills an envelope tab with parsed frames, resetting frame selection and
/// the preview workspace.
pub(crate) fn show_envelope_browser(
    env: &EnvelopeTabState,
    source_id: MessageId,
    bytes: Rc<Vec<u8>>,
    frames: Vec<crate::envelope::EnvelopeFrame>,
    meta: Vec<crate::envelope::EnvelopeFrameMeta>,
) {
    env.preview.clear_loaded_data();
    env.selected.set(0);
    env.view.set(Some(EnvelopeView { source_id, bytes, frames, meta }));
}

/// Opens frame `idx` in the envelope tab's read-only preview workspace.
pub(crate) fn open_envelope_frame(env: &EnvelopeTabState, idx: usize, toast: &ToastManager) {
    let Some((bytes, frame, cached_err)) = env.view.with_untracked(|state| {
        let view = state.as_ref()?;
        let frame = view.frames.get(idx).copied()?;
        let cached_err = view.meta.get(idx).and_then(|meta| meta.protobuf_error.as_ref()).cloned();
        Some((view.bytes.clone(), frame, cached_err))
    }) else {
        return;
    };

    let Some(view) = ByteView::slice(
        bytes,
        frame.payload_offset,
        frame.payload_offset.saturating_add(frame.payload_len),
    ) else {
        toast.show(ToastKind::Alert, "Envelope frame payload range is out of bounds.");
        return;
    };

    env.selected.set(idx);

    if frame.is_compressed() || frame.is_json() || cached_err.is_some() {
        env.preview.show_root_raw_bytes(view);
        return;
    }

    match open_session(&view) {
        Ok(session) => {
            env.preview.show_root_session(session, view, None, FxHashSet::default());
        }
        Err(err) => {
            let msg = shared_error(err.to_string());
            env.view.update(|state| {
                let Some(view) = state.as_mut() else {
                    return;
                };
                let Some(meta) = view.meta.get_mut(idx) else {
                    return;
                };
                meta.protobuf_error = Some(msg.clone());
            });
            env.preview.show_root_raw_bytes(view);
            toast.show(
                ToastKind::Alert,
                format!("Failed to parse envelope frame as protobuf: {msg}"),
            );
        }
    }
}

pub(crate) fn revert_pending_edits(ws: &WorkspaceState) -> Result<(), String> {
    let mut reverted = false;
    ws.session.update(|state| {
        if let Some(session) = state.as_mut() {
            session.revert_all();
            reverted = true;
        }
    });
    if !reverted {
        return Err("no document loaded".to_string());
    }

    // Handles survive the revert (session topology is monotone), so
    // the selection and expansion carry over; rows the revert
    // shrouded or orphaned fall out through the presentation filter.
    let selected = ws.session.with_untracked(|state| {
        state
            .as_ref()
            .and_then(|session| selection_if_shown(session, ws.selected.get_untracked()))
    });
    let expanded = ws.expanded.get_untracked();
    ws.reset_ui_state_keep_selected(selected, expanded);
    Ok(())
}

pub(crate) fn save_and_reparse(ws: &WorkspaceState) -> Result<SaveReparseInfo, String> {
    let prev_selected = ws.selected.get_untracked();
    let prev_path = ws.session.with_untracked(|state| {
        let session = state.as_ref()?;
        build_selection_path(session, prev_selected?)
    });

    let t0 = js_sys::Date::now();
    let doc = ws.session.with_untracked(|state| {
        state.as_ref().map_or_else(
            || Err("no document loaded".to_string()),
            |session| session.save().map_err(|e| e.to_string()),
        )
    })?;
    let bytes_view = ByteView::from_vec(doc.as_slice().to_vec());
    // The saved carrier is the new session's document (no reparse
    // copy); handles are session-scoped, so the selection is carried
    // over by path.
    let mut session = Session::open(doc).map_err(|e| e.to_string())?;
    let elapsed_ms = (js_sys::Date::now() - t0).max(0.0);

    let field_count = shown_children(&session, None).count();
    let bytes_len = bytes_view.len();

    let (new_selected, new_expanded) = prev_path.map_or_else(
        || (None, FxHashSet::default()),
        |path| {
            resolve_selection_path(&mut session, &path, false)
                .map_or_else(|| (None, FxHashSet::default()), |(h, exp)| (Some(h), exp))
        },
    );

    ws.show_root_session(session, bytes_view.clone(), new_selected, new_expanded);
    Ok(SaveReparseInfo { bytes: bytes_view, bytes_len, field_count, elapsed_ms })
}
