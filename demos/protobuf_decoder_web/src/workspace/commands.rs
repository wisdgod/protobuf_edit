use crate::bytes::ByteView;
use crate::error::shared_error;
use crate::envelope::{parse_envelope_frames, EnvelopeView};
use crate::fx::FxHashSet;
use crate::messages::MessageId;
use crate::toast::{show_toast, Toast, ToastKind};
use super::{
    build_selection_path, collect_visible_fields, decode_selection_path, resolve_selection_path,
};
use leptos::prelude::*;
use protobuf_edit::{FieldId, Patch, TreeError};
use std::rc::Rc;

use super::session::WorkspaceSession;

pub(crate) struct SaveReparseInfo {
    pub bytes: ByteView,
    pub bytes_len: usize,
    pub field_count: usize,
    pub elapsed_ms: f64,
}

pub(crate) fn confirm_discard_edits(session: &WorkspaceSession, action: &str) -> bool {
    let pending = session.dirty_fields.with_untracked(|state| state.len());
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

pub(crate) fn load_patch_from_view(
    session: &WorkspaceSession,
    label: &str,
    bytes: ByteView,
    auto_expand_paths: Vec<String>,
    toasts: RwSignal<Vec<Toast>>,
    next_toast_id: RwSignal<u64>,
) {
    let source = unsafe { protobuf_edit::Buf::from_borrowed_slice(bytes.as_slice()) };
    match Patch::from_buf(source) {
        Ok(mut patch) => {
            let _ = patch.enable_read_cache();
            let bytes_len = bytes.len();
            let field_count =
                patch.message_fields(patch.root()).map(|fields| fields.len()).unwrap_or(0);

            let mut expanded_by_default: FxHashSet<FieldId> = FxHashSet::default();
            for raw in auto_expand_paths {
                let Some(path) = decode_selection_path(&raw) else {
                    continue;
                };
                let Ok(Some((_fid, expanded))) = resolve_selection_path(&mut patch, &path, true)
                else {
                    continue;
                };
                expanded_by_default.extend(expanded);
            }

            session.show_root_patch(patch, bytes, None, expanded_by_default);
            show_toast(
                toasts,
                next_toast_id,
                ToastKind::Success,
                format!("Loaded {label}: {bytes_len} bytes, {field_count} field(s)."),
            );
        }
        Err(err) => {
            let frames = parse_envelope_frames(bytes.as_slice()).ok();
            session.show_root_raw_bytes(bytes);
            let msg = match frames {
                Some(frames) if !frames.is_empty() => format!(
                    "Failed to load {label}: {err:?}. Bytes match envelope framing ({} frame(s)). Use \"View Frames\", \"Import Envelope\", or \"Extract Frames\".",
                    frames.len()
                ),
                _ => format!("Failed to load {label}: {err:?}"),
            };
            show_toast(toasts, next_toast_id, ToastKind::Error, msg);
        }
    }
}

pub(crate) fn show_envelope_browser(
    session: &WorkspaceSession,
    source_id: MessageId,
    bytes: Rc<Vec<u8>>,
    frames: Vec<crate::envelope::EnvelopeFrame>,
    meta: Vec<crate::envelope::EnvelopeFrameMeta>,
) {
    session.show_envelope_browser(EnvelopeView { source_id, bytes, frames, meta });
}

pub(crate) fn open_envelope_frame(
    session: &WorkspaceSession,
    idx: usize,
    toasts: RwSignal<Vec<Toast>>,
    next_toast_id: RwSignal<u64>,
) {
    let Some((bytes, frame, cached_err)) = session.envelope_view.with_untracked(|state| {
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
        show_toast(
            toasts,
            next_toast_id,
            ToastKind::Error,
            "Envelope frame payload range is out of bounds.",
        );
        return;
    };

    if frame.is_compressed() || frame.is_json() || cached_err.is_some() {
        session.show_envelope_frame_raw_bytes(view, idx);
        return;
    }

    let source = unsafe { protobuf_edit::Buf::from_borrowed_slice(view.as_slice()) };
    match Patch::from_buf(source) {
        Ok(mut patch) => {
            let _ = patch.enable_read_cache();
            session.show_envelope_frame_patch(patch, view, idx);
        }
        Err(err) => {
            let msg = shared_error(format!("{err:?}"));
            session.envelope_view.update(|state| {
                let Some(view) = state.as_mut() else {
                    return;
                };
                let Some(meta) = view.meta.get_mut(idx) else {
                    return;
                };
                meta.protobuf_error = Some(msg.clone());
            });
            session.show_envelope_frame_raw_bytes(view, idx);
            show_toast(
                toasts,
                next_toast_id,
                ToastKind::Error,
                format!("Failed to parse envelope frame as protobuf: {msg}"),
            );
        }
    }
}

pub(crate) fn close_envelope_browser(
    session: &WorkspaceSession,
    toasts: RwSignal<Vec<Toast>>,
    next_toast_id: RwSignal<u64>,
) {
    let Some(bytes) =
        session.envelope_view.with_untracked(|state| state.as_ref().map(|view| view.bytes.clone()))
    else {
        return;
    };
    let len = bytes.len();
    let Some(view) = ByteView::slice(bytes, 0, len) else {
        return;
    };
    session.show_root_raw_bytes(view);
    show_toast(toasts, next_toast_id, ToastKind::Success, "Showing raw envelope bytes.");
}

pub(crate) fn visible_fields(session: &WorkspaceSession) -> Vec<FieldId> {
    session.patch_state.with_untracked(|state| {
        let Some(patch) = state.as_ref() else {
            return Vec::new();
        };
        session.expanded.with_untracked(|expanded| {
            let mut out = Vec::new();
            collect_visible_fields(patch, patch.root(), expanded, &mut out);
            out
        })
    })
}

pub(crate) fn revert_pending_edits(session: &WorkspaceSession) -> Result<(), TreeError> {
    let bytes_view = session.patch_bytes.get_untracked();
    let prev_selected = session.selected.get_untracked();
    let prev_path = session.patch_state.with(|state| {
        let patch = state.as_ref()?;
        let fid = prev_selected?;
        build_selection_path(patch, fid)
    });

    let mut next_selected = None;
    let mut next_expanded = FxHashSet::default();
    let mut result = Ok(());
    session.patch_state.update(|state| {
        let Some(mut patch) = state.take() else {
            result = Err(TreeError::DecodeError);
            return;
        };

        if patch.txn_active() {
            patch.txn_rollback();
        } else {
            let Some(bytes_view) = bytes_view.as_ref() else {
                result = Err(TreeError::DecodeError);
                *state = Some(patch);
                return;
            };
            let source = unsafe { protobuf_edit::Buf::from_borrowed_slice(bytes_view.as_slice()) };
            match Patch::from_buf(source) {
                Ok(value) => patch = value,
                Err(err) => {
                    result = Err(err);
                    *state = Some(patch);
                    return;
                }
            }
        }

        let _ = patch.enable_read_cache();
        if let Some(path) = prev_path.as_ref() {
            match resolve_selection_path(&mut patch, path, false) {
                Ok(Some((fid, expanded))) => {
                    next_selected = Some(fid);
                    next_expanded = expanded;
                }
                Ok(None) => {}
                Err(err) => {
                    result = Err(err);
                    *state = Some(patch);
                    return;
                }
            }
        }

        *state = Some(patch);
    });
    result?;
    session.reset_ui_state_keep_selected(next_selected, next_expanded);
    Ok(())
}

pub(crate) fn save_and_reparse(session: &WorkspaceSession) -> Result<SaveReparseInfo, TreeError> {
    let prev_selected = session.selected.get_untracked();
    let prev_path = session.patch_state.with(|state| {
        let patch = state.as_ref()?;
        let fid = prev_selected?;
        build_selection_path(patch, fid)
    });

    let t0 = js_sys::Date::now();
    let (mut patch, bytes_view) = session.patch_state.with(|state| {
        let Some(patch) = state.as_ref() else {
            return Err(TreeError::DecodeError);
        };
        let bytes = patch.save()?;
        let bytes = ByteView::from_vec(bytes.into_vec());
        let source = unsafe { protobuf_edit::Buf::from_borrowed_slice(bytes.as_slice()) };
        let patch = Patch::from_buf(source)?;
        Ok((patch, bytes))
    })?;
    let elapsed_ms = (js_sys::Date::now() - t0).max(0.0);

    let _ = patch.enable_read_cache();
    let field_count = patch.message_fields(patch.root()).map(|fields| fields.len()).unwrap_or(0);
    let bytes_len = patch.root_bytes().len();

    let (new_selected, new_expanded) = match prev_path {
        Some(path) => match resolve_selection_path(&mut patch, &path, false) {
            Ok(Some((fid, expanded))) => (Some(fid), expanded),
            Ok(None) => (None, FxHashSet::default()),
            Err(_) => (None, FxHashSet::default()),
        },
        None => (None, FxHashSet::default()),
    };

    session.show_root_patch(patch, bytes_view.clone(), new_selected, new_expanded);
    Ok(SaveReparseInfo { bytes: bytes_view, bytes_len, field_count, elapsed_ms })
}
