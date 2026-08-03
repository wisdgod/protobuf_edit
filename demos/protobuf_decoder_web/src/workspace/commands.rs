use crate::bytes::ByteView;
use crate::error::shared_error;
use crate::envelope::{parse_envelope_frames, EnvelopeView};
use rustc_hash::FxHashSet;
use crate::messages::MessageId;
use crate::state::{EnvelopeTabState, WorkspaceState};
use crate::toast::{ToastManager, ToastKind};
use super::{build_selection_path, decode_selection_path, resolve_selection_path};
use leptos::prelude::*;
use protobuf_edit::patch::FieldId;
use protobuf_edit::{Patch, TreeError};
use std::rc::Rc;

pub(crate) struct SaveReparseInfo {
    pub bytes: ByteView,
    pub bytes_len: usize,
    pub field_count: usize,
    pub elapsed_ms: f64,
}

/// Parses a `Patch` borrowing `view`'s backing bytes, with the read cache on.
///
/// SAFETY contract (single point for the whole demo): the returned `Patch`
/// must only be stored together with a clone of `view` keeping the backing
/// `Rc<Vec<u8>>` alive, and must be replaced before that clone drops.
/// `WorkspaceState::show_root_patch` maintains this by setting `patch_state`
/// before `patch_bytes`; tab closing clears the patch first for the same
/// reason.
fn patch_from_view(view: &ByteView) -> Result<Patch, TreeError> {
    // SAFETY: see the function contract above; callers keep `view` alive for
    // the patch's whole lifetime.
    let source = unsafe { protobuf_edit::Buf::from_borrowed_slice(view.as_slice()) };
    let mut patch = Patch::from_buf(source)?;
    let _ = patch.enable_read_cache();
    Ok(patch)
}

/// Parses `field`'s child message without notifying `patch_state` subscribers.
///
/// `parse_child_message` only fills the lazy-parse cache; what becomes
/// visible is driven by the `expanded`/`selected` signals. A tracked update
/// here would recompute every patch-dependent memo in the app for a
/// cache-only mutation.
pub(crate) fn parse_child_untracked(
    patch_state: RwSignal<Option<Patch>, LocalStorage>,
    field: FieldId,
) -> Result<protobuf_edit::patch::MessageId, TreeError> {
    patch_state
        .try_update_untracked(|p| {
            let patch = p.as_mut().ok_or(TreeError::InvalidId)?;
            patch.parse_child_message(field)
        })
        .unwrap_or(Err(TreeError::InvalidId))
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

pub(crate) fn load_patch_from_view(
    ws: &WorkspaceState,
    label: &str,
    bytes: ByteView,
    auto_expand_paths: Vec<String>,
    toast: &ToastManager,
) {
    match patch_from_view(&bytes) {
        Ok(mut patch) => {
            let bytes_len = bytes.len();
            let field_count = patch.message_fields(patch.root()).map_or(0, |fields| fields.len());

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

            ws.show_root_patch(patch, bytes, None, expanded_by_default);
            toast.show(
                ToastKind::Success,
                format!("Loaded {label}: {bytes_len} bytes, {field_count} field(s)."),
            );
        }
        Err(err) => {
            let frames = parse_envelope_frames(bytes.as_slice()).ok();
            ws.show_root_raw_bytes(bytes);
            let msg = match frames {
                Some(frames) if !frames.is_empty() => format!(
                    "Failed to load {label}: {err:?}. Bytes match envelope framing ({} frame(s)). Use \"View Frames\", \"Import Envelope\", or \"Extract Frames\".",
                    frames.len()
                ),
                _ => format!("Failed to load {label}: {err:?}"),
            };
            toast.show(ToastKind::Error, msg);
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
        toast.show(ToastKind::Error, "Envelope frame payload range is out of bounds.");
        return;
    };

    env.selected.set(idx);

    if frame.is_compressed() || frame.is_json() || cached_err.is_some() {
        env.preview.show_root_raw_bytes(view);
        return;
    }

    match patch_from_view(&view) {
        Ok(patch) => {
            env.preview.show_root_patch(patch, view, None, FxHashSet::default());
        }
        Err(err) => {
            let msg = shared_error(format!("{err:?}"));
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
                ToastKind::Error,
                format!("Failed to parse envelope frame as protobuf: {msg}"),
            );
        }
    }
}

pub(crate) fn revert_pending_edits(ws: &WorkspaceState) -> Result<(), TreeError> {
    let bytes_view = ws.patch_bytes.get_untracked();
    let prev_selected = ws.selected.get_untracked();
    let prev_path = ws.patch_state.with_untracked(|state| {
        let patch = state.as_ref()?;
        let fid = prev_selected?;
        build_selection_path(patch, fid)
    });

    let mut next_selected = None;
    let mut next_expanded = FxHashSet::default();
    let mut result = Ok(());
    ws.patch_state.update(|state| {
        let Some(mut patch) = state.take() else {
            result = Err(TreeError::InvalidId);
            return;
        };

        if patch.txn_active() {
            patch.txn_rollback();
        } else {
            let Some(bytes_view) = bytes_view.as_ref() else {
                result = Err(TreeError::InvalidId);
                *state = Some(patch);
                return;
            };
            match patch_from_view(bytes_view) {
                Ok(value) => patch = value,
                Err(err) => {
                    result = Err(err);
                    *state = Some(patch);
                    return;
                }
            }
        }

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
    ws.reset_ui_state_keep_selected(next_selected, next_expanded);
    Ok(())
}

pub(crate) fn save_and_reparse(ws: &WorkspaceState) -> Result<SaveReparseInfo, TreeError> {
    let prev_selected = ws.selected.get_untracked();
    let prev_path = ws.patch_state.with_untracked(|state| {
        let patch = state.as_ref()?;
        let fid = prev_selected?;
        build_selection_path(patch, fid)
    });

    let t0 = js_sys::Date::now();
    let (mut patch, bytes_view) = ws.patch_state.with_untracked(|state| {
        let Some(patch) = state.as_ref() else {
            return Err(TreeError::InvalidId);
        };
        let bytes = patch.save()?;
        let bytes = ByteView::from_vec(bytes.into_vec());
        let patch = patch_from_view(&bytes)?;
        Ok((patch, bytes))
    })?;
    let elapsed_ms = (js_sys::Date::now() - t0).max(0.0);

    let field_count = patch.message_fields(patch.root()).map_or(0, |fields| fields.len());
    let bytes_len = patch.root_bytes().len();

    let (new_selected, new_expanded) = prev_path.map_or_else(
        || (None, FxHashSet::default()),
        |path| match resolve_selection_path(&mut patch, &path, false) {
            Ok(Some((fid, expanded))) => (Some(fid), expanded),
            Ok(None) | Err(_) => (None, FxHashSet::default()),
        },
    );

    ws.show_root_patch(patch, bytes_view.clone(), new_selected, new_expanded);
    Ok(SaveReparseInfo { bytes: bytes_view, bytes_len, field_count, elapsed_ms })
}
