use crate::bytes::ByteView;
use crate::envelope::EnvelopeView;
use crate::fx::FxHashSet;
use leptos::prelude::*;
use protobuf_edit::{FieldId, Patch};

#[derive(Clone)]
pub(crate) struct WorkspaceSession {
    pub patch_state: RwSignal<Option<Patch>, LocalStorage>,
    pub patch_bytes: RwSignal<Option<ByteView>, LocalStorage>,
    pub raw_bytes: RwSignal<Option<ByteView>, LocalStorage>,
    pub envelope_view: RwSignal<Option<EnvelopeView>, LocalStorage>,
    pub envelope_selected: RwSignal<usize>,
    pub selected: RwSignal<Option<FieldId>>,
    pub hovered: RwSignal<Option<FieldId>>,
    pub expanded: RwSignal<FxHashSet<FieldId>>,
    pub dirty_fields: RwSignal<FxHashSet<FieldId>>,
}

impl WorkspaceSession {
    pub(crate) fn reset_ui_state(&self) {
        self.selected.set(None);
        self.hovered.set(None);
        self.expanded.set(FxHashSet::default());
        self.dirty_fields.set(FxHashSet::default());
    }

    pub(crate) fn reset_ui_state_keep_selected(
        &self,
        new_selected: Option<FieldId>,
        new_expanded: FxHashSet<FieldId>,
    ) {
        self.selected.set(new_selected);
        self.hovered.set(None);
        self.expanded.set(new_expanded);
        self.dirty_fields.set(FxHashSet::default());
    }

    pub(crate) fn clear_loaded_data(&self) {
        self.envelope_view.set(None);
        self.envelope_selected.set(0);
        self.patch_state.set(None);
        self.patch_bytes.set(None);
        self.raw_bytes.set(None);
        self.reset_ui_state();
    }

    pub(crate) fn show_root_patch(
        &self,
        patch: Patch,
        bytes: ByteView,
        new_selected: Option<FieldId>,
        new_expanded: FxHashSet<FieldId>,
    ) {
        self.envelope_view.set(None);
        self.envelope_selected.set(0);
        self.patch_bytes.set(Some(bytes));
        self.patch_state.set(Some(patch));
        self.raw_bytes.set(None);
        self.reset_ui_state_keep_selected(new_selected, new_expanded);
    }

    pub(crate) fn show_root_raw_bytes(&self, bytes: ByteView) {
        self.envelope_view.set(None);
        self.envelope_selected.set(0);
        self.patch_state.set(None);
        self.patch_bytes.set(None);
        self.raw_bytes.set(Some(bytes));
        self.reset_ui_state();
    }

    pub(crate) fn show_envelope_browser(&self, view: EnvelopeView) {
        self.envelope_selected.set(0);
        self.envelope_view.set(Some(view));
        self.patch_state.set(None);
        self.patch_bytes.set(None);
        self.raw_bytes.set(None);
        self.reset_ui_state();
    }

    pub(crate) fn show_envelope_frame_patch(&self, patch: Patch, bytes: ByteView, idx: usize) {
        self.envelope_selected.set(idx);
        self.patch_bytes.set(Some(bytes));
        self.patch_state.set(Some(patch));
        self.raw_bytes.set(None);
        self.reset_ui_state();
    }

    pub(crate) fn show_envelope_frame_raw_bytes(&self, bytes: ByteView, idx: usize) {
        self.envelope_selected.set(idx);
        self.patch_state.set(None);
        self.patch_bytes.set(None);
        self.raw_bytes.set(Some(bytes));
        self.reset_ui_state();
    }
}
