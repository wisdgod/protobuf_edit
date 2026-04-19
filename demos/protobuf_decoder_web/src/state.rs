use crate::bytes::ByteView;
use crate::envelope::EnvelopeView;
use crate::fx::FxHashSet;
use crate::hex_view::HexTextMode;
use crate::messages::{MessageId, MessageMeta};
use crate::toast::ToastManager;
use crate::workspace::{compute_highlights, HighlightRange};
use leptos::prelude::*;
use protobuf_edit::{FieldId, Patch};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Theme {
    Light,
    Dark,
}

impl Theme {
    pub(crate) const fn toggle(self) -> Self {
        match self {
            Self::Light => Self::Dark,
            Self::Dark => Self::Light,
        }
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Light => "light",
            Self::Dark => "dark",
        }
    }
}

pub(crate) fn parse_theme(raw: &str) -> Option<Theme> {
    match raw.trim() {
        "light" => Some(Theme::Light),
        "dark" => Some(Theme::Dark),
        _ => None,
    }
}

#[derive(Clone)]
pub(crate) struct WorkspaceState {
    pub patch_state: RwSignal<Option<Patch>, LocalStorage>,
    pub patch_bytes: RwSignal<Option<ByteView>, LocalStorage>,
    pub raw_bytes: RwSignal<Option<ByteView>, LocalStorage>,
    pub envelope_view: RwSignal<Option<EnvelopeView>, LocalStorage>,
    pub envelope_selected: RwSignal<usize>,

    pub selected: RwSignal<Option<FieldId>>,
    pub hovered: RwSignal<Option<FieldId>>,
    pub expanded: RwSignal<FxHashSet<FieldId>>,
    pub dirty_fields: RwSignal<FxHashSet<FieldId>>,
    pub hex_text_mode: RwSignal<HexTextMode>,
    pub hex_selection: RwSignal<Option<(usize, usize)>>,

    pub highlights: Memo<Vec<HighlightRange>>,
    pub highlight_range_count: Memo<usize>,
    pub read_only: Memo<bool>,
    pub bytes_count: Memo<Option<usize>>,
    pub field_count: Memo<Option<usize>>,
    pub dirty_count: Memo<usize>,
}

impl WorkspaceState {
    pub fn new() -> Self {
        let patch_state = RwSignal::new_local(None::<Patch>);
        let patch_bytes = RwSignal::new_local(None::<ByteView>);
        let raw_bytes = RwSignal::new_local(None::<ByteView>);
        let envelope_view: RwSignal<Option<EnvelopeView>, LocalStorage> = RwSignal::new_local(None);
        let envelope_selected: RwSignal<usize> = RwSignal::new(0);

        let selected: RwSignal<Option<FieldId>> = RwSignal::new(None);
        let hovered: RwSignal<Option<FieldId>> = RwSignal::new(None);
        let expanded: RwSignal<FxHashSet<FieldId>> = RwSignal::new(FxHashSet::default());
        let dirty_fields: RwSignal<FxHashSet<FieldId>> = RwSignal::new(FxHashSet::default());
        let hex_text_mode: RwSignal<HexTextMode> = RwSignal::new(HexTextMode::Ascii);
        let hex_selection: RwSignal<Option<(usize, usize)>> = RwSignal::new(None);

        let highlights = Memo::new(move |_| {
            patch_state.with(|p| {
                let Some(patch) = p.as_ref() else {
                    return Vec::new();
                };
                compute_highlights(patch, selected.get(), hovered.get())
            })
        });
        let highlight_range_count = Memo::new(move |_| highlights.get().len());
        let read_only = Memo::new(move |_| envelope_view.with(|s| s.is_some()));
        let bytes_count = Memo::new(move |_| {
            patch_state
                .with(|p| p.as_ref().map(|p| p.root_bytes().len()))
                .or_else(|| raw_bytes.with(|b| b.as_ref().map(|b| b.len())))
        });
        let field_count = Memo::new(move |_| {
            patch_state.with(|p| {
                let patch = p.as_ref()?;
                let fields = patch.message_fields(patch.root()).ok()?;
                let mut live: usize = 0;
                for &fid in fields {
                    if matches!(patch.field_is_deleted(fid), Ok(true)) {
                        continue;
                    }
                    live = live.saturating_add(1);
                }
                Some(live)
            })
        });
        let dirty_count = Memo::new(move |_| dirty_fields.with(|s| s.len()));

        Self {
            patch_state,
            patch_bytes,
            raw_bytes,
            envelope_view,
            envelope_selected,
            selected,
            hovered,
            expanded,
            dirty_fields,
            hex_text_mode,
            hex_selection,
            highlights,
            highlight_range_count,
            read_only,
            bytes_count,
            field_count,
            dirty_count,
        }
    }

    pub(crate) fn reset_ui_state(&self) {
        self.selected.set(None);
        self.hovered.set(None);
        self.expanded.set(FxHashSet::default());
        self.dirty_fields.set(FxHashSet::default());
        self.hex_selection.set(None);
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
        self.hex_selection.set(None);
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

#[derive(Clone)]
pub(crate) struct MessageCatalogState {
    pub raw_input: RwSignal<String>,
    pub import_name_text: RwSignal<String>,
    pub messages_list: RwSignal<Vec<MessageMeta>>,
    pub current_message_id: RwSignal<Option<MessageId>>,
    pub message_name_text: RwSignal<String>,
    pub frame_name_template_text: RwSignal<String>,
}

#[derive(Clone)]
pub(crate) struct UiState {
    pub theme_is_dark: Memo<bool>,
    pub toast: ToastManager,
}
