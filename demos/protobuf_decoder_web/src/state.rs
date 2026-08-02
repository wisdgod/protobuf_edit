use crate::bytes::ByteView;
use crate::envelope::EnvelopeView;
use crate::fx::FxHashSet;
use crate::hex_view::HexTextMode;
use crate::messages::{MessageId, MessageMeta};
use crate::toast::ToastManager;
use crate::workspace::{compute_hovered_range, compute_selected_highlights, HighlightRange};
use leptos::prelude::*;
use protobuf_edit::patch::FieldId;
use protobuf_edit::Patch;

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

    pub selected_highlights: Memo<Vec<HighlightRange>>,
    pub hovered_range: Memo<Option<HighlightRange>>,
    pub highlight_range_count: Memo<usize>,
    pub read_only: Memo<bool>,
    pub bytes_count: Memo<Option<usize>>,
    /// Live fields of the root message only; nested fields are not counted.
    pub root_field_count: Memo<Option<usize>>,
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

        // Hover changes at mouse frequency; keep it out of the (heavier)
        // selection-derived ranges so hovering never recomputes them.
        let selected_highlights = Memo::new(move |_| {
            patch_state.with(|p| {
                let Some(patch) = p.as_ref() else {
                    return Vec::new();
                };
                compute_selected_highlights(patch, selected.get())
            })
        });
        let hovered_range = Memo::new(move |_| {
            patch_state.with(|p| compute_hovered_range(p.as_ref()?, hovered.get()))
        });
        let highlight_range_count = Memo::new(move |_| {
            selected_highlights.with(Vec::len) + usize::from(hovered_range.get().is_some())
        });
        let read_only = Memo::new(move |_| envelope_view.with(Option::is_some));
        let bytes_count = Memo::new(move |_| {
            // patch_bytes mirrors the patch's root bytes; reading it keeps
            // this memo off the patch_state invalidation path.
            patch_bytes
                .with(|b| b.as_ref().map(ByteView::len))
                .or_else(|| raw_bytes.with(|b| b.as_ref().map(ByteView::len)))
        });
        let root_field_count = Memo::new(move |_| {
            patch_state.with(|p| {
                let patch = p.as_ref()?;
                let fields = patch.message_fields(patch.root()).ok()?;
                let mut live: usize = 0;
                for fid in fields {
                    if matches!(patch.field_is_deleted(fid), Ok(true)) {
                        continue;
                    }
                    live = live.saturating_add(1);
                }
                Some(live)
            })
        });
        let dirty_count = Memo::new(move |_| dirty_fields.with(std::collections::HashSet::len));

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
            selected_highlights,
            hovered_range,
            highlight_range_count,
            read_only,
            bytes_count,
            root_field_count,
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
        // Order matters: the old Patch borrows the old ByteView's backing
        // bytes, so the borrower must be replaced before its backing drops.
        self.patch_state.set(Some(patch));
        self.patch_bytes.set(Some(bytes));
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
        // Same ordering contract as `show_root_patch`: replace the borrowing
        // Patch before dropping the ByteView that backs it.
        self.patch_state.set(Some(patch));
        self.patch_bytes.set(Some(bytes));
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
