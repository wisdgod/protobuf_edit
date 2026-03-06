use crate::envelope::EnvelopeView;
use crate::fx::FxHashSet;
use crate::hex_view::HexTextMode;
use crate::messages::{MessageId, MessageMeta};
use crate::toast::Toast;
use crate::workspace::HighlightRange;
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
    pub raw_bytes: RwSignal<Option<crate::bytes::ByteView>, LocalStorage>,
    pub envelope_view: RwSignal<Option<EnvelopeView>, LocalStorage>,
    pub envelope_selected: RwSignal<usize>,
    pub selected: RwSignal<Option<FieldId>>,
    pub hovered: RwSignal<Option<FieldId>>,
    pub expanded: RwSignal<FxHashSet<FieldId>>,
    pub dirty_fields: RwSignal<FxHashSet<FieldId>>,
    pub hex_text_mode: RwSignal<HexTextMode>,
    pub highlights: Memo<Vec<HighlightRange>>,
    pub highlight_range_count: Memo<usize>,
    pub read_only: Memo<bool>,
    pub bytes_count: Memo<Option<usize>>,
    pub field_count: Memo<Option<usize>>,
    pub dirty_count: Memo<usize>,
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
    pub toasts: RwSignal<Vec<Toast>>,
    pub next_toast_id: RwSignal<u64>,
}

#[derive(Clone)]
pub(crate) struct MessageSidebarActions {
    pub on_select_message: UnsyncCallback<MessageId>,
    pub on_message_name_change: UnsyncCallback<leptos::ev::Event>,
    pub on_rename_message: UnsyncCallback<(MessageId, String)>,
    pub on_rename_class: UnsyncCallback<(MessageId, String)>,
    pub on_new_message: UnsyncCallback<()>,
    pub on_delete_selected_messages: UnsyncCallback<Vec<MessageId>>,
    pub on_view_frames: UnsyncCallback<()>,
    pub on_import: UnsyncCallback<()>,
    pub on_import_envelope: UnsyncCallback<()>,
    pub on_upload_change: UnsyncCallback<leptos::ev::Event>,
    pub on_toggle_theme: UnsyncCallback<()>,
    pub on_store_frame_name_template: UnsyncCallback<()>,
}

#[derive(Clone)]
pub(crate) struct EnvelopeActions {
    pub on_close: UnsyncCallback<()>,
    pub on_decompress: UnsyncCallback<()>,
    pub on_open: UnsyncCallback<usize>,
    pub on_extract: UnsyncCallback<usize>,
    pub on_extract_all: UnsyncCallback<()>,
}

#[derive(Clone)]
pub(crate) struct StatusBarActions {
    pub on_copy_hex: UnsyncCallback<()>,
    pub on_copy_base64: UnsyncCallback<()>,
    pub on_copy_share_url: UnsyncCallback<()>,
    pub on_download_bin: UnsyncCallback<()>,
    pub on_save_expand_defaults: UnsyncCallback<()>,
    pub on_save_reparse: UnsyncCallback<()>,
    pub on_bump_modified: UnsyncCallback<()>,
}
