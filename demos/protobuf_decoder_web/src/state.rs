use crate::bytes::ByteView;
use crate::envelope::EnvelopeView;
use rustc_hash::FxHashSet;
use crate::hex_view::HexTextMode;
use crate::i18n::Locale;
use crate::messages::{MessageId, MessageMeta, PersistedTab};
use crate::toast::ToastManager;
use crate::workspace::{
    collect_visible_fields, compute_hovered_range, compute_selected_highlights, HighlightRange,
};
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

    pub selected: RwSignal<Option<FieldId>>,
    pub hovered: RwSignal<Option<FieldId>>,
    pub expanded: RwSignal<FxHashSet<FieldId>>,
    /// Len fields whose child parse failed: their expand affordance is
    /// settled as "no" (a fresh Len field shows an undetermined arrow
    /// until a click settles it one way or the other).
    pub parse_failed: RwSignal<FxHashSet<FieldId>>,
    pub dirty_fields: RwSignal<FxHashSet<FieldId>>,
    pub hex_text_mode: RwSignal<HexTextMode>,
    pub hex_selection: RwSignal<Option<(usize, usize)>>,
    /// Whether the inspector drawer was opened manually (without selection).
    pub inspector_open: RwSignal<bool>,
    /// Inspector drawer height in px (per-document UI preference).
    pub inspector_height: RwSignal<f64>,

    pub selected_highlights: Memo<Vec<HighlightRange>>,
    pub hovered_range: Memo<Option<HighlightRange>>,
    pub highlight_range_count: Memo<usize>,
    /// Fields in tree display order (expanded subtrees inlined), for
    /// keyboard navigation.
    pub visible_fields: Memo<Vec<FieldId>>,
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

        let selected: RwSignal<Option<FieldId>> = RwSignal::new(None);
        let hovered: RwSignal<Option<FieldId>> = RwSignal::new(None);
        let expanded: RwSignal<FxHashSet<FieldId>> = RwSignal::new(FxHashSet::default());
        let parse_failed: RwSignal<FxHashSet<FieldId>> = RwSignal::new(FxHashSet::default());
        let dirty_fields: RwSignal<FxHashSet<FieldId>> = RwSignal::new(FxHashSet::default());
        let hex_text_mode: RwSignal<HexTextMode> = RwSignal::new(HexTextMode::Ascii);
        let hex_selection: RwSignal<Option<(usize, usize)>> = RwSignal::new(None);
        let inspector_open: RwSignal<bool> = RwSignal::new(false);
        let inspector_height: RwSignal<f64> = RwSignal::new(280.0);

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
        let visible_fields = Memo::new(move |_| {
            patch_state.with(|p| {
                let Some(patch) = p.as_ref() else {
                    return Vec::new();
                };
                expanded.with(|exp| {
                    let mut out = Vec::new();
                    collect_visible_fields(patch, patch.root(), exp, &mut out);
                    out
                })
            })
        });
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
            selected,
            hovered,
            expanded,
            parse_failed,
            dirty_fields,
            hex_text_mode,
            hex_selection,
            inspector_open,
            inspector_height,
            selected_highlights,
            hovered_range,
            highlight_range_count,
            visible_fields,
            bytes_count,
            root_field_count,
            dirty_count,
        }
    }

    pub(crate) fn reset_ui_state(&self) {
        self.selected.set(None);
        self.hovered.set(None);
        self.expanded.set(FxHashSet::default());
        self.parse_failed.set(FxHashSet::default());
        self.dirty_fields.set(FxHashSet::default());
        self.hex_selection.set(None);
        self.inspector_open.set(false);
    }

    pub(crate) fn reset_ui_state_keep_selected(
        &self,
        new_selected: Option<FieldId>,
        new_expanded: FxHashSet<FieldId>,
    ) {
        self.selected.set(new_selected);
        self.hovered.set(None);
        self.expanded.set(new_expanded);
        self.parse_failed.set(FxHashSet::default());
        self.dirty_fields.set(FxHashSet::default());
        self.hex_selection.set(None);
    }

    pub(crate) fn clear_loaded_data(&self) {
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
        // Order matters: the old Patch borrows the old ByteView's backing
        // bytes, so the borrower must be replaced before its backing drops.
        self.patch_state.set(Some(patch));
        self.patch_bytes.set(Some(bytes));
        self.raw_bytes.set(None);
        self.reset_ui_state_keep_selected(new_selected, new_expanded);
    }

    pub(crate) fn show_root_raw_bytes(&self, bytes: ByteView) {
        self.patch_state.set(None);
        self.patch_bytes.set(None);
        self.raw_bytes.set(Some(bytes));
        self.reset_ui_state();
    }
}

/// State of one open envelope tab: the parsed frame list plus a read-only
/// preview workspace for the selected frame.
#[derive(Clone)]
pub(crate) struct EnvelopeTabState {
    pub view: RwSignal<Option<EnvelopeView>, LocalStorage>,
    pub selected: RwSignal<usize>,
    pub preview: WorkspaceState,
}

impl EnvelopeTabState {
    pub(crate) fn new() -> Self {
        Self {
            view: RwSignal::new_local(None),
            selected: RwSignal::new(0),
            preview: WorkspaceState::new(),
        }
    }

    /// Frees loaded data; the preview `Patch` is cleared before the envelope
    /// bytes backing it drop.
    pub(crate) fn clear_loaded_data(&self) {
        self.preview.clear_loaded_data();
        self.view.set(None);
        self.selected.set(0);
    }
}

pub(crate) type TabId = u64;

/// Document payload of a tab: an editable message workspace, or an envelope
/// frame browser with a read-only preview.
#[derive(Clone)]
pub(crate) enum TabDoc {
    Message(WorkspaceState),
    Envelope(EnvelopeTabState),
}

/// One open document: its identity plus dedicated state that keeps
/// selection/expansion/edits alive across tab switches.
#[derive(Clone)]
pub(crate) struct Tab {
    pub id: TabId,
    /// The backing message: the document itself for message tabs, the
    /// envelope source for envelope tabs.
    pub message_id: MessageId,
    pub doc: TabDoc,
    /// Cancellation token for this tab's async byte loads.
    pub load_nonce: RwSignal<u64>,
}

impl Tab {
    pub(crate) fn message_ws(&self) -> Option<WorkspaceState> {
        match &self.doc {
            TabDoc::Message(ws) => Some(ws.clone()),
            TabDoc::Envelope(_) => None,
        }
    }

    pub(crate) fn envelope(&self) -> Option<EnvelopeTabState> {
        match &self.doc {
            TabDoc::Message(_) => None,
            TabDoc::Envelope(env) => Some(env.clone()),
        }
    }

    pub(crate) const fn is_envelope(&self) -> bool {
        matches!(self.doc, TabDoc::Envelope(_))
    }

    fn clear_loaded_data(&self) {
        match &self.doc {
            TabDoc::Message(ws) => ws.clear_loaded_data(),
            TabDoc::Envelope(env) => env.clear_loaded_data(),
        }
    }
}

/// The open working set. `active == None` shows the start/library view.
///
/// Closed tabs leak their (small) signal arena slots; documents' byte
/// buffers are freed explicitly in `close`, so the leak is bounded and
/// acceptable for a demo.
#[derive(Clone)]
pub(crate) struct TabsState {
    pub tabs: RwSignal<Vec<Tab>, LocalStorage>,
    pub active: RwSignal<Option<TabId>>,
    next_tab_id: RwSignal<TabId>,
    /// Mirror of the active tab's message id. This struct is the single
    /// writer; everything else only reads it.
    current_message_id: RwSignal<Option<MessageId>>,
    /// App-lifetime owner for per-tab signals. Tabs are created from event
    /// handlers whose reactive owner dies with the view that installed them
    /// (e.g. the start page); creating tab state there would leave disposed
    /// signals behind after navigation.
    owner: Owner,
}

impl TabsState {
    pub(crate) fn new(current_message_id: RwSignal<Option<MessageId>>) -> Self {
        Self {
            tabs: RwSignal::new_local(Vec::new()),
            active: RwSignal::new(None),
            next_tab_id: RwSignal::new(1),
            current_message_id,
            owner: Owner::current().expect("TabsState created outside a reactive owner"),
        }
    }

    fn alloc_id(&self) -> TabId {
        let id = self.next_tab_id.get_untracked();
        self.next_tab_id.set(id.wrapping_add(1));
        id
    }

    fn sync_mirror(&self) {
        let mid = self.active_message_id_untracked();
        if self.current_message_id.get_untracked() != mid {
            self.current_message_id.set(mid);
        }
    }

    pub(crate) fn get(&self, tab_id: TabId) -> Option<Tab> {
        self.tabs.with_untracked(|v| v.iter().find(|t| t.id == tab_id).cloned())
    }

    pub(crate) fn contains(&self, tab_id: TabId) -> bool {
        self.tabs.with_untracked(|v| v.iter().any(|t| t.id == tab_id))
    }

    pub(crate) fn find_message(&self, mid: MessageId) -> Option<Tab> {
        self.tabs
            .with_untracked(|v| v.iter().find(|t| t.message_id == mid && !t.is_envelope()).cloned())
    }

    pub(crate) fn find_envelope(&self, mid: MessageId) -> Option<Tab> {
        self.tabs
            .with_untracked(|v| v.iter().find(|t| t.message_id == mid && t.is_envelope()).cloned())
    }

    fn push_tab(&self, mid: MessageId, make_doc: impl FnOnce() -> TabDoc) -> Tab {
        // All per-tab signals must be built under the app-lifetime owner;
        // see the `owner` field.
        let tab = self.owner.with(|| Tab {
            id: self.alloc_id(),
            message_id: mid,
            doc: make_doc(),
            load_nonce: RwSignal::new(0),
        });
        let cloned = tab.clone();
        self.tabs.update(|v| v.push(cloned));
        tab
    }

    /// Creates (but does not activate) a new message tab.
    pub(crate) fn push_message_tab(&self, mid: MessageId) -> Tab {
        self.push_tab(mid, || TabDoc::Message(WorkspaceState::new()))
    }

    /// Creates (but does not activate) a new envelope tab for a source
    /// message.
    pub(crate) fn push_envelope_tab(&self, mid: MessageId) -> Tab {
        self.push_tab(mid, || TabDoc::Envelope(EnvelopeTabState::new()))
    }

    pub(crate) fn activate(&self, tab_id: TabId) {
        if !self.contains(tab_id) {
            return;
        }
        if self.active.get_untracked() != Some(tab_id) {
            self.active.set(Some(tab_id));
        }
        self.sync_mirror();
    }

    /// Shows the start/library view without closing any tab.
    pub(crate) fn show_start(&self) {
        if self.active.get_untracked().is_some() {
            self.active.set(None);
        }
        self.sync_mirror();
    }

    /// Closes a tab, freeing its loaded data first (the `Patch` must be
    /// dropped before the `ByteView` backing it).
    pub(crate) fn close(&self, tab_id: TabId) {
        let Some(tab) = self.get(tab_id) else {
            return;
        };
        tab.clear_loaded_data();

        let mut next_active: Option<TabId> = self.active.get_untracked();
        self.tabs.update(|v| {
            let Some(pos) = v.iter().position(|t| t.id == tab_id) else {
                return;
            };
            v.remove(pos);
            if next_active == Some(tab_id) {
                next_active = v.get(pos).or_else(|| v.get(pos.wrapping_sub(1))).map(|t| t.id);
            }
        });
        if self.active.get_untracked() != next_active {
            self.active.set(next_active);
        }
        self.sync_mirror();
    }

    pub(crate) fn active_tab_untracked(&self) -> Option<Tab> {
        let tab_id = self.active.get_untracked()?;
        self.get(tab_id)
    }

    /// The active tab's message workspace; `None` for envelope tabs or the
    /// start view.
    pub(crate) fn active_ws_untracked(&self) -> Option<WorkspaceState> {
        self.active_tab_untracked().and_then(|t| t.message_ws())
    }

    pub(crate) fn active_message_id_untracked(&self) -> Option<MessageId> {
        self.active_tab_untracked().map(|t| t.message_id)
    }

    /// Tracked persisted form of the working set, in tab order.
    pub(crate) fn open_tabs_persisted(&self) -> Vec<PersistedTab> {
        self.tabs.with(|v| v.iter().map(persisted_of).collect())
    }

    /// Tracked persisted form of the active tab.
    pub(crate) fn active_tab_persisted(&self) -> Option<PersistedTab> {
        let tab_id = self.active.get()?;
        self.tabs.with(|v| v.iter().find(|t| t.id == tab_id).map(persisted_of))
    }
}

fn persisted_of(tab: &Tab) -> PersistedTab {
    if tab.is_envelope() {
        PersistedTab::Envelope(tab.message_id)
    } else {
        PersistedTab::Message(tab.message_id)
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
    pub toast: ToastManager,
    pub locale: RwSignal<Locale>,
    /// Hides all editing UI (inspector, save, insert) when set.
    pub read_only: RwSignal<bool>,
}
