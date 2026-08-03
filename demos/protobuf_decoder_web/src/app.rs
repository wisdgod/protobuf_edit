use crate::components::{DocumentView, EnvelopeTabView, StartPage, TabStrip, ThemeSwitcher};
use crate::messages::{self, MessageId, MessageMeta};
use crate::services::{EnvelopeService, ExportService, MessageService, WorkspaceService};
use crate::state::{parse_theme, MessageCatalogState, TabsState, Theme, UiState};
use crate::toast::{ToastContainer, ToastManager};
use crate::web::{get_document_theme, set_document_theme, start_theme_transition};
use leptos::prelude::*;

#[component]
pub fn App() -> impl IntoView {
    let toast = ToastManager::new();

    let raw_input = RwSignal::new(String::new());
    let import_name_text = RwSignal::new(String::new());
    let messages_list: RwSignal<Vec<MessageMeta>> = RwSignal::new(Vec::new());
    let current_message_id: RwSignal<Option<MessageId>> = RwSignal::new(None);
    let message_name_text = RwSignal::new(String::new());
    let frame_name_template_text = RwSignal::new(messages::DEFAULT_FRAME_NAME_TEMPLATE.to_string());

    let initial_theme = get_document_theme()
        .ok()
        .flatten()
        .as_deref()
        .and_then(parse_theme)
        .unwrap_or(Theme::Light);
    let theme: RwSignal<Theme> = RwSignal::new(initial_theme);
    let theme_is_dark = Memo::new(move |_| theme.get() == Theme::Dark);

    let catalog = MessageCatalogState {
        raw_input,
        import_name_text,
        messages_list,
        current_message_id,
        message_name_text,
        frame_name_template_text,
    };
    let ui = UiState { toast };

    let tabs = TabsState::new(current_message_id);

    let ws_svc = WorkspaceService::new(tabs.clone(), catalog.clone(), toast);
    let msg_svc = MessageService::new(tabs.clone(), catalog.clone(), toast, ws_svc.clone());
    let env_svc = EnvelopeService::new(tabs.clone(), catalog.clone(), toast, msg_svc.clone());
    let export_svc = ExportService::new(tabs.clone(), catalog.clone(), toast);

    provide_context(tabs.clone());
    provide_context(catalog);
    provide_context(ui);
    provide_context(msg_svc.clone());
    provide_context(env_svc);
    provide_context(ws_svc.clone());
    provide_context(export_svc);

    Effect::new(move |_| {
        let _ = set_document_theme(theme.get().as_str());
    });

    {
        let msg_svc = msg_svc.clone();
        Effect::new(move |_| msg_svc.bootstrap());
    }

    // Persist the working set (open tabs + active tab) across reloads.
    {
        let tabs = tabs.clone();
        Effect::new(move |prev: Option<()>| {
            let open = tabs.open_tabs_persisted();
            let active = tabs.active_tab_persisted();
            // Skip the very first run so bootstrap restoration reads the
            // stored values before this effect overwrites them.
            if prev.is_some() {
                let _ = messages::set_open_tabs(&open);
                let _ = messages::set_active_tab(active);
            }
        });
    }

    // Keep the export-filename mirror in sync with the active document.
    Effect::new(move |_| {
        let name = current_message_id.get().and_then(|id| {
            messages_list.with(|list| list.iter().find(|m| m.id == id).map(|m| m.name.clone()))
        });
        let name = name.as_deref().unwrap_or("");
        if message_name_text.with_untracked(|s| s.as_str() != name) {
            message_name_text.set(name.to_string());
        }
    });

    // Hex pane width in px, shared across tabs so the layout stays put when
    // switching documents. Default fits one full 16-byte row.
    let split_px: RwSignal<f64> = RwSignal::new(620.0);

    let on_open_message = {
        let msg_svc = msg_svc.clone();
        UnsyncCallback::new(move |id: MessageId| {
            msg_svc.switch_to(id);
        })
    };

    let on_toggle_theme = UnsyncCallback::new(move |()| {
        let _ = start_theme_transition(180);
        let next = theme.get_untracked().toggle();
        theme.set(next);
        let _ = messages::store_theme_pref(next.as_str());
    });

    let active_tab_id = {
        let tabs = tabs.clone();
        Memo::new(move |_| tabs.active.get())
    };

    let main_view = {
        let tabs = tabs.clone();
        move || {
            let tab = active_tab_id.get().and_then(|tab_id| tabs.get(tab_id));
            let Some(tab) = tab else {
                return view! { <StartPage on_open=on_open_message /> }.into_any();
            };
            match &tab.doc {
                crate::state::TabDoc::Message(ws) => {
                    view! { <DocumentView ws=ws.clone() split_px=split_px /> }.into_any()
                }
                crate::state::TabDoc::Envelope(env) => {
                    view! { <EnvelopeTabView env=env.clone() split_px=split_px /> }.into_any()
                }
            }
        }
    };

    view! {
        <div class="app">
            <div class="shell-bar">
                <TabStrip />
                <ThemeSwitcher is_night=theme_is_dark on_toggle=on_toggle_theme />
            </div>

            <div class="main">{main_view}</div>

            <ToastContainer toasts=toast.toasts_signal() />
        </div>
    }
}
