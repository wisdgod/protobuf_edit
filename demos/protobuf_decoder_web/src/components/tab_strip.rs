use crate::services::MessageService;
use crate::state::{MessageCatalogState, Tab, TabsState, UiState};
use leptos::prelude::*;

/// The resident tab strip: a pinned Library entry plus one tab per open
/// document (message or envelope).
#[component]
pub(crate) fn TabStrip() -> impl IntoView {
    let tabs = expect_context::<TabsState>();
    let locale = expect_context::<UiState>().locale;
    let tabs_for_start = tabs.clone();

    let is_start = {
        let tabs = tabs.clone();
        move || tabs.active.get().is_none()
    };

    view! {
        <div class="tab-strip">
            <button
                class="tab tab--library"
                class:tab--active=is_start
                on:click=move |_| tabs_for_start.show_start()
            >
                {move || locale.get().t().library}
            </button>
            <For
                each={
                    let tabs = tabs.clone();
                    move || tabs.tabs.get()
                }
                key=|tab| tab.id
                children=move |tab| tab_view(&tab)
            />
        </div>
    }
}

fn tab_view(tab: &Tab) -> impl IntoView + use<> {
    let tabs = expect_context::<TabsState>();
    let msg_svc = expect_context::<MessageService>();
    let catalog = expect_context::<MessageCatalogState>();
    let locale = expect_context::<UiState>().locale;
    let messages_list = catalog.messages_list;

    let tab_id = tab.id;
    let mid = tab.message_id;
    let is_envelope = tab.is_envelope();
    let dirty_count = tab.message_ws().map(|ws| ws.dirty_count);

    let title = Memo::new(move |_| {
        let t = locale.get().t();
        let name = messages_list.with(|list| {
            list.iter()
                .find(|m| m.id == mid)
                .map_or_else(|| format!("{} {mid}", t.message_fallback), |m| m.name.to_string())
        });
        if is_envelope { format!("{name} \u{00B7} {}", t.frames_tab_suffix) } else { name }
    });

    let is_active = {
        let tabs = tabs.clone();
        move || tabs.active.get() == Some(tab_id)
    };

    // Message tabs may need a (re)load on focus; envelope tab bodies load
    // themselves on mount, so plain activation is enough for them.
    let on_activate = {
        let tabs = tabs.clone();
        move |_| {
            if is_envelope {
                tabs.activate(tab_id);
            } else {
                msg_svc.switch_to(mid);
            }
        }
    };

    let close_svc = expect_context::<MessageService>();
    let aux_close_svc = close_svc.clone();

    view! {
        <div
            class="tab"
            class:tab--active=is_active
            title=move || title.get()
            on:click=on_activate
            on:auxclick=move |ev: web_sys::MouseEvent| {
                if ev.button() == 1 {
                    ev.prevent_default();
                    aux_close_svc.close_tab(tab_id);
                }
            }
        >
            <span
                class="tab-dirty"
                class:hidden=move || dirty_count.is_none_or(|d| d.get() == 0)
            >
                "\u{25CF}"
            </span>
            <span class="tab-title">{move || title.get()}</span>
            <button
                class="tab-close"
                title=move || locale.get().t().close_tab
                on:click=move |ev: web_sys::MouseEvent| {
                    ev.stop_propagation();
                    close_svc.close_tab(tab_id);
                }
            >
                "\u{00D7}"
            </button>
        </div>
    }
}
