use crate::components::{
    Breadcrumb, EnvelopeFramesPanel, FieldTree, InspectorDrawer, MessageSidebar, StatusBar,
};
use crate::hex_view::HexGrid;
use crate::messages::{self, MessageMeta};
use crate::services::{EnvelopeService, ExportService, MessageService, WorkspaceService};
use crate::state::{parse_theme, MessageCatalogState, Theme, UiState, WorkspaceState};
use crate::toast::{ToastContainer, ToastKind, ToastManager};
use crate::web::{get_document_theme, set_document_theme, start_theme_transition};
use crate::workspace::visible_fields as visible_workspace_fields;
use leptos::html;
use leptos::prelude::*;
use leptos_use::use_event_listener;
use protobuf_edit::TreeError;
use wasm_bindgen::JsCast;

#[component]
pub fn App() -> impl IntoView {
    let ws = WorkspaceState::new();
    let toast = ToastManager::new();

    let raw_input = RwSignal::new(String::new());
    let import_name_text = RwSignal::new(String::new());
    let messages_list: RwSignal<Vec<MessageMeta>> = RwSignal::new(Vec::new());
    let current_message_id = RwSignal::new(None);
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
    let ui = UiState { theme_is_dark, toast };

    let ws_svc = WorkspaceService::new(ws.clone(), catalog.clone(), toast);
    let load_nonce: RwSignal<u64> = RwSignal::new(0);
    let msg_svc =
        MessageService::new(ws.clone(), catalog.clone(), toast, ws_svc.clone(), load_nonce);
    let env_svc = EnvelopeService::new(ws.clone(), catalog.clone(), toast, msg_svc.clone());
    let export_svc = ExportService::new(ws.clone(), catalog.clone(), toast);

    provide_context(ws.clone());
    provide_context(catalog.clone());
    provide_context(ui.clone());
    provide_context(msg_svc.clone());
    provide_context(env_svc.clone());
    provide_context(ws_svc.clone());
    provide_context(export_svc.clone());

    Effect::new(move |_| {
        let _ = set_document_theme(theme.get().as_str());
    });

    let patch_state = ws.patch_state;
    let raw_bytes = ws.raw_bytes;
    let envelope_view = ws.envelope_view;
    let selected = ws.selected;
    let expanded = ws.expanded;
    let dirty_count = ws.dirty_count;
    let hex_text_mode = ws.hex_text_mode;

    Effect::new({
        let msg_svc = msg_svc.clone();
        move |_| msg_svc.bootstrap()
    });

    let split_ref = NodeRef::<html::Div>::new();
    let hex_container_ref = NodeRef::<html::Div>::new();
    let tree_container_ref = NodeRef::<html::Div>::new();
    let split_pct: RwSignal<f64> = RwSignal::new(50.0);
    let split_dragging: RwSignal<bool> = RwSignal::new(false);

    let _stop_hotkeys = {
        let ws_svc = ws_svc.clone();
        let ws = ws.clone();
        use_event_listener(
            web_sys::window().expect("window is available"),
            leptos::ev::keydown,
            move |ev: web_sys::KeyboardEvent| {
                if ev.target().is_some_and(|target| {
                    target.dyn_ref::<web_sys::HtmlInputElement>().is_some()
                        || target.dyn_ref::<web_sys::HtmlTextAreaElement>().is_some()
                        || target.dyn_ref::<web_sys::HtmlSelectElement>().is_some()
                }) {
                    return;
                }

                let key = ev.key();

                if key == "Tab" && !ev.ctrl_key() && !ev.meta_key() && !ev.alt_key() {
                    let Some(hex) = hex_container_ref.get() else {
                        return;
                    };
                    let Some(tree) = tree_container_ref.get() else {
                        return;
                    };
                    ev.prevent_default();

                    let active_in_hex = web_sys::window()
                        .and_then(|w| w.document())
                        .and_then(|d| d.active_element())
                        .is_some_and(|active| {
                            let active: web_sys::Node = active.unchecked_into();
                            let hex: web_sys::Node = hex.clone().unchecked_into();
                            hex.contains(Some(&active))
                        });

                    if active_in_hex {
                        let _ = tree.focus();
                    } else {
                        let _ = hex.focus();
                    }
                    return;
                }

                if (ev.ctrl_key() || ev.meta_key()) && key.eq_ignore_ascii_case("z") {
                    if patch_state.with_untracked(|p| p.is_some())
                        && dirty_count.get_untracked() > 0
                    {
                        ev.prevent_default();
                        ws_svc.revert_edits();
                    }
                    return;
                }

                if (ev.ctrl_key() || ev.meta_key()) && key.eq_ignore_ascii_case("s") {
                    ev.prevent_default();
                    if patch_state.with_untracked(|p| p.is_some())
                        && dirty_count.get_untracked() > 0
                    {
                        let _ = ws_svc.save_reparse();
                    }
                    return;
                }

                match key.as_str() {
                    "Escape" => {
                        ev.prevent_default();
                        selected.set(None);
                        ws.hex_selection.set(None);
                    }
                    "ArrowDown" => {
                        ev.prevent_default();
                        let visible = visible_workspace_fields(&ws);
                        if visible.is_empty() {
                            return;
                        }

                        let next = match selected.get_untracked() {
                            None => visible.first().copied(),
                            Some(cur) => visible
                                .iter()
                                .position(|&f| f == cur)
                                .and_then(|i| visible.get(i + 1))
                                .copied()
                                .or(Some(cur)),
                        };
                        selected.set(next);
                    }
                    "ArrowUp" => {
                        ev.prevent_default();
                        let visible = visible_workspace_fields(&ws);
                        if visible.is_empty() {
                            return;
                        }

                        let prev = match selected.get_untracked() {
                            None => visible.last().copied(),
                            Some(cur) => visible
                                .iter()
                                .position(|&f| f == cur)
                                .and_then(|i| i.checked_sub(1).and_then(|j| visible.get(j)))
                                .copied()
                                .or(Some(cur)),
                        };
                        selected.set(prev);
                    }
                    "Enter" => {
                        let Some(field) = selected.get_untracked() else {
                            return;
                        };
                        let is_len = patch_state.with_untracked(|p| {
                            let Some(patch) = p.as_ref() else {
                                return false;
                            };
                            patch
                                .field_tag(field)
                                .ok()
                                .is_some_and(|tag| tag.wire_type() == protobuf_edit::WireType::Len)
                        });
                        if !is_len {
                            return;
                        }

                        ev.prevent_default();

                        if expanded.with_untracked(|s| s.contains(&field)) {
                            expanded.update(|s| {
                                s.remove(&field);
                            });
                            return;
                        }

                        let mut parsed: Option<Result<protobuf_edit::MessageId, TreeError>> = None;
                        patch_state.update(|p| {
                            let Some(patch) = p.as_mut() else {
                                parsed = Some(Err(TreeError::DecodeError));
                                return;
                            };
                            parsed = Some(patch.parse_child_message(field));
                        });

                        match parsed.unwrap_or(Err(TreeError::DecodeError)) {
                            Ok(_child) => expanded.update(|s| {
                                s.insert(field);
                            }),
                            Err(e) => toast.show(
                                ToastKind::Error,
                                format!("Failed to parse child message: {e:?}"),
                            ),
                        }
                    }
                    _ => {}
                }
            },
        )
    };

    let on_split_mouse_move = move |ev: leptos::ev::MouseEvent| {
        if !split_dragging.get_untracked() {
            return;
        }
        let Some(el) = split_ref.get() else {
            return;
        };
        let rect = el.get_bounding_client_rect();
        let x = ev.client_x() as f64 - rect.left();
        let w = rect.width();
        if w <= 0.0 {
            return;
        }
        let pct = (x / w * 100.0).clamp(20.0, 80.0);
        split_pct.set(pct);
    };

    let stop_split_drag = move |_| {
        split_dragging.set(false);
    };

    let structure_tree_fallback = move || {
        if raw_bytes.with(|b| b.is_some()) {
            view! { <div class="panel-header">"No protobuf structure."</div> }.into_any()
        } else {
            view! { <div class="panel-header">"No data loaded."</div> }.into_any()
        }
    };

    let field_tree_view = move || {
        let root =
            patch_state.with(|p| p.as_ref().expect("Show ensures patch_state is Some").root());
        view! {
            <FieldTree
                msg=root
                depth=0
            />
        }
    };

    let on_toggle_theme = UnsyncCallback::new(move |_| {
        let _ = start_theme_transition(180);
        let next = theme.get_untracked().toggle();
        theme.set(next);
        let _ = messages::store_theme_pref(next.as_str());
    });

    view! {
        <div class="app">
            <div class="main">
                <div class="workspace">
                    <MessageSidebar on_toggle_theme=on_toggle_theme />

                    <div
                        node_ref=split_ref
                        class="split-pane"
                        on:mousemove=on_split_mouse_move
                        on:mouseup=stop_split_drag
                        on:mouseleave=stop_split_drag
                    >
                        <div
                            class="split-left"
                            style:flex=move || format!("0 0 {:.2}%", split_pct.get())
                        >
                            <div class="panel">
                                <div class="panel-header">
                                    <span>"Hex View"</span>
                                    <button
                                        class="btn btn--secondary"
                                        on:click=move |_| hex_text_mode.update(|m| *m = m.toggle())
                                    >
                                        {move || hex_text_mode.get().label()}
                                    </button>
                                </div>
                                <HexGrid container_ref=hex_container_ref />
                            </div>
                        </div>
                        <div
                            class="split-handle"
                            on:mousedown=move |ev: leptos::ev::MouseEvent| {
                                ev.prevent_default();
                                split_dragging.set(true);
                            }
                        ></div>
                        <div class="split-right" style:flex="1 1 0">
                            <div class="panel panel--right">
                                <div class="panel-header">"Structure Tree"</div>
                                <div class="structure">
                                    <Breadcrumb />

                                    <Show
                                        when=move || envelope_view.with(|s| s.is_some())
                                        fallback=|| ()
                                    >
                                        <EnvelopeFramesPanel />
                                    </Show>

                                    <div class="field-list" node_ref=tree_container_ref tabindex="0">
                                        <Show
                                            when=move || patch_state.with(|p| p.is_some())
                                            fallback=structure_tree_fallback
                                        >
                                            {field_tree_view}
                                        </Show>
                                    </div>

                                    <InspectorDrawer />
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <StatusBar />

            <ToastContainer toasts=toast.toasts_signal() />
        </div>
    }
}
