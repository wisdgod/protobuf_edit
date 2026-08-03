use crate::components::{Breadcrumb, FieldTree, InspectorDrawer, StatusBar};
use crate::hex_view::HexGrid;
use crate::services::WorkspaceService;
use crate::state::{UiState, WorkspaceState};
use crate::toast::ToastKind;
use leptos::html;
use leptos::prelude::*;
use leptos_use::use_event_listener;
use wasm_bindgen::JsCast;

/// One open document: hex view + structure tree + inspector + status bar.
///
/// Provides its tab's `WorkspaceState` as context, so every child component
/// transparently operates on this document.
#[component]
pub(crate) fn DocumentView(ws: WorkspaceState, split_px: RwSignal<f64>) -> impl IntoView {
    provide_context(ws.clone());

    let ws_svc = expect_context::<WorkspaceService>();
    let ui = expect_context::<UiState>();
    let toast = ui.toast;
    let locale = ui.locale;
    let read_only = ui.read_only;

    let patch_state = ws.patch_state;
    let raw_bytes = ws.raw_bytes;
    let selected = ws.selected;
    let expanded = ws.expanded;
    let dirty_count = ws.dirty_count;
    let hex_selection = ws.hex_selection;
    let visible_fields = ws.visible_fields;

    let split_ref = NodeRef::<html::Div>::new();
    let hex_container_ref = NodeRef::<html::Div>::new();
    let tree_container_ref = NodeRef::<html::Div>::new();
    let split_dragging: RwSignal<bool> = RwSignal::new(false);

    let _stop_hotkeys = use_event_listener(
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
                if !read_only.get_untracked()
                    && patch_state.with_untracked(std::option::Option::is_some)
                    && dirty_count.get_untracked() > 0
                {
                    ev.prevent_default();
                    ws_svc.revert_edits();
                }
                return;
            }

            if (ev.ctrl_key() || ev.meta_key()) && key.eq_ignore_ascii_case("s") {
                ev.prevent_default();
                if !read_only.get_untracked()
                    && patch_state.with_untracked(std::option::Option::is_some)
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
                    hex_selection.set(None);
                }
                "ArrowDown" => {
                    ev.prevent_default();
                    let next = visible_fields.with_untracked(|visible| {
                        selected.get_untracked().map_or_else(
                            || visible.first().copied(),
                            |cur| {
                                visible
                                    .iter()
                                    .position(|&f| f == cur)
                                    .and_then(|i| visible.get(i + 1))
                                    .copied()
                                    .or(Some(cur))
                            },
                        )
                    });
                    if next.is_some() {
                        selected.set(next);
                    }
                }
                "ArrowUp" => {
                    ev.prevent_default();
                    let prev = visible_fields.with_untracked(|visible| {
                        selected.get_untracked().map_or_else(
                            || visible.last().copied(),
                            |cur| {
                                visible
                                    .iter()
                                    .position(|&f| f == cur)
                                    .and_then(|i| i.checked_sub(1).and_then(|j| visible.get(j)))
                                    .copied()
                                    .or(Some(cur))
                            },
                        )
                    });
                    if prev.is_some() {
                        selected.set(prev);
                    }
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
                            .is_ok_and(|tag| tag.wire_type() == protobuf_edit::WireType::Len)
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

                    match crate::workspace::parse_child_untracked(patch_state, field) {
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
    );

    // Window-level listeners keep the drag alive when the cursor leaves the
    // pane; mouseup anywhere ends it.
    let _stop_split_move = use_event_listener(
        web_sys::window().expect("window is available"),
        leptos::ev::mousemove,
        move |ev: web_sys::MouseEvent| {
            if !split_dragging.get_untracked() {
                return;
            }
            let Some(el) = split_ref.get() else {
                return;
            };
            let rect = el.get_bounding_client_rect();
            let w = rect.width();
            if w <= 0.0 {
                return;
            }
            // Hex pane may collapse to zero; the tree keeps a usable sliver.
            let max = (w - 220.0).max(0.0);
            let x = (f64::from(ev.client_x()) - rect.left()).clamp(0.0, max);
            split_px.set(x);
        },
    );

    let _stop_split_up = use_event_listener(
        web_sys::window().expect("window is available"),
        leptos::ev::mouseup,
        move |_| {
            if split_dragging.get_untracked() {
                split_dragging.set(false);
            }
        },
    );

    let structure_tree_fallback = move || {
        let t = locale.get().t();
        if raw_bytes.with(std::option::Option::is_some) {
            view! { <div class="panel-header">{t.no_protobuf_structure}</div> }.into_any()
        } else {
            view! { <div class="panel-header">{t.no_data_loaded}</div> }.into_any()
        }
    };

    let field_tree_view = move || {
        // `Show` gates on patch presence, but never panic if the value went
        // away between `when` and children evaluation.
        patch_state
            .with(|p| p.as_ref().map(protobuf_edit::Patch::root))
            .map(|root| view! { <FieldTree msg=root depth=0 /> })
    };

    view! {
        <div class="document">
            <div class="workspace">
                <div node_ref=split_ref class="split-pane">
                    <div
                        class="split-left"
                        style:flex=move || format!("0 1 {:.0}px", split_px.get())
                    >
                        <div class="panel">
                            <HexGrid container_ref=hex_container_ref />
                        </div>
                    </div>
                    <div
                        class="split-handle"
                        on:mousedown=move |ev: leptos::ev::MouseEvent| {
                            ev.prevent_default();
                            split_dragging.set(true);
                        }
                        // Double-click: snap the hex pane to the narrowest
                        // width without a horizontal scrollbar.
                        on:dblclick=move |_| {
                            let Some(el) = hex_container_ref.get() else {
                                return;
                            };
                            if let Some(w) = crate::hex_view::hex_fit_width(&el) {
                                split_px.set(w);
                            }
                        }
                    ></div>
                    <div class="split-right" style:flex="1 1 0">
                        <div class="panel panel--right">
                            <div class="structure">
                                <Breadcrumb />

                                <div class="field-list" node_ref=tree_container_ref tabindex="0">
                                    <Show
                                        when=move || patch_state.with(std::option::Option::is_some)
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

            <StatusBar />
        </div>
    }
}
