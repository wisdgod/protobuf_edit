use crate::state::WorkspaceState;
use crate::toast::ToastKind;
use crate::workspace::{format_user_path, parse_user_path, resolve_user_path};
use leptos::html;
use leptos::prelude::*;
use protobuf_edit::session::Handle;
use std::sync::Arc;
use wasm_bindgen::JsCast;

#[derive(Clone, PartialEq, Eq)]
struct Crumb {
    label: Arc<str>,
    field_id: Option<Handle>,
}

#[component]
pub(crate) fn Breadcrumb() -> impl IntoView {
    let workspace = expect_context::<WorkspaceState>();
    let ui = expect_context::<crate::state::UiState>();
    let toast = ui.toast;
    let locale = ui.locale;
    let read_only = ui.read_only;
    let session_state = workspace.session;
    let selected = workspace.selected;
    let expanded = workspace.expanded;
    let inspector_open = workspace.inspector_open;

    let editing = RwSignal::new(false);
    let edit_text = RwSignal::new(String::new());
    let input_ref = NodeRef::<html::Input>::new();

    let crumbs = Memo::new(move |_| {
        let selected_handle = selected.get();
        session_state.with(|s| {
            let Some(session) = s.as_ref() else {
                return vec![Crumb { label: Arc::<str>::from("."), field_id: None }];
            };

            let mut chain: Vec<Handle> = selected_handle
                .map(|handle| {
                    core::iter::once(handle)
                        .chain(session.ancestors(handle).ok().into_iter().flatten())
                        .collect()
                })
                .unwrap_or_default();
            chain.reverse();

            let mut out = Vec::with_capacity(chain.len().saturating_add(1));
            out.push(Crumb { label: Arc::<str>::from("."), field_id: None });
            for handle in chain {
                let label = session.field(handle).map_or_else(
                    |_| Arc::<str>::from("?"),
                    |field| Arc::<str>::from(field.as_inner().to_string()),
                );
                out.push(Crumb { label, field_id: Some(handle) });
            }
            out
        })
    });

    let current_path = Memo::new(move |_| {
        session_state
            .with(|s| {
                let session = s.as_ref()?;
                let handle = selected.get()?;
                format_user_path(session, handle)
            })
            .unwrap_or_else(|| ".".to_string())
    });

    let enter_edit = move |_| {
        edit_text.set(current_path.get_untracked());
        editing.set(true);
        request_animation_frame(move || {
            if let Some(el) = input_ref.get() {
                let _ = el.focus();
                el.select();
            }
        });
    };

    let cancel_edit = move || {
        editing.set(false);
        edit_text.set(String::new());
    };

    let navigate = move || {
        let input = edit_text.get_untracked();
        let Some(steps) = parse_user_path(&input) else {
            toast.show(ToastKind::Alert, "Invalid path format. Use .field.field:occurrence");
            return;
        };
        editing.set(false);

        if steps.is_empty() {
            selected.set(None);
            return;
        }

        let mut result = None;
        session_state.update(|s| {
            let Some(session) = s.as_mut() else {
                return;
            };
            result = Some(resolve_user_path(session, &steps));
        });

        match result {
            Some(Ok(Some((handle, new_expanded)))) => {
                expanded.update(|s| s.extend(new_expanded));
                selected.set(Some(handle));
            }
            Some(Ok(None)) => {
                toast.show(ToastKind::Alert, format!("Path not found: {input}"));
            }
            Some(Err(e)) => {
                toast.show(ToastKind::Alert, format!("Path resolution error: {e}"));
            }
            None => {
                toast.show(ToastKind::Alert, "No protobuf loaded.");
            }
        }
    };

    let on_keydown = move |ev: leptos::ev::KeyboardEvent| match ev.key().as_str() {
        "Enter" => {
            ev.prevent_default();
            navigate();
        }
        "Escape" => {
            ev.prevent_default();
            cancel_edit();
        }
        _ => {}
    };

    let on_blur = move |ev: leptos::ev::FocusEvent| {
        if let Some(related) = ev.related_target()
            && let Ok(btn) = related.dyn_into::<web_sys::HtmlButtonElement>()
            && btn.class_list().contains("breadcrumb-clear")
        {
            return;
        }
        cancel_edit();
    };

    let on_clear = move |_| {
        edit_text.set(String::new());
        if let Some(el) = input_ref.get() {
            let _ = el.focus();
        }
    };

    view! {
        <div class="breadcrumb">
            <Show
                when=move || editing.get()
                fallback=move || {
                    let crumbs_view = move || {
                        let items = crumbs.get();
                        let len = items.len();
                        items
                            .into_iter()
                            .enumerate()
                            .map(|(i, crumb)| {
                                let is_last = i + 1 == len;
                                let show_sep = i > 0 && !is_last;
                                let label = crumb.label;
                                let field_id = crumb.field_id;
                                view! {
                                    <span class="breadcrumb-item" on:click=move |ev: web_sys::MouseEvent| {
                                        ev.stop_propagation();
                                        selected.set(field_id);
                                    }>
                                        {Oco::from(label)}
                                    </span>
                                    <Show when=move || show_sep fallback=|| ()>
                                        <span class="breadcrumb-sep">"."</span>
                                    </Show>
                                }
                            })
                            .collect_view()
                    };
                    view! {
                        <div class="breadcrumb-display" on:click=enter_edit>
                            {crumbs_view}
                        </div>
                    }
                }
            >
                <input
                    node_ref=input_ref
                    class="input breadcrumb-edit"
                    prop:value=move || edit_text.get()
                    on:input=move |ev| edit_text.set(event_target_value(&ev))
                    on:keydown=on_keydown
                    on:blur=on_blur
                />
                <button class="breadcrumb-clear" on:mousedown=on_clear title="Clear">
                    "\u{00D7}"
                </button>
            </Show>
            <Show when=move || !read_only.get() fallback=|| ()>
                <button
                    class="btn btn--secondary btn--small breadcrumb-insert"
                    class:btn--active=move || inspector_open.get()
                    title=move || locale.get().t().inspector_open_title
                    on:click=move |_| inspector_open.update(|v| *v = !*v)
                >
                    {move || locale.get().t().inspector}
                </button>
            </Show>
        </div>
    }
}
