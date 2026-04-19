use crate::state::WorkspaceState;
use crate::toast::ToastKind;
use crate::workspace::{format_user_path, parse_user_path, resolve_user_path};
use leptos::html;
use leptos::prelude::*;
use protobuf_edit::FieldId;
use std::sync::Arc;
use wasm_bindgen::JsCast;

#[derive(Clone, PartialEq, Eq)]
struct Crumb {
    label: Arc<str>,
    field_id: Option<FieldId>,
}

#[component]
pub(crate) fn Breadcrumb() -> impl IntoView {
    let workspace = expect_context::<WorkspaceState>();
    let toast = expect_context::<crate::state::UiState>().toast;
    let patch_state = workspace.patch_state;
    let selected = workspace.selected;
    let expanded = workspace.expanded;

    let editing = RwSignal::new(false);
    let edit_text = RwSignal::new(String::new());
    let input_ref = NodeRef::<html::Input>::new();

    let crumbs = Memo::new(move |_| {
        let selected_field = selected.get();
        patch_state.with(|p| {
            let Some(patch) = p.as_ref() else {
                return vec![Crumb { label: Arc::<str>::from("."), field_id: None }];
            };

            let mut chain_fields: Vec<FieldId> = Vec::new();
            if let Some(fid) = selected_field {
                chain_fields.push(fid);
                let mut msg = patch.field_parent_message(fid).ok();
                while let Some(m) = msg {
                    match patch.message_parent_field(m) {
                        Ok(Some(parent_field)) => {
                            chain_fields.push(parent_field);
                            msg = patch.field_parent_message(parent_field).ok();
                        }
                        Ok(None) => break,
                        Err(_) => break,
                    }
                }
            }
            chain_fields.reverse();

            let mut out = Vec::with_capacity(chain_fields.len().saturating_add(1));
            out.push(Crumb { label: Arc::<str>::from("."), field_id: None });
            for fid in chain_fields {
                let label = match patch.field_tag(fid) {
                    Ok(tag) => Arc::<str>::from(tag.field_number().as_inner().to_string()),
                    Err(_) => Arc::<str>::from("?"),
                };
                out.push(Crumb { label, field_id: Some(fid) });
            }
            out
        })
    });

    let current_path = Memo::new(move |_| {
        patch_state.with(|p| {
            let patch = p.as_ref()?;
            let fid = selected.get()?;
            format_user_path(patch, fid)
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
            toast.show(ToastKind::Error, "Invalid path format. Use .field.field:occurrence");
            return;
        };
        editing.set(false);

        if steps.is_empty() {
            selected.set(None);
            return;
        }

        let mut result = None;
        patch_state.update(|p| {
            let Some(patch) = p.as_mut() else {
                result = Some(Err(protobuf_edit::TreeError::DecodeError));
                return;
            };
            result = Some(resolve_user_path(patch, &steps));
        });

        match result {
            Some(Ok(Some((fid, new_expanded)))) => {
                expanded.update(|s| s.extend(new_expanded));
                selected.set(Some(fid));
            }
            Some(Ok(None)) => {
                toast.show(ToastKind::Error, format!("Path not found: {input}"));
            }
            Some(Err(e)) => {
                toast.show(ToastKind::Error, format!("Path resolution error: {e:?}"));
            }
            None => {
                toast.show(ToastKind::Error, "No protobuf loaded.");
            }
        }
    };

    let on_keydown = move |ev: leptos::ev::KeyboardEvent| {
        match ev.key().as_str() {
            "Enter" => {
                ev.prevent_default();
                navigate();
            }
            "Escape" => {
                ev.prevent_default();
                cancel_edit();
            }
            _ => {}
        }
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
                                let label = crumb.label;
                                let field_id = crumb.field_id;
                                view! {
                                    <span class="breadcrumb-item" on:click=move |_| selected.set(field_id)>
                                        {Oco::from(label)}
                                    </span>
                                    <Show when=move || !is_last fallback=|| ()>
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
        </div>
    }
}
