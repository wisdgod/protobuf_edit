use crate::state::WorkspaceState;
use crate::toast::ToastKind;
use crate::workspace::{format_user_path, parse_user_path, resolve_user_path};
use leptos::prelude::*;
use protobuf_edit::FieldId;
use std::sync::Arc;

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

    let path_input = RwSignal::new(String::new());

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

    let user_path = Memo::new(move |_| {
        let fid = selected.get()?;
        patch_state.with(|p| {
            let patch = p.as_ref()?;
            format_user_path(patch, fid)
        })
    });

    let on_path_submit = move |ev: leptos::ev::KeyboardEvent| {
        if ev.key() != "Enter" {
            return;
        }
        ev.prevent_default();
        let input = path_input.get_untracked();
        let Some(steps) = parse_user_path(&input) else {
            toast.show(ToastKind::Error, "Invalid path format. Use .field.field:occurrence");
            return;
        };
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
                path_input.set(String::new());
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

    view! {
        <div class="breadcrumb">
            <div class="breadcrumb-path">
                {move || {
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
                }}
            </div>
            <Show when=move || user_path.get().is_some() fallback=|| ()>
                <span class="breadcrumb-user-path">{move || user_path.get().unwrap_or_default()}</span>
            </Show>
            <input
                class="input breadcrumb-input"
                placeholder=".3.1.2"
                prop:value=move || path_input.get()
                on:input=move |ev| path_input.set(event_target_value(&ev))
                on:keydown=on_path_submit
            />
        </div>
    }
}
