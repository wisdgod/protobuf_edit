use crate::state::WorkspaceState;
use leptos::prelude::*;
use protobuf_edit::FieldId;

#[derive(Clone, PartialEq, Eq)]
struct Crumb {
    label: String,
    field_id: Option<FieldId>,
}

#[component]
pub(crate) fn Breadcrumb() -> impl IntoView {
    let workspace = expect_context::<WorkspaceState>();
    let patch_state = workspace.patch_state;
    let selected = workspace.selected;

    let crumbs = Memo::new(move |_| {
        let selected_field = selected.get();
        patch_state.with(|p| {
            let Some(patch) = p.as_ref() else {
                return vec![Crumb { label: "root".to_string(), field_id: None }];
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
            out.push(Crumb { label: "root".to_string(), field_id: None });
            for fid in chain_fields {
                let label = match patch.field_tag(fid) {
                    Ok(tag) => format!("field {}", tag.field_number().as_inner()),
                    Err(_) => "field ?".to_string(),
                };
                out.push(Crumb { label, field_id: Some(fid) });
            }
            out
        })
    });

    view! {
        <div class="breadcrumb">
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
                                {label}
                            </span>
                            <Show when=move || !is_last fallback=|| ()>
                                <span class="breadcrumb-sep">"›"</span>
                            </Show>
                        }
                    })
                    .collect_view()
            }}
        </div>
    }
}
