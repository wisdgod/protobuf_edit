use crate::fx::{FxHashMap, FxHashSet};
use crate::messages::{MessageId, MessageMeta};
use crate::state::{MessageCatalogState, MessageSidebarActions, UiState};
use super::ThemeSwitcher;
use leptos::prelude::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ImportMode {
    Bytes,
    Envelope,
}

impl ImportMode {
    const fn as_value(self) -> &'static str {
        match self {
            Self::Bytes => "bytes",
            Self::Envelope => "envelope",
        }
    }

    fn from_value(value: &str) -> Option<Self> {
        match value {
            "bytes" => Some(Self::Bytes),
            "envelope" => Some(Self::Envelope),
            _ => None,
        }
    }
}

#[component]
pub(crate) fn MessageSidebar(actions: MessageSidebarActions) -> impl IntoView {
    let messages = expect_context::<MessageCatalogState>();
    let ui = expect_context::<UiState>();
    let messages_list = messages.messages_list;
    let current_message_id = messages.current_message_id;
    let message_name_text = messages.message_name_text;
    let import_name_text = messages.import_name_text;
    let raw_input = messages.raw_input;
    let frame_name_template_text = messages.frame_name_template_text;
    let theme_is_dark = ui.theme_is_dark;
    let MessageSidebarActions {
        on_select_message,
        on_message_name_change,
        on_rename_message,
        on_rename_class,
        on_new_message,
        on_delete_selected_messages,
        on_view_frames,
        on_import,
        on_import_envelope,
        on_upload_change,
        on_toggle_theme,
        on_store_frame_name_template,
    } = actions;
    let collapsed = RwSignal::new(false);
    let selected_for_delete: RwSignal<FxHashSet<MessageId>> = RwSignal::new(FxHashSet::default());
    let collapsed_classes: RwSignal<FxHashSet<MessageId>> = RwSignal::new(FxHashSet::default());
    let import_mode: RwSignal<ImportMode> = RwSignal::new(ImportMode::Bytes);
    let filter_text = RwSignal::new(String::new());
    let renaming_id: RwSignal<Option<MessageId>> = RwSignal::new(None);
    let rename_text = RwSignal::new(String::new());
    let row_ctx = MessageRowCtx {
        current_message_id,
        selected_for_delete,
        renaming_id,
        rename_text,
        on_select_message,
        on_rename_message,
        on_rename_class,
    };

    Effect::new(move |_| {
        let ids: FxHashSet<MessageId> =
            messages_list.with(|list| list.iter().map(|m| m.id).collect());
        selected_for_delete.update(|set| set.retain(|id| ids.contains(id)));
    });

    let has_current_message = move || current_message_id.get().is_some();

    let delete_selected_count = Memo::new(move |_| selected_for_delete.with(|s| s.len()));
    let delete_selected_enabled = Memo::new(move |_| selected_for_delete.with(|s| !s.is_empty()));

    let on_toggle_collapsed = UnsyncCallback::new(move |_| {
        collapsed.update(|v| {
            *v = !*v;
        });
    });

    let on_delete_selected = UnsyncCallback::new(move |_| {
        let ids: Vec<MessageId> = selected_for_delete.with(|s| s.iter().copied().collect());
        if ids.is_empty() {
            return;
        }
        on_delete_selected_messages.run(ids);
    });

    let on_select_all_visible = UnsyncCallback::new(move |_| {
        let filter = normalize_filter(&filter_text.get_untracked());
        let ids: Vec<MessageId> = messages_list.with(|list| {
            list.iter().filter(|m| matches_filter(m, &filter)).map(|m| m.id).collect()
        });
        if ids.is_empty() {
            return;
        }
        selected_for_delete.update(|set| set.extend(ids));
    });

    let on_clear_selection = UnsyncCallback::new(move |_| {
        selected_for_delete.set(FxHashSet::default());
    });

    let on_import_click = UnsyncCallback::new(move |_| match import_mode.get_untracked() {
        ImportMode::Bytes => on_import.run(()),
        ImportMode::Envelope => on_import_envelope.run(()),
    });

    let sidebar_class =
        move || if collapsed.get() { "sidebar sidebar--collapsed" } else { "sidebar" };

    view! {
        <div class=sidebar_class>
            <div class="sidebar-header">
                <button
                    class="btn btn--secondary sidebar-collapse-btn"
                    on:click=move |_| on_toggle_collapsed.run(())
                >
                    {move || if collapsed.get() { "»" } else { "«" }}
                </button>
                <div class="sidebar-title" class:hidden=move || collapsed.get()>
                    "Messages"
                </div>
            </div>

            <div class="sidebar-body" class:hidden=move || collapsed.get()>
                <div class="sidebar-actions">
                    <button class="btn btn--secondary" on:click=move |_| on_new_message.run(())>
                        "New"
                    </button>

                    <button
                        class="btn btn--danger"
                        on:click=move |_| on_delete_selected.run(())
                        disabled=move || !delete_selected_enabled.get()
                    >
                        {move || format!("Delete selected ({})", delete_selected_count.get())}
                    </button>

                    <button
                        class="btn btn--secondary"
                        on:click=move |_| on_view_frames.run(())
                        disabled=move || !has_current_message()
                    >
                        "Frames"
                    </button>
                </div>

                <div class="sidebar-list-controls">
                    <input
                        class="input sidebar-search"
                        placeholder="Search…"
                        prop:value=move || filter_text.get()
                        on:input=move |ev| filter_text.set(event_target_value(&ev))
                    />
                    <button
                        class="btn btn--secondary"
                        on:click=move |_| on_select_all_visible.run(())
                        disabled=move || messages_list.with(|list| list.is_empty())
                    >
                        "All"
                    </button>
                    <button
                        class="btn btn--secondary"
                        on:click=move |_| on_clear_selection.run(())
                        disabled=move || selected_for_delete.with(|s| s.is_empty())
                    >
                        "None"
                    </button>
                </div>

                <div class="sidebar-current">
                    <label class="sidebar-label">"Name"</label>
                    <div class="sidebar-current-row">
                        <input
                            class="input sidebar-input"
                            placeholder="Message name"
                            prop:value=move || message_name_text.get()
                            on:input=move |ev| message_name_text.set(event_target_value(&ev))
                            on:change=move |ev| on_message_name_change.run(ev)
                            disabled=move || !has_current_message()
                        />
                    </div>
                </div>

                <details class="sidebar-section">
                    <summary class="sidebar-summary">"Import"</summary>
                    <div class="sidebar-import">
                        <input
                            class="input sidebar-input"
                            placeholder="New message name (optional)"
                            prop:value=move || import_name_text.get()
                            on:input=move |ev| import_name_text.set(event_target_value(&ev))
                        />
                        <input
                            class="input sidebar-input"
                            placeholder="Frame name template ({source} {idx} {idx1} {len})"
                            prop:value=move || frame_name_template_text.get()
                            on:input=move |ev| frame_name_template_text.set(event_target_value(&ev))
                            on:change=move |_| on_store_frame_name_template.run(())
                        />
                        <div class="sidebar-import-row">
                            <select
                                class="select sidebar-select"
                                prop:value=move || import_mode.get().as_value()
                                on:change=move |ev| {
                                    let v = event_target_value(&ev);
                                    if let Some(mode) = ImportMode::from_value(v.trim()) {
                                        import_mode.set(mode);
                                    }
                                }
                            >
                                <option value={ImportMode::Bytes.as_value()}>"Bytes"</option>
                                <option value={ImportMode::Envelope.as_value()}>"Envelope"</option>
                            </select>
                            <button
                                class="btn btn--primary"
                                on:click=move |_| on_import_click.run(())
                                disabled=move || raw_input.with(|s| s.trim().is_empty())
                            >
                                "Import"
                            </button>
                            <label class="btn btn--secondary">
                                "Upload"
                                <input
                                    class="file-input"
                                    type="file"
                                    on:change=move |ev| on_upload_change.run(ev)
                                />
                            </label>
                        </div>

                        <textarea
                            class="input sidebar-textarea"
                            placeholder="Paste hex/base64…"
                            prop:value=move || raw_input.get()
                            on:input=move |ev| raw_input.set(event_target_value(&ev))
                        />
                    </div>
                </details>

                <div class="message-list">
                    {move || {
                        let filter = normalize_filter(&filter_text.get());
                        messages_list.with(|list| {
                            if list.is_empty() {
                                return vec![view! { <div class="message-empty">"No messages."</div> }
                                    .into_any()];
                            }

                            let GroupedMessages {
                                groups,
                                group_order,
                                meta_by_id,
                            } = build_groups(list, &filter);

                            let mut out: Vec<AnyView> = Vec::new();
                            for class_id in group_order {
                                let Some(members) = groups.get(&class_id) else {
                                    continue;
                                };

                                if members.len() <= 1 {
                                    let Some(m) = members.first() else {
                                        continue;
                                    };
                                    out.push(message_row_view(
                                        m,
                                        0,
                                        &row_ctx,
                                    ));
                                    continue;
                                }

                                out.push(class_row_view(
                                    class_id,
                                    members,
                                    &meta_by_id,
                                    collapsed_classes,
                                    &row_ctx,
                                ));

                                if !collapsed_classes.with(|s| s.contains(&class_id)) {
                                    let mut sorted: Vec<&MessageMeta> = members.to_vec();
                                    sort_members(&mut sorted, class_id);

                                    for m in sorted {
                                        if m.id == class_id {
                                            continue;
                                        }
                                        out.push(message_row_view(m, 1, &row_ctx));
                                    }
                                }
                            }

                            out
                        })
                    }}
                </div>
            </div>
            <div class="sidebar-footer">
                <ThemeSwitcher is_night=theme_is_dark on_toggle=on_toggle_theme />
            </div>
        </div>
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SelectState {
    None,
    Some,
    All,
}

#[derive(Clone)]
struct MessageRowCtx {
    current_message_id: RwSignal<Option<MessageId>>,
    selected_for_delete: RwSignal<FxHashSet<MessageId>>,
    renaming_id: RwSignal<Option<MessageId>>,
    rename_text: RwSignal<String>,
    on_select_message: UnsyncCallback<MessageId>,
    on_rename_message: UnsyncCallback<(MessageId, String)>,
    on_rename_class: UnsyncCallback<(MessageId, String)>,
}

fn normalize_filter(raw: &str) -> String {
    raw.trim().to_lowercase()
}

fn matches_filter(meta: &MessageMeta, filter: &str) -> bool {
    if filter.is_empty() {
        return true;
    }
    meta.name.as_ref().to_lowercase().contains(filter)
        || meta.class_name.as_ref().to_lowercase().contains(filter)
}

struct GroupedMessages<'a> {
    groups: FxHashMap<MessageId, Vec<&'a MessageMeta>>,
    group_order: Vec<MessageId>,
    meta_by_id: FxHashMap<MessageId, &'a MessageMeta>,
}

fn build_groups<'a>(list: &'a [MessageMeta], filter: &str) -> GroupedMessages<'a> {
    let mut groups: FxHashMap<MessageId, Vec<&'a MessageMeta>> = FxHashMap::default();
    let mut group_order: Vec<MessageId> = Vec::new();
    let mut meta_by_id: FxHashMap<MessageId, &'a MessageMeta> = FxHashMap::default();

    for meta in list {
        meta_by_id.insert(meta.id, meta);
        if !matches_filter(meta, filter) {
            continue;
        }

        let class_id = meta.class_id;
        let entry = groups.entry(class_id).or_insert_with(|| {
            group_order.push(class_id);
            Vec::new()
        });
        entry.push(meta);
    }

    GroupedMessages { groups, group_order, meta_by_id }
}

fn sort_members(members: &mut Vec<&MessageMeta>, class_id: MessageId) {
    members.sort_by(|a, b| {
        let a_is_root = a.id == class_id;
        let b_is_root = b.id == class_id;
        b_is_root
            .cmp(&a_is_root)
            .then_with(|| b.modified_ms.cmp(&a.modified_ms))
            .then_with(|| b.id.cmp(&a.id))
    });
}

fn class_select_state(
    members: &[&MessageMeta],
    selected_for_delete: RwSignal<FxHashSet<MessageId>>,
) -> SelectState {
    let selected =
        selected_for_delete.with(|set| members.iter().filter(|m| set.contains(&m.id)).count());

    if selected == 0 {
        return SelectState::None;
    }
    if selected == members.len() {
        return SelectState::All;
    }
    SelectState::Some
}

fn commit_rename(
    target_id: Option<MessageId>,
    rename_text: RwSignal<String>,
    on_rename: UnsyncCallback<(MessageId, String)>,
) {
    let Some(id) = target_id else {
        return;
    };
    rename_text.with_untracked(|raw| {
        let name = raw.trim();
        if name.is_empty() {
            return;
        }
        on_rename.run((id, name.to_string()));
    });
}

fn handle_rename_keydown(
    target_id: Option<MessageId>,
    rename_text: RwSignal<String>,
    renaming_id: RwSignal<Option<MessageId>>,
    on_rename: UnsyncCallback<(MessageId, String)>,
) -> impl FnMut(leptos::ev::KeyboardEvent) + 'static {
    move |ev: leptos::ev::KeyboardEvent| {
        let key = ev.key();
        if key == "Escape" {
            ev.prevent_default();
            renaming_id.set(None);
            return;
        }
        if key != "Enter" {
            return;
        }

        ev.prevent_default();
        commit_rename(target_id, rename_text, on_rename);
        renaming_id.set(None);
    }
}

fn handle_rename_blur(
    target_id: Option<MessageId>,
    rename_text: RwSignal<String>,
    renaming_id: RwSignal<Option<MessageId>>,
    on_rename: UnsyncCallback<(MessageId, String)>,
) -> impl FnMut(leptos::ev::FocusEvent) + 'static {
    move |_| {
        if renaming_id.get_untracked() != target_id {
            return;
        }
        commit_rename(target_id, rename_text, on_rename);
        renaming_id.set(None);
    }
}

fn class_row_view(
    class_id: MessageId,
    members: &[&MessageMeta],
    meta_by_id: &FxHashMap<MessageId, &MessageMeta>,
    collapsed_classes: RwSignal<FxHashSet<MessageId>>,
    ctx: &MessageRowCtx,
) -> AnyView {
    let MessageRowCtx {
        selected_for_delete,
        renaming_id,
        rename_text,
        on_select_message,
        on_rename_class,
        ..
    } = ctx.clone();

    let root_id: Option<MessageId> = meta_by_id.get(&class_id).map(|meta| meta.id);
    let title = meta_by_id
        .get(&class_id)
        .map(|meta| meta.class_name.clone())
        .or_else(|| members.first().map(|m| m.class_name.clone()))
        .unwrap_or_else(|| std::sync::Arc::<str>::from(format!("Class {class_id}")));
    let label = format!("{title} ({})", members.len());
    let expanded = !collapsed_classes.with(|s| s.contains(&class_id));
    let caret = if expanded { "▾" } else { "▸" };

    let class_selected_state = class_select_state(members, selected_for_delete);
    let class_checked = class_selected_state == SelectState::All;
    let class_indeterminate = class_selected_state == SelectState::Some;
    let class_members: Vec<MessageId> = members.iter().map(|m| m.id).collect();

    let class_is_renaming = move || renaming_id.get().is_some_and(|id| id == class_id);

    let default_select_id: Option<MessageId> =
        root_id.or_else(|| members.iter().max_by_key(|m| m.modified_ms).map(|m| m.id));

    let on_toggle_collapse = move |_| {
        collapsed_classes.update(|s| {
            if s.contains(&class_id) {
                s.remove(&class_id);
            } else {
                s.insert(class_id);
            }
        });
    };

    let on_checkbox_change = move |ev| {
        let input: web_sys::HtmlInputElement = event_target(&ev);
        let checked = input.checked();
        selected_for_delete.update(|set| {
            if checked {
                set.extend(class_members.iter().copied());
            } else {
                for id in &class_members {
                    set.remove(id);
                }
            }
        });
    };

    view! {
        <div class="message-class-row">
            <button class="btn btn--secondary message-caret" on:click=on_toggle_collapse>
                {caret}
            </button>
            <input
                class="message-checkbox"
                type="checkbox"
                prop:checked=class_checked
                prop:indeterminate=class_indeterminate
                on:click=move |ev| ev.stop_propagation()
                on:change=on_checkbox_change
            />
            <div
                class="message-class-title"
                on:click=move |_| {
                    if let Some(id) = default_select_id {
                        on_select_message.run(id);
                    }
                }
            >
                <Show when=class_is_renaming fallback=move || view! { {label.clone()} }>
                    <input
                        class="input message-rename-input"
                        prop:value=move || rename_text.get()
                        on:input=move |ev| rename_text.set(event_target_value(&ev))
                        on:click=move |ev| ev.stop_propagation()
                        on:keydown=handle_rename_keydown(
                            Some(class_id),
                            rename_text,
                            renaming_id,
                            on_rename_class,
                        )
                        on:blur=handle_rename_blur(
                            Some(class_id),
                            rename_text,
                            renaming_id,
                            on_rename_class,
                        )
                        autofocus=true
                    />
                </Show>
            </div>
            <button
                class="btn btn--secondary message-rename-btn"
                title="Rename"
                on:click=move |ev: leptos::ev::MouseEvent| {
                    ev.stop_propagation();
                    renaming_id.set(Some(class_id));
                    rename_text.update(|s| {
                        s.clear();
                        s.push_str(title.as_ref());
                    });
                }
            >
                "✎"
            </button>
        </div>
    }
    .into_any()
}

fn message_row_view(meta: &MessageMeta, indent: usize, ctx: &MessageRowCtx) -> AnyView {
    let MessageRowCtx {
        current_message_id,
        selected_for_delete,
        renaming_id,
        rename_text,
        on_select_message,
        on_rename_message,
        ..
    } = ctx.clone();
    let id = meta.id;
    let name = meta.name.clone();
    let name_for_display = name.clone();
    let name_for_rename = name.clone();
    let bytes_len = meta.bytes_len;
    let indent_px = (indent as i32) * 14;

    let row_class = move || {
        let current = current_message_id.get().is_some_and(|cur| cur == id);
        if current { "message-row message-row--current" } else { "message-row" }
    };

    view! {
        <div class=row_class on:click=move |_| on_select_message.run(id)>
            <div class="message-indent" style=move || format!("width: {indent_px}px")></div>
            <input
                class="message-checkbox"
                type="checkbox"
                prop:checked=move || selected_for_delete.with(|s| s.contains(&id))
                on:click=move |ev| ev.stop_propagation()
                on:change=move |ev| {
                    let input: web_sys::HtmlInputElement = event_target(&ev);
                    let checked = input.checked();
                    selected_for_delete.update(|set| {
                        if checked {
                            set.insert(id);
                        } else {
                            set.remove(&id);
                        }
                    });
                }
            />
            <div class="message-name">
                <Show
                    when=move || renaming_id.get().is_some_and(|rid| rid == id)
                    fallback=move || view! { {Oco::from(name_for_display.clone())} }
                >
                    <input
                        class="input message-rename-input"
                        prop:value=move || rename_text.get()
                        on:input=move |ev| rename_text.set(event_target_value(&ev))
                        on:click=move |ev| ev.stop_propagation()
                        on:keydown=handle_rename_keydown(
                            Some(id),
                            rename_text,
                            renaming_id,
                            on_rename_message,
                        )
                        on:blur=handle_rename_blur(
                            Some(id),
                            rename_text,
                            renaming_id,
                            on_rename_message,
                        )
                        autofocus=true
                    />
                </Show>
            </div>
            <div class="message-bytes">{format!("{bytes_len}B")}</div>
            <button
                class="btn btn--secondary message-rename-btn"
                title="Rename"
                on:click=move |ev| {
                    ev.stop_propagation();
                    renaming_id.set(Some(id));
                    rename_text.update(|s| {
                        s.clear();
                        s.push_str(name_for_rename.as_ref());
                    });
                }
            >
                "✎"
            </button>
        </div>
    }
    .into_any()
}
