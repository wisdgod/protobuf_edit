use crate::messages::{self, MessageId, MessageMeta};
use crate::services::{EnvelopeService, MessageService};
use crate::state::{MessageCatalogState, UiState};
use crate::toast::ToastKind;
use leptos::prelude::*;
use rustc_hash::{FxHashMap, FxHashSet};
use std::sync::Arc;

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

/// Start tab: centered import card plus the message library.
#[component]
pub(crate) fn StartPage(on_open: UnsyncCallback<MessageId>) -> impl IntoView {
    let msg_svc = expect_context::<MessageService>();
    let env_svc = expect_context::<EnvelopeService>();
    let messages_state = expect_context::<MessageCatalogState>();
    let ui = expect_context::<UiState>();
    let messages_list = messages_state.messages_list;
    let current_message_id = messages_state.current_message_id;
    let import_name_text = messages_state.import_name_text;
    let raw_input = messages_state.raw_input;
    let frame_name_template_text = messages_state.frame_name_template_text;
    let toast = ui.toast;

    let selected_for_delete: RwSignal<FxHashSet<MessageId>> = RwSignal::new(FxHashSet::default());
    let collapsed_classes: RwSignal<FxHashSet<MessageId>> = RwSignal::new(FxHashSet::default());
    let import_mode: RwSignal<ImportMode> = RwSignal::new(ImportMode::Bytes);
    let filter_text = RwSignal::new(String::new());
    let renaming_id: RwSignal<Option<MessageId>> = RwSignal::new(None);
    let rename_text = RwSignal::new(String::new());
    let drag_over = RwSignal::new(false);
    let row_ctx = MessageRowCtx {
        current_message_id,
        selected_for_delete,
        renaming_id,
        rename_text,
        msg_svc: msg_svc.clone(),
        on_open,
    };

    Effect::new(move |_| {
        let ids: FxHashSet<MessageId> =
            messages_list.with(|list| list.iter().map(|m| m.id).collect());
        selected_for_delete.update(|set| set.retain(|id| ids.contains(id)));
    });

    // Structural row list; selection checkboxes are reactive inside the rows,
    // so toggling them does not rebuild the list.
    let row_specs: Memo<Vec<RowSpec>> = Memo::new(move |_| {
        messages_list.with(|list| {
            filter_text.with(|raw| {
                let filter = raw.trim();
                let GroupedMessages { groups, group_order, meta_by_id } =
                    build_groups(list, filter);

                let mut out: Vec<RowSpec> = Vec::new();
                for class_id in group_order {
                    let Some(members) = groups.get(&class_id) else {
                        continue;
                    };

                    if members.len() <= 1 {
                        if let Some(m) = members.first() {
                            out.push(RowSpec::Message { meta: (*m).clone(), indent: 0 });
                        }
                        continue;
                    }

                    let root_id = meta_by_id.get(&class_id).map(|meta| meta.id);
                    let title = meta_by_id
                        .get(&class_id)
                        .map(|meta| meta.class_name.clone())
                        .or_else(|| members.first().map(|m| m.class_name.clone()))
                        .unwrap_or_else(|| Arc::<str>::from(format!("Class {class_id}")));
                    let label = Arc::<str>::from(format!("{title} ({})", members.len()));
                    let default_select_id = root_id
                        .or_else(|| members.iter().max_by_key(|m| m.modified_ms).map(|m| m.id));
                    let member_ids: Arc<[MessageId]> = members.iter().map(|m| m.id).collect();

                    out.push(RowSpec::Class {
                        class_id,
                        label,
                        title,
                        member_ids,
                        default_select_id,
                    });

                    if !collapsed_classes.with(|s| s.contains(&class_id)) {
                        let mut sorted: Vec<&MessageMeta> = members.clone();
                        sort_members(&mut sorted, class_id);
                        for m in sorted {
                            if m.id == class_id {
                                continue;
                            }
                            out.push(RowSpec::Message { meta: m.clone(), indent: 1 });
                        }
                    }
                }
                out
            })
        })
    });

    let delete_selected_count =
        Memo::new(move |_| selected_for_delete.with(std::collections::HashSet::len));
    let delete_selected_enabled = Memo::new(move |_| selected_for_delete.with(|s| !s.is_empty()));

    let on_delete_selected = {
        let msg_svc = msg_svc.clone();
        UnsyncCallback::new(move |()| {
            let ids: Vec<MessageId> = selected_for_delete.with(|s| s.iter().copied().collect());
            if ids.is_empty() {
                return;
            }
            msg_svc.delete(ids);
        })
    };

    let on_select_all_visible = UnsyncCallback::new(move |()| {
        let ids: Vec<MessageId> = filter_text.with_untracked(|raw| {
            let filter = raw.trim();
            messages_list.with_untracked(|list| {
                list.iter().filter(|m| matches_filter(m, filter)).map(|m| m.id).collect()
            })
        });
        if ids.is_empty() {
            return;
        }
        selected_for_delete.update(|set| set.extend(ids));
    });

    let on_clear_selection = UnsyncCallback::new(move |()| {
        selected_for_delete.set(FxHashSet::default());
    });

    let on_import_click = {
        let msg_svc = msg_svc.clone();
        let env_svc = env_svc.clone();
        UnsyncCallback::new(move |()| match import_mode.get_untracked() {
            ImportMode::Bytes => msg_svc.on_import_click(),
            ImportMode::Envelope => env_svc.import_envelope(),
        })
    };

    let on_new_message = {
        let msg_svc = msg_svc.clone();
        move |_| msg_svc.create()
    };

    let on_upload = {
        let msg_svc = msg_svc.clone();
        move |ev: leptos::ev::Event| msg_svc.upload(&ev)
    };

    let on_drop = {
        let msg_svc = msg_svc.clone();
        move |ev: web_sys::DragEvent| {
            ev.prevent_default();
            drag_over.set(false);
            let Some(file) = ev.data_transfer().and_then(|dt| dt.files()).and_then(|f| f.get(0))
            else {
                return;
            };
            msg_svc.import_file(file);
        }
    };

    let on_store_template = move |_| {
        if let Err(msg) =
            messages::store_frame_name_template(&frame_name_template_text.get_untracked())
        {
            toast.show(ToastKind::Error, msg);
        }
    };

    let card_class = move || {
        if drag_over.get() { "start-card start-card--drag" } else { "start-card" }
    };

    view! {
        <div class="start-page">
            <div class="start-page-inner">
                <div
                    class=card_class
                    on:dragover=move |ev: web_sys::DragEvent| {
                        ev.prevent_default();
                        drag_over.set(true);
                    }
                    on:dragleave=move |_| drag_over.set(false)
                    on:drop=on_drop
                >
                    <div class="start-card-title">"Drop a file or paste data"</div>
                    <div class="start-card-hint">"Base64 · Hex · binary file"</div>

                    <textarea
                        class="input start-textarea"
                        placeholder="Paste hex/base64…"
                        prop:value=move || raw_input.get()
                        on:input=move |ev| raw_input.set(event_target_value(&ev))
                    />

                    <div class="start-card-row">
                        <input
                            class="input start-name-input"
                            placeholder="New message name (optional)"
                            prop:value=move || import_name_text.get()
                            on:input=move |ev| import_name_text.set(event_target_value(&ev))
                        />
                        <select
                            class="select"
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
                            <input class="file-input" type="file" on:change=on_upload />
                        </label>
                    </div>

                    <details class="start-options">
                        <summary class="start-options-summary">"Options"</summary>
                        <input
                            class="input start-name-input"
                            placeholder="Frame name template ({source} {idx} {idx1} {len})"
                            prop:value=move || frame_name_template_text.get()
                            on:input=move |ev| {
                                frame_name_template_text.set(event_target_value(&ev))
                            }
                            on:change=on_store_template
                        />
                    </details>
                </div>

                <div class="start-library">
                    <div class="start-library-toolbar">
                        <input
                            class="input start-search"
                            placeholder="Search…"
                            prop:value=move || filter_text.get()
                            on:input=move |ev| filter_text.set(event_target_value(&ev))
                        />
                        <button class="btn btn--secondary btn--small" on:click=on_new_message>
                            "New"
                        </button>
                        <button
                            class="btn btn--secondary btn--small"
                            on:click=move |_| on_select_all_visible.run(())
                            disabled=move || messages_list.with(std::vec::Vec::is_empty)
                        >
                            "All"
                        </button>
                        <button
                            class="btn btn--secondary btn--small"
                            on:click=move |_| on_clear_selection.run(())
                            disabled=move || {
                                selected_for_delete.with(std::collections::HashSet::is_empty)
                            }
                        >
                            "None"
                        </button>
                        <button
                            class="btn btn--danger btn--small"
                            on:click=move |_| on_delete_selected.run(())
                            disabled=move || !delete_selected_enabled.get()
                        >
                            {move || format!("Delete ({})", delete_selected_count.get())}
                        </button>
                    </div>

                    <div class="message-list">
                        <Show
                            when=move || messages_list.with(|list| !list.is_empty())
                            fallback=|| view! { <div class="message-empty">"No messages yet."</div> }
                        >
                            <For
                                each=move || row_specs.get()
                                key=RowSpec::key
                                children={
                                    let row_ctx = row_ctx.clone();
                                    move |spec| match spec {
                                        RowSpec::Class {
                                            class_id,
                                            label,
                                            title,
                                            member_ids,
                                            default_select_id,
                                        } => class_row_view(
                                            class_id,
                                            label,
                                            title,
                                            member_ids,
                                            default_select_id,
                                            collapsed_classes,
                                            &row_ctx,
                                        ),
                                        RowSpec::Message { meta, indent } => {
                                            message_row_view(&meta, indent, &row_ctx)
                                        }
                                    }
                                }
                            />
                        </Show>
                    </div>
                </div>
            </div>
        </div>
    }
}

/// One rendered list row; keyed so `<For>` preserves untouched row DOM.
#[derive(Clone, PartialEq, Eq)]
enum RowSpec {
    Class {
        class_id: MessageId,
        label: Arc<str>,
        title: Arc<str>,
        member_ids: Arc<[MessageId]>,
        default_select_id: Option<MessageId>,
    },
    Message {
        meta: MessageMeta,
        indent: usize,
    },
}

impl RowSpec {
    fn key(&self) -> (bool, MessageId) {
        match self {
            Self::Class { class_id, .. } => (true, *class_id),
            Self::Message { meta, .. } => (false, meta.id),
        }
    }
}

#[derive(Clone)]
struct MessageRowCtx {
    current_message_id: RwSignal<Option<MessageId>>,
    selected_for_delete: RwSignal<FxHashSet<MessageId>>,
    renaming_id: RwSignal<Option<MessageId>>,
    rename_text: RwSignal<String>,
    msg_svc: MessageService,
    on_open: UnsyncCallback<MessageId>,
}

/// ASCII-case-insensitive substring search without allocating.
fn contains_ignore_ascii_case(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.len() > haystack.len() {
        return false;
    }
    haystack.as_bytes().windows(needle.len()).any(|w| w.eq_ignore_ascii_case(needle.as_bytes()))
}

fn matches_filter(meta: &MessageMeta, filter: &str) -> bool {
    filter.is_empty()
        || contains_ignore_ascii_case(meta.name.as_ref(), filter)
        || contains_ignore_ascii_case(meta.class_name.as_ref(), filter)
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

fn commit_rename(
    target_id: Option<MessageId>,
    rename_text: RwSignal<String>,
    msg_svc: &MessageService,
    is_class: bool,
) {
    let Some(id) = target_id else {
        return;
    };
    rename_text.with_untracked(|raw| {
        let name = raw.trim();
        if name.is_empty() {
            return;
        }
        let arc_name = Arc::<str>::from(name);
        if is_class {
            msg_svc.rename_class(id, arc_name);
        } else {
            msg_svc.rename(id, arc_name);
        }
    });
}

fn handle_rename_keydown(
    target_id: Option<MessageId>,
    rename_text: RwSignal<String>,
    renaming_id: RwSignal<Option<MessageId>>,
    msg_svc: MessageService,
    is_class: bool,
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
        commit_rename(target_id, rename_text, &msg_svc, is_class);
        renaming_id.set(None);
    }
}

fn handle_rename_blur(
    target_id: Option<MessageId>,
    rename_text: RwSignal<String>,
    renaming_id: RwSignal<Option<MessageId>>,
    msg_svc: MessageService,
    is_class: bool,
) -> impl FnMut(leptos::ev::FocusEvent) + 'static {
    move |_| {
        if renaming_id.get_untracked() != target_id {
            return;
        }
        commit_rename(target_id, rename_text, &msg_svc, is_class);
        renaming_id.set(None);
    }
}

fn class_row_view(
    class_id: MessageId,
    label: Arc<str>,
    title: Arc<str>,
    member_ids: Arc<[MessageId]>,
    default_select_id: Option<MessageId>,
    collapsed_classes: RwSignal<FxHashSet<MessageId>>,
    ctx: &MessageRowCtx,
) -> AnyView {
    let MessageRowCtx { selected_for_delete, renaming_id, rename_text, msg_svc, on_open, .. } =
        ctx.clone();

    // Caret and checkbox state are reactive, so collapsing a class or
    // toggling a selection never rebuilds the row list.
    let caret =
        move || if collapsed_classes.with(|s| s.contains(&class_id)) { "▸" } else { "▾" };

    let selected_count = {
        let member_ids = member_ids.clone();
        move || {
            selected_for_delete.with(|set| member_ids.iter().filter(|id| set.contains(id)).count())
        }
    };
    let class_checked = {
        let selected_count = selected_count.clone();
        let total = member_ids.len();
        move || total > 0 && selected_count() == total
    };
    let class_indeterminate = {
        let total = member_ids.len();
        move || {
            let n = selected_count();
            n > 0 && n < total
        }
    };

    let class_is_renaming = move || renaming_id.get().is_some_and(|id| id == class_id);

    let on_toggle_collapse = move |_| {
        collapsed_classes.update(|s| {
            if s.contains(&class_id) {
                s.remove(&class_id);
            } else {
                s.insert(class_id);
            }
        });
    };

    let on_checkbox_change = {
        let member_ids = member_ids.clone();
        move |ev| {
            let input: web_sys::HtmlInputElement = event_target(&ev);
            let checked = input.checked();
            selected_for_delete.update(|set| {
                if checked {
                    set.extend(member_ids.iter().copied());
                } else {
                    for id in member_ids.iter() {
                        set.remove(id);
                    }
                }
            });
        }
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
                        on_open.run(id);
                    }
                }
            >
                <Show when=class_is_renaming fallback=move || view! { {Oco::from(label.clone())} }>
                    <input
                        class="input message-rename-input"
                        prop:value=move || rename_text.get()
                        on:input=move |ev| rename_text.set(event_target_value(&ev))
                        on:click=move |ev| ev.stop_propagation()
                        on:keydown=handle_rename_keydown(
                            Some(class_id),
                            rename_text,
                            renaming_id,
                            msg_svc.clone(),
                            true,
                        )
                        on:blur=handle_rename_blur(
                            Some(class_id),
                            rename_text,
                            renaming_id,
                            msg_svc.clone(),
                            true,
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
        msg_svc,
        on_open,
    } = ctx.clone();
    let id = meta.id;
    let name = meta.name.clone();
    let name_for_display = name.clone();
    let name_for_rename = name;
    let bytes_len = meta.bytes_len;
    let indent_px = (indent as i32) * 14;

    let row_class = move || {
        let current = current_message_id.get().is_some_and(|cur| cur == id);
        if current { "message-row message-row--current" } else { "message-row" }
    };

    view! {
        <div class=row_class on:click=move |_| on_open.run(id)>
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
                            msg_svc.clone(),
                            false,
                        )
                        on:blur=handle_rename_blur(
                            Some(id),
                            rename_text,
                            renaming_id,
                            msg_svc.clone(),
                            false,
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
