use crate::decode::{decode_base64_url, decode_user_input, encode_base64, encode_base64_url};
use crate::envelope::{parse_envelope_frames, EnvelopeFrameMeta, EnvelopeView};
use crate::fx::FxHashSet;
use crate::bytes::ByteView;
use crate::hex_view::{compute_highlights, HexGrid, HexTextMode};
use crate::components::{
    Breadcrumb, EnvelopeFramesPanel, FieldTree, InspectorDrawer, MessageSidebar, StatusBar,
};
use crate::messages::{self, LoadedBytesMode, MessageId, MessageMeta};
use crate::page_cache;
use crate::toast::{show_toast, Toast, ToastContainer, ToastKind};
use crate::web::{
    build_share_url, clipboard_write_text, download_bytes, get_document_theme, get_url_hash,
    set_document_theme, start_theme_transition,
};
use leptos::html;
use leptos::prelude::*;
use leptos_use::use_event_listener;
use protobuf_edit::{FieldId, Patch, TreeError};
use core::future::Future;
use core::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use wasm_bindgen::closure::Closure;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::spawn_local;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Theme {
    Light,
    Dark,
}

impl Theme {
    const fn toggle(self) -> Self {
        match self {
            Self::Light => Self::Dark,
            Self::Dark => Self::Light,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Light => "light",
            Self::Dark => "dark",
        }
    }
}

fn parse_theme(raw: &str) -> Option<Theme> {
    match raw.trim() {
        "light" => Some(Theme::Light),
        "dark" => Some(Theme::Dark),
        _ => None,
    }
}

fn format_frame_name_template(
    template: &str,
    source: &str,
    idx: usize,
    payload_len: usize,
) -> String {
    use core::fmt::Write as _;

    let template = template.trim();
    let template =
        if template.is_empty() { messages::DEFAULT_FRAME_NAME_TEMPLATE } else { template };

    let mut out = String::with_capacity(template.len().saturating_add(source.len()));
    let mut last: usize = 0;
    while let Some(open_rel) = template[last..].find('{') {
        let open = last.saturating_add(open_rel);
        let Some(close_rel) = template[open.saturating_add(1)..].find('}') else {
            break;
        };
        let close = open.saturating_add(1).saturating_add(close_rel);

        out.push_str(&template[last..open]);
        match &template[open.saturating_add(1)..close] {
            "source" => out.push_str(source),
            "idx" => {
                let _ = write!(out, "{idx}");
            }
            "idx1" => {
                let _ = write!(out, "{}", idx.saturating_add(1));
            }
            "len" => {
                let _ = write!(out, "{payload_len}");
            }
            other => {
                out.push('{');
                out.push_str(other);
                out.push('}');
            }
        }
        last = close.saturating_add(1);
    }
    out.push_str(&template[last..]);
    out
}

fn collect_visible_fields(
    patch: &Patch,
    msg: protobuf_edit::MessageId,
    expanded: &FxHashSet<FieldId>,
    out: &mut Vec<FieldId>,
) {
    let Ok(fields) = patch.message_fields(msg) else {
        return;
    };
    for &field in fields {
        if matches!(patch.field_is_deleted(field), Ok(true)) {
            continue;
        }
        out.push(field);
        if !expanded.contains(&field) {
            continue;
        }
        let Ok(Some(child)) = patch.field_child_message(field) else {
            continue;
        };
        collect_visible_fields(patch, child, expanded, out);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SelectionStep {
    tag: protobuf_edit::Tag,
    occurrence: u32,
}

fn encode_selection_path(path: &[SelectionStep]) -> String {
    use core::fmt::Write as _;

    let mut out = String::new();
    for (i, step) in path.iter().enumerate() {
        if i != 0 {
            out.push('/');
        }
        let (field_number, wire_type) = step.tag.split();
        let _ =
            write!(&mut out, "{}:{}:{}", field_number.as_inner(), wire_type as u8, step.occurrence);
    }
    out
}

fn decode_selection_path(input: &str) -> Option<Vec<SelectionStep>> {
    let input = input.trim();
    if input.is_empty() {
        return None;
    }

    let mut out = Vec::new();
    for part in input.split('/') {
        let mut it = part.trim().split(':');
        let field_number = it.next()?.parse::<u32>().ok()?;
        let wire_type = it.next()?.parse::<u32>().ok()?;
        let occurrence = it.next()?.parse::<u32>().ok()?;
        if it.next().is_some() {
            return None;
        }

        let field_number = protobuf_edit::FieldNumber::new(field_number)?;
        let wire_type = protobuf_edit::WireType::from_low3(wire_type)?;
        let tag = protobuf_edit::Tag::from_parts(field_number, wire_type);
        out.push(SelectionStep { tag, occurrence });
    }

    Some(out)
}

fn build_selection_path(patch: &Patch, selected: FieldId) -> Option<Vec<SelectionStep>> {
    let mut chain_fields: Vec<FieldId> = Vec::new();
    chain_fields.push(selected);
    let mut msg = patch.field_parent_message(selected).ok();
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
    chain_fields.reverse();

    let mut out = Vec::with_capacity(chain_fields.len());
    for fid in chain_fields {
        let tag = patch.field_tag(fid).ok()?;
        let parent = patch.field_parent_message(fid).ok()?;
        let fields = patch.message_fields(parent).ok()?;

        let mut occurrence: u32 = 0;
        let mut found = false;
        for &f in fields {
            if matches!(patch.field_is_deleted(f), Ok(true)) {
                continue;
            }
            let t = patch.field_tag(f).ok()?;
            if t != tag {
                continue;
            }
            if f == fid {
                found = true;
                break;
            }
            occurrence = occurrence.saturating_add(1);
        }
        if !found {
            return None;
        }

        out.push(SelectionStep { tag, occurrence });
    }
    Some(out)
}

fn find_field_by_tag_occurrence(
    patch: &Patch,
    msg: protobuf_edit::MessageId,
    tag: protobuf_edit::Tag,
    occurrence: u32,
) -> Result<Option<FieldId>, TreeError> {
    let fields = patch.message_fields(msg)?;
    let mut seen: u32 = 0;
    for &field in fields {
        if patch.field_is_deleted(field)? {
            continue;
        }
        if patch.field_tag(field)? != tag {
            continue;
        }
        if seen == occurrence {
            return Ok(Some(field));
        }
        seen = seen.saturating_add(1);
    }
    Ok(None)
}

fn resolve_selection_path(
    patch: &mut Patch,
    path: &[SelectionStep],
    expand_last_len: bool,
) -> Result<Option<(FieldId, FxHashSet<FieldId>)>, TreeError> {
    let mut msg = patch.root();
    let mut expanded: FxHashSet<FieldId> = FxHashSet::default();
    let mut current: Option<FieldId> = None;

    for (i, step) in path.iter().enumerate() {
        let Some(field) = find_field_by_tag_occurrence(patch, msg, step.tag, step.occurrence)?
        else {
            return Ok(None);
        };
        current = Some(field);

        let is_last = i + 1 == path.len();
        if is_last {
            if expand_last_len
                && step.tag.wire_type() == protobuf_edit::WireType::Len
                && patch.parse_child_message(field).is_ok()
            {
                expanded.insert(field);
            }
            break;
        }

        if step.tag.wire_type() != protobuf_edit::WireType::Len {
            break;
        }

        match patch.parse_child_message(field) {
            Ok(child) => {
                expanded.insert(field);
                msg = child;
            }
            Err(_) => break,
        }
    }

    Ok(current.map(|fid| (fid, expanded)))
}

#[component]
pub fn App() -> impl IntoView {
    let raw_input = RwSignal::new(String::new());
    let import_name_text = RwSignal::new(String::new());
    let patch_state = RwSignal::new_local(None::<Patch>);
    let patch_bytes = RwSignal::new_local(None::<ByteView>);
    let raw_bytes = RwSignal::new_local(None::<ByteView>);
    let envelope_view: RwSignal<Option<EnvelopeView>, LocalStorage> = RwSignal::new_local(None);
    let envelope_selected: RwSignal<usize> = RwSignal::new(0);

    let selected: RwSignal<Option<FieldId>> = RwSignal::new(None);
    let hovered: RwSignal<Option<FieldId>> = RwSignal::new(None);
    let expanded: RwSignal<FxHashSet<FieldId>> = RwSignal::new(FxHashSet::default());
    let dirty_fields: RwSignal<FxHashSet<FieldId>> = RwSignal::new(FxHashSet::default());
    let messages_list: RwSignal<Vec<MessageMeta>> = RwSignal::new(Vec::new());
    let current_message_id: RwSignal<Option<MessageId>> = RwSignal::new(None);
    let message_name_text = RwSignal::new(String::new());
    let frame_name_template_text = RwSignal::new(messages::DEFAULT_FRAME_NAME_TEMPLATE.to_string());
    let did_bootstrap: RwSignal<bool> = RwSignal::new(false);
    let load_nonce: RwSignal<u64> = RwSignal::new(0);

    let initial_theme = get_document_theme()
        .ok()
        .flatten()
        .as_deref()
        .and_then(parse_theme)
        .unwrap_or(Theme::Light);
    let theme: RwSignal<Theme> = RwSignal::new(initial_theme);

    let toasts: RwSignal<Vec<Toast>> = RwSignal::new(Vec::new());
    let next_toast_id: RwSignal<u64> = RwSignal::new(1);

    let split_ref = NodeRef::<html::Div>::new();
    let hex_container_ref = NodeRef::<html::Div>::new();
    let tree_container_ref = NodeRef::<html::Div>::new();
    let split_pct: RwSignal<f64> = RwSignal::new(50.0);
    let split_dragging: RwSignal<bool> = RwSignal::new(false);
    let hex_text_mode: RwSignal<HexTextMode> = RwSignal::new(HexTextMode::Ascii);

    Effect::new(move |_| {
        let _ = set_document_theme(theme.get().as_str());
    });

    let highlights = Memo::new(move |_| {
        patch_state.with(|p| {
            let Some(patch) = p.as_ref() else {
                return Vec::new();
            };
            compute_highlights(patch, selected.get(), hovered.get())
        })
    });

    let highlight_range_count = Memo::new(move |_| highlights.get().len());

    let read_only = Memo::new(move |_| envelope_view.with(|s| s.is_some()));

    let reset_ui_state = move || {
        selected.set(None);
        hovered.set(None);
        expanded.set(FxHashSet::default());
        dirty_fields.set(FxHashSet::default());
    };

    let reset_ui_state_keep_selected =
        move |new_selected: Option<FieldId>, new_expanded: FxHashSet<FieldId>| {
            selected.set(new_selected);
            hovered.set(None);
            expanded.set(new_expanded);
            dirty_fields.set(FxHashSet::default());
        };

    let confirm_discard_edits = move |action: &str| -> bool {
        let pending = dirty_fields.with_untracked(|s| s.len());
        if pending == 0 {
            return true;
        }
        let Some(window) = web_sys::window() else {
            return false;
        };
        window
            .confirm_with_message(&format!(
                "You have {pending} pending edit(s). Discard and {action}?"
            ))
            .unwrap_or(false)
    };

    type LoadPatchFn = dyn Fn(&str, ByteView, Vec<String>);

    let load_patch_from_view: Rc<LoadPatchFn> = Rc::new(
        move |label: &str, bytes: ByteView, auto_expand_paths: Vec<String>| {
            envelope_view.set(None);
            raw_bytes.set(None);
            patch_bytes.set(Some(bytes.clone()));

            // SAFETY: `patch_bytes` keeps the backing `Rc<Vec<u8>>` alive for the lifetime of
            // `patch_state`.
            let source = unsafe { protobuf_edit::Buf::from_borrowed_slice(bytes.as_slice()) };
            let res = Patch::from_buf(source);
            match res {
                Ok(mut patch) => {
                    let _ = patch.enable_read_cache();
                    let field_count =
                        patch.message_fields(patch.root()).map(|f| f.len()).unwrap_or(0);

                    let expanded_by_default = {
                        let mut out: FxHashSet<FieldId> = FxHashSet::default();
                        for raw in auto_expand_paths {
                            let Some(path) = decode_selection_path(&raw) else {
                                continue;
                            };
                            let Ok(Some((_fid, expanded))) =
                                resolve_selection_path(&mut patch, &path, true)
                            else {
                                continue;
                            };
                            out.extend(expanded);
                        }
                        out
                    };

                    patch_state.set(Some(patch));
                    reset_ui_state_keep_selected(None, expanded_by_default);
                    show_toast(
                        toasts,
                        next_toast_id,
                        ToastKind::Success,
                        format!("Loaded {label}: {} bytes, {field_count} field(s).", bytes.len()),
                    );
                }
                Err(e) => {
                    patch_state.set(None);
                    patch_bytes.set(None);
                    reset_ui_state();
                    let frames = parse_envelope_frames(bytes.as_slice()).ok();
                    raw_bytes.set(Some(bytes));
                    let msg = match frames {
                        Some(frames) if !frames.is_empty() => format!(
                            "Failed to load {label}: {e:?}. Bytes match envelope framing ({} frame(s)). Use \"View Frames\", \"Import Envelope\", or \"Extract Frames\".",
                            frames.len()
                        ),
                        _ => format!("Failed to load {label}: {e:?}"),
                    };
                    show_toast(toasts, next_toast_id, ToastKind::Error, msg);
                }
            }
        },
    );

    type RefreshMessagesFn = dyn Fn() -> Pin<Box<dyn Future<Output = ()> + 'static>>;

    let refresh_messages: Rc<RefreshMessagesFn> = Rc::new(move || {
        Box::pin(async move {
            let list = match messages::list_messages().await {
                Ok(v) => v,
                Err(msg) => {
                    show_toast(
                        toasts,
                        next_toast_id,
                        ToastKind::Error,
                        format!("Failed to load messages: {msg}"),
                    );
                    Vec::new()
                }
            };

            let mut current = match messages::current_message() {
                Ok(v) => v,
                Err(msg) => {
                    show_toast(
                        toasts,
                        next_toast_id,
                        ToastKind::Error,
                        format!("Failed to read current message: {msg}"),
                    );
                    None
                }
            };

            if current.is_some() && !list.iter().any(|m| Some(m.id) == current) {
                current = None;
            }

            if current.is_none() && !list.is_empty() {
                current = Some(list[0].id);
                let _ = messages::set_current_message(current);
            }

            let name = current
                .and_then(|id| list.iter().find(|m| m.id == id).map(|m| m.name.as_ref()))
                .unwrap_or("");
            let needs_update = message_name_text.with_untracked(|s| s.as_str() != name);
            if needs_update {
                message_name_text.update(|s| {
                    s.clear();
                    s.push_str(name);
                });
            }

            messages_list.set(list);
            current_message_id.set(current);
        })
    });

    let switch_to_message = {
        let load_patch_from_view = load_patch_from_view.clone();
        Rc::new(move |id: MessageId| {
            let already_current = current_message_id.get_untracked() == Some(id);
            if dirty_fields.with_untracked(|s| !s.is_empty())
                && !confirm_discard_edits("switch messages")
            {
                return;
            }

            if !already_current && let Err(msg) = messages::set_current_message(Some(id)) {
                show_toast(toasts, next_toast_id, ToastKind::Error, msg);
                return;
            }

            current_message_id.set(Some(id));

            let name = messages_list
                .with_untracked(|list| list.iter().find(|m| m.id == id).map(|m| m.name.clone()))
                .unwrap_or_else(|| Arc::<str>::from(format!("Message {id}")));
            message_name_text.update(|s| {
                s.clear();
                s.push_str(name.as_ref());
            });

            patch_state.set(None);
            patch_bytes.set(None);
            raw_bytes.set(None);
            envelope_view.set(None);
            reset_ui_state();

            let nonce = load_nonce.get_untracked().wrapping_add(1);
            load_nonce.set(nonce);

            let label = format!("message \"{name}\"");
            let class_id = messages_list
                .with_untracked(|list| list.iter().find(|m| m.id == id).map(|m| m.class_id))
                .unwrap_or(id);
            let load_patch_from_view = load_patch_from_view.clone();
            spawn_local(async move {
                match messages::load_message_bytes(id).await {
                    Ok(loaded) => {
                        if load_nonce.get_untracked() != nonce
                            || current_message_id.get_untracked() != Some(id)
                        {
                            return;
                        }
                        match loaded.mode {
                            LoadedBytesMode::Protobuf => {
                                let auto_expand = match messages::load_auto_expand_paths(class_id)
                                    .await
                                {
                                    Ok(v) => v,
                                    Err(msg) => {
                                        show_toast(toasts, next_toast_id, ToastKind::Error, msg);
                                        Vec::new()
                                    }
                                };
                                load_patch_from_view(&label, loaded.bytes, auto_expand);
                            }
                            LoadedBytesMode::Raw => {
                                patch_state.set(None);
                                patch_bytes.set(None);
                                raw_bytes.set(Some(loaded.bytes));
                                reset_ui_state();
                                if let Some(note) = loaded.note {
                                    show_toast(toasts, next_toast_id, ToastKind::Success, note);
                                }
                            }
                        }
                    }
                    Err(msg) => {
                        if load_nonce.get_untracked() != nonce
                            || current_message_id.get_untracked() != Some(id)
                        {
                            return;
                        }
                        show_toast(
                            toasts,
                            next_toast_id,
                            ToastKind::Error,
                            format!("Failed to load message bytes: {msg}"),
                        );
                    }
                }
            });
        })
    };

    Effect::new({
        let refresh_messages = refresh_messages.clone();
        let switch_to_message = switch_to_message.clone();
        let load_patch_from_view = load_patch_from_view.clone();
        move |_| {
            if did_bootstrap.get() {
                return;
            }
            did_bootstrap.set(true);

            let refresh_messages = refresh_messages.clone();
            let switch_to_message = switch_to_message.clone();
            let load_patch_from_view = load_patch_from_view.clone();
            spawn_local(async move {
                match messages::load_frame_name_template() {
                    Ok(v) => frame_name_template_text.set(v),
                    Err(msg) => show_toast(toasts, next_toast_id, ToastKind::Error, msg),
                }

                refresh_messages().await;

                let hash = match get_url_hash() {
                    Ok(h) => h,
                    Err(msg) => {
                        show_toast(toasts, next_toast_id, ToastKind::Error, msg);
                        return;
                    }
                };

                let Some(b64) =
                    hash.strip_prefix("#base64=").or_else(|| hash.strip_prefix("#b64="))
                else {
                    if let Some(id) = current_message_id.get_untracked() {
                        switch_to_message(id);
                    }
                    return;
                };
                if b64.is_empty() {
                    return;
                }

                match decode_base64_url(b64) {
                    Ok(bytes) => {
                        raw_input.set(b64.to_string());
                        let name = format!("From URL hash ({}B)", bytes.len());
                        let bytes_len = bytes.len();
                        let bytes_value = js_sys::Uint8Array::from(bytes.as_slice());
                        match messages::create_message(&name, bytes_len, bytes_value).await {
                            Ok(id) => {
                                refresh_messages().await;
                                current_message_id.set(Some(id));
                                load_patch_from_view(
                                    &format!("URL hash → message \"{name}\""),
                                    ByteView::from_vec(bytes),
                                    Vec::new(),
                                );
                                show_toast(
                                    toasts,
                                    next_toast_id,
                                    ToastKind::Success,
                                    format!("Imported URL hash as message \"{name}\"."),
                                );
                                message_name_text.set(name);
                            }
                            Err(msg) => show_toast(toasts, next_toast_id, ToastKind::Error, msg),
                        }
                    }
                    Err(msg) => show_toast(toasts, next_toast_id, ToastKind::Error, msg),
                }
            });
        }
    });

    let on_select_message = {
        let switch_to_message = switch_to_message.clone();
        UnsyncCallback::new(move |id: MessageId| {
            switch_to_message(id);
        })
    };

    let on_message_name_change = {
        let refresh_messages = refresh_messages.clone();
        UnsyncCallback::new(move |ev: leptos::ev::Event| {
            let Some(id) = current_message_id.get_untracked() else {
                return;
            };
            let name = event_target_value(&ev);
            let name = name.trim();
            if name.is_empty() {
                return;
            }
            let name = name.to_string();
            let refresh_messages = refresh_messages.clone();
            spawn_local(async move {
                if let Err(msg) = messages::rename_message(id, &name).await {
                    show_toast(toasts, next_toast_id, ToastKind::Error, msg);
                    return;
                }
                refresh_messages().await;
            });
        })
    };

    let on_new_message = {
        let refresh_messages = refresh_messages.clone();
        let load_patch_from_view = load_patch_from_view.clone();
        UnsyncCallback::new(move |_| {
            if !confirm_discard_edits("create a new message") {
                return;
            }
            let name = "New message";
            let bytes_value = js_sys::Uint8Array::new_with_length(0);
            let refresh_messages = refresh_messages.clone();
            let load_patch_from_view = load_patch_from_view.clone();
            spawn_local(async move {
                match messages::create_message(name, 0, bytes_value).await {
                    Ok(id) => {
                        refresh_messages().await;
                        current_message_id.set(Some(id));
                        message_name_text.update(|s| {
                            s.clear();
                            s.push_str(name);
                        });
                        load_patch_from_view(
                            &format!("new → message \"{name}\""),
                            ByteView::from_vec(Vec::new()),
                            Vec::new(),
                        );
                    }
                    Err(msg) => show_toast(toasts, next_toast_id, ToastKind::Error, msg),
                }
            });
        })
    };

    let on_delete_selected_messages = {
        let refresh_messages = refresh_messages.clone();
        let switch_to_message = switch_to_message.clone();
        UnsyncCallback::new(move |ids: Vec<MessageId>| {
            let mut ids = ids;
            ids.sort_unstable();
            ids.dedup();
            if ids.is_empty() {
                return;
            }

            let current = current_message_id.get_untracked();
            let deleting_current = current.is_some_and(|cur| ids.contains(&cur));

            if deleting_current
                && dirty_fields.with_untracked(|s| !s.is_empty())
                && !confirm_discard_edits("delete selected messages")
            {
                return;
            }

            let Some(window) = web_sys::window() else {
                return;
            };
            let msg = if deleting_current {
                format!("Delete {} message(s) (including the current message)?", ids.len())
            } else {
                format!("Delete {} message(s)?", ids.len())
            };
            let confirmed = window.confirm_with_message(&msg).unwrap_or(false);
            if !confirmed {
                return;
            }

            if deleting_current {
                patch_state.set(None);
                patch_bytes.set(None);
                raw_bytes.set(None);
                envelope_view.set(None);
                reset_ui_state();
            }

            let refresh_messages = refresh_messages.clone();
            let switch_to_message = switch_to_message.clone();
            spawn_local(async move {
                let mut deleted: usize = 0;
                for id in ids {
                    match messages::delete_message(id).await {
                        Ok(()) => deleted = deleted.saturating_add(1),
                        Err(msg) => show_toast(toasts, next_toast_id, ToastKind::Error, msg),
                    }
                }

                refresh_messages().await;
                if deleting_current && let Some(next_id) = current_message_id.get_untracked() {
                    switch_to_message(next_id);
                }

                show_toast(
                    toasts,
                    next_toast_id,
                    ToastKind::Success,
                    format!("Deleted {deleted} message(s)."),
                );
            });
        })
    };

    let import_text = {
        let refresh_messages = refresh_messages.clone();
        let load_patch_from_view = load_patch_from_view.clone();
        move |label: &str, input: &str, name_prefix: &str| {
            if !confirm_discard_edits("import new bytes") {
                return;
            }
            match decode_user_input(input) {
                Ok(bytes) => {
                    let label = label.to_string();
                    let name = import_name_text.get_untracked();
                    let name = if name.trim().is_empty() {
                        format!("{name_prefix} ({}B)", bytes.len())
                    } else {
                        name.trim().to_string()
                    };
                    let bytes_len = bytes.len();
                    let bytes_value = js_sys::Uint8Array::from(bytes.as_slice());
                    let refresh_messages = refresh_messages.clone();
                    let load_patch_from_view = load_patch_from_view.clone();
                    spawn_local(async move {
                        match messages::create_message(&name, bytes_len, bytes_value).await {
                            Ok(id) => {
                                refresh_messages().await;
                                current_message_id.set(Some(id));
                                load_patch_from_view(
                                    &format!("{label} → message \"{name}\""),
                                    ByteView::from_vec(bytes),
                                    Vec::new(),
                                );
                                message_name_text.set(name);
                            }
                            Err(msg) => show_toast(toasts, next_toast_id, ToastKind::Error, msg),
                        }
                    });
                }
                Err(msg) => show_toast(
                    toasts,
                    next_toast_id,
                    ToastKind::Error,
                    format!("Failed to decode {label}: {msg}"),
                ),
            }
        }
    };

    let on_import_click = UnsyncCallback::new(move |_| {
        if let Err(msg) =
            messages::store_frame_name_template(&frame_name_template_text.get_untracked())
        {
            show_toast(toasts, next_toast_id, ToastKind::Error, msg);
        }
        let input = raw_input.get_untracked();
        import_text("input", &input, "Import");
    });

    let extract_envelope_bytes = {
        let switch_to_message = switch_to_message.clone();
        let refresh_messages = refresh_messages.clone();
        Rc::new(move |source_id: MessageId, source_name: String, bytes: Vec<u8>| {
            envelope_view.set(None);
            patch_state.set(None);
            patch_bytes.set(None);
            raw_bytes.set(None);
            reset_ui_state();

            let bytes = Rc::new(bytes);
            let template = frame_name_template_text.get_untracked();
            let refresh_messages = refresh_messages.clone();
            let switch_to_message = switch_to_message.clone();
            spawn_local(async move {
                let revision = match messages::message_modified_ms(source_id).await {
                    Ok(v) => v,
                    Err(msg) => {
                        show_toast(toasts, next_toast_id, ToastKind::Error, msg);
                        0
                    }
                };
                page_cache::store_message_bytes(source_id, revision, bytes.clone());

                let frames = match parse_envelope_frames(bytes.as_slice()) {
                    Ok(v) => v,
                    Err(msg) => {
                        show_toast(toasts, next_toast_id, ToastKind::Error, msg);
                        return;
                    }
                };

                let mut created: usize = 0;
                let mut compressed: usize = 0;
                let mut json: usize = 0;
                let mut open_id: Option<MessageId> = None;
                let mut open_score: u8 = 0;

                for (idx, frame) in frames.iter().copied().enumerate() {
                    let payload_len = frame.payload_len;
                    let mut name =
                        format_frame_name_template(&template, &source_name, idx, payload_len);
                    if frame.is_compressed() {
                        compressed = compressed.saturating_add(1);
                        name.push_str(" (compressed)");
                    }
                    if frame.is_json() {
                        json = json.saturating_add(1);
                        name.push_str(" (json)");
                    }

                    let id = match messages::create_envelope_frame_ref_in_same_class(
                        source_id,
                        &name,
                        frame.payload_offset,
                        frame.payload_len,
                        frame.flags,
                        frame.is_compressed(),
                    )
                    .await
                    {
                        Ok(v) => v,
                        Err(msg) => {
                            show_toast(toasts, next_toast_id, ToastKind::Error, msg);
                            return;
                        }
                    };
                    created = created.saturating_add(1);

                    let score = if !frame.is_json() && !frame.is_compressed() {
                        3
                    } else if !frame.is_json() {
                        2
                    } else {
                        1
                    };
                    if open_id.is_none() || score > open_score {
                        open_id = Some(id);
                        open_score = score;
                    }
                }

                let Some(open_id) = open_id else {
                    show_toast(
                        toasts,
                        next_toast_id,
                        ToastKind::Error,
                        "Envelope did not contain any frames.",
                    );
                    return;
                };

                refresh_messages().await;
                switch_to_message(open_id);
                let msg = match (compressed, json) {
                    (0, 0) => format!("Extracted {created} frame(s) into new messages."),
                    (_, 0) => format!(
                        "Extracted {created} frame(s) into new messages. ({compressed} compressed.)"
                    ),
                    (0, _) => {
                        format!("Extracted {created} frame(s) into new messages. ({json} json.)")
                    }
                    (_, _) => format!(
                        "Extracted {created} frame(s) into new messages. ({compressed} compressed, {json} json.)"
                    ),
                };
                show_toast(toasts, next_toast_id, ToastKind::Success, msg);
            });
        })
    };

    let on_import_envelope_click = {
        let extract_envelope_bytes = extract_envelope_bytes.clone();
        UnsyncCallback::new(move |_| {
            if !confirm_discard_edits("import envelope bytes") {
                return;
            }
            let input = raw_input.get_untracked();
            let bytes = match decode_user_input(&input) {
                Ok(v) => v,
                Err(msg) => {
                    show_toast(
                        toasts,
                        next_toast_id,
                        ToastKind::Error,
                        format!("Failed to decode input: {msg}"),
                    );
                    return;
                }
            };
            if let Err(msg) =
                messages::store_frame_name_template(&frame_name_template_text.get_untracked())
            {
                show_toast(toasts, next_toast_id, ToastKind::Error, msg);
            }

            let import_name = import_name_text.get_untracked();
            let source_name = if import_name.trim().is_empty() {
                format!("Envelope import ({}B)", bytes.len())
            } else {
                import_name.trim().to_string()
            };
            let bytes_len = bytes.len();
            let bytes_value = js_sys::Uint8Array::from(bytes.as_slice());
            let extract_envelope_bytes = extract_envelope_bytes.clone();
            spawn_local(async move {
                let source_id =
                    match messages::create_message(&source_name, bytes_len, bytes_value).await {
                        Ok(v) => v,
                        Err(msg) => {
                            show_toast(toasts, next_toast_id, ToastKind::Error, msg);
                            return;
                        }
                    };
                extract_envelope_bytes(source_id, source_name, bytes);
            });
        })
    };

    let open_envelope_frame = UnsyncCallback::new(move |idx: usize| {
        let Some((bytes, frame, cached_err)) = envelope_view.with_untracked(|state| {
            let view = state.as_ref()?;
            let frame = view.frames.get(idx).copied()?;
            let cached_err =
                view.meta.get(idx).and_then(|meta| meta.protobuf_error.as_ref()).cloned();
            Some((view.bytes.clone(), frame, cached_err))
        }) else {
            return;
        };

        envelope_selected.set(idx);

        let Some(view) = ByteView::slice(
            bytes.clone(),
            frame.payload_offset,
            frame.payload_offset.saturating_add(frame.payload_len),
        ) else {
            show_toast(
                toasts,
                next_toast_id,
                ToastKind::Error,
                "Envelope frame payload range is out of bounds.",
            );
            return;
        };

        if frame.is_compressed() {
            patch_state.set(None);
            patch_bytes.set(None);
            raw_bytes.set(Some(view));
            reset_ui_state();
            return;
        }

        if frame.is_json() {
            patch_state.set(None);
            patch_bytes.set(None);
            raw_bytes.set(Some(view));
            reset_ui_state();
            return;
        }

        if cached_err.is_some() {
            patch_state.set(None);
            patch_bytes.set(None);
            raw_bytes.set(Some(view));
            reset_ui_state();
            return;
        }

        patch_bytes.set(Some(view.clone()));
        // SAFETY: `patch_bytes` keeps the backing `Rc<Vec<u8>>` alive while `patch_state` is set.
        let source = unsafe { protobuf_edit::Buf::from_borrowed_slice(view.as_slice()) };
        match Patch::from_buf(source) {
            Ok(mut patch) => {
                let _ = patch.enable_read_cache();
                patch_state.set(Some(patch));
                raw_bytes.set(None);
                reset_ui_state();
            }
            Err(e) => {
                let msg = format!("{e:?}");
                envelope_view.update(|state| {
                    let Some(view) = state.as_mut() else {
                        return;
                    };
                    let Some(meta) = view.meta.get_mut(idx) else {
                        return;
                    };
                    meta.protobuf_error = Some(msg.clone());
                });

                patch_state.set(None);
                patch_bytes.set(None);
                raw_bytes.set(Some(view));
                reset_ui_state();
                show_toast(
                    toasts,
                    next_toast_id,
                    ToastKind::Error,
                    format!("Failed to parse envelope frame as protobuf: {msg}"),
                );
            }
        }
    });

    let on_view_frames = UnsyncCallback::new(move |_| {
        let Some(source_id) = current_message_id.get_untracked() else {
            show_toast(toasts, next_toast_id, ToastKind::Error, "No message selected.");
            return;
        };
        if !confirm_discard_edits("view envelope frames") {
            return;
        }

        spawn_local(async move {
            let revision = match messages::message_modified_ms(source_id).await {
                Ok(v) => v,
                Err(msg) => {
                    show_toast(toasts, next_toast_id, ToastKind::Error, msg);
                    return;
                }
            };

            let loaded = match messages::load_message_bytes(source_id).await {
                Ok(v) => v,
                Err(msg) => {
                    show_toast(toasts, next_toast_id, ToastKind::Error, msg);
                    return;
                }
            };

            let bytes_view = loaded.bytes;
            let bytes = bytes_view.bytes_rc();
            if bytes_view.len() != bytes.len() {
                show_toast(
                    toasts,
                    next_toast_id,
                    ToastKind::Error,
                    "View Frames is not supported for sliced messages.",
                );
                return;
            }

            page_cache::store_message_bytes(source_id, revision, bytes.clone());
            let frames = match parse_envelope_frames(bytes_view.as_slice()) {
                Ok(v) => v,
                Err(msg) => {
                    show_toast(toasts, next_toast_id, ToastKind::Error, msg);
                    return;
                }
            };
            if frames.is_empty() {
                show_toast(
                    toasts,
                    next_toast_id,
                    ToastKind::Error,
                    "Envelope did not contain any frames.",
                );
                return;
            }

            patch_state.set(None);
            patch_bytes.set(None);
            raw_bytes.set(None);
            reset_ui_state();

            let frames_len = frames.len();
            let selected = frames
                .iter()
                .position(|f| !f.is_compressed() && !f.is_json())
                .or_else(|| frames.iter().position(|f| !f.is_compressed()))
                .unwrap_or(0);

            let meta = vec![EnvelopeFrameMeta::default(); frames.len()];
            envelope_view.set(Some(EnvelopeView { source_id, bytes, frames, meta }));
            envelope_selected.set(selected);
            open_envelope_frame.run(selected);
            show_toast(
                toasts,
                next_toast_id,
                ToastKind::Success,
                format!("Loaded envelope view: {frames_len} frame(s)."),
            );
        });
    });

    let on_close_frames = UnsyncCallback::new(move |_| {
        let Some(bytes) =
            envelope_view.with_untracked(|state| state.as_ref().map(|v| v.bytes.clone()))
        else {
            return;
        };
        let len = bytes.len();
        envelope_view.set(None);
        envelope_selected.set(0);
        patch_state.set(None);
        patch_bytes.set(None);
        raw_bytes.set(ByteView::slice(bytes, 0, len));
        reset_ui_state();
        show_toast(toasts, next_toast_id, ToastKind::Success, "Showing raw envelope bytes.");
    });

    let on_decompress_selected_frame = {
        let switch_to_message = switch_to_message.clone();
        let refresh_messages = refresh_messages.clone();
        UnsyncCallback::new(move |_| {
            let Some((source_id, idx, frame)) = envelope_view.with_untracked(|state| {
                let view = state.as_ref()?;
                let idx = envelope_selected.get_untracked();
                let frame = view.frames.get(idx).copied()?;
                Some((view.source_id, idx, frame))
            }) else {
                show_toast(toasts, next_toast_id, ToastKind::Error, "No envelope view loaded.");
                return;
            };

            if !frame.is_compressed() {
                show_toast(
                    toasts,
                    next_toast_id,
                    ToastKind::Error,
                    "Selected envelope frame is not compressed.",
                );
                return;
            }

            let source_name = message_name_text.get_untracked();
            let payload_len = frame.payload_len;
            let template = frame_name_template_text.get_untracked();
            let mut name = format_frame_name_template(&template, &source_name, idx, payload_len);
            name.push_str(" (compressed)");
            if frame.is_json() {
                name.push_str(" (json)");
            }

            let refresh_messages = refresh_messages.clone();
            let switch_to_message = switch_to_message.clone();
            spawn_local(async move {
                let id = match messages::create_envelope_frame_ref_in_same_class(
                    source_id,
                    &name,
                    frame.payload_offset,
                    frame.payload_len,
                    frame.flags,
                    true,
                )
                .await
                {
                    Ok(id) => id,
                    Err(msg) => {
                        show_toast(toasts, next_toast_id, ToastKind::Error, msg);
                        return;
                    }
                };

                refresh_messages().await;
                switch_to_message(id);
                show_toast(
                    toasts,
                    next_toast_id,
                    ToastKind::Success,
                    format!("Opened frame {idx} as message \"{name}\" ({id})."),
                );
            });
        })
    };

    let extract_envelope_frame = {
        let refresh_messages = refresh_messages.clone();
        UnsyncCallback::new(move |idx: usize| {
            let Some((source_id, frame)) = envelope_view.with_untracked(|state| {
                let view = state.as_ref()?;
                let frame = view.frames.get(idx).copied()?;
                Some((view.source_id, frame))
            }) else {
                show_toast(toasts, next_toast_id, ToastKind::Error, "No envelope view loaded.");
                return;
            };

            let source_name = message_name_text.get_untracked();
            let payload_len = frame.payload_len;
            let template = frame_name_template_text.get_untracked();
            let mut name = format_frame_name_template(&template, &source_name, idx, payload_len);
            if frame.is_compressed() {
                name.push_str(" (compressed)");
            }
            if frame.is_json() {
                name.push_str(" (json)");
            }

            let refresh_messages = refresh_messages.clone();
            spawn_local(async move {
                let id = match messages::create_envelope_frame_ref_in_same_class(
                    source_id,
                    &name,
                    frame.payload_offset,
                    frame.payload_len,
                    frame.flags,
                    frame.is_compressed(),
                )
                .await
                {
                    Ok(id) => id,
                    Err(msg) => {
                        show_toast(toasts, next_toast_id, ToastKind::Error, msg);
                        return;
                    }
                };

                let _ = messages::set_current_message(Some(source_id));
                refresh_messages().await;
                show_toast(
                    toasts,
                    next_toast_id,
                    ToastKind::Success,
                    format!("Extracted frame {idx} as message \"{name}\" ({id})."),
                );
            });
        })
    };

    let on_extract_all_frames = {
        let refresh_messages = refresh_messages.clone();
        UnsyncCallback::new(move |_| {
            let source_name = message_name_text.get_untracked();
            let Some((source_id, frames)) = envelope_view.with_untracked(|state| {
                let view = state.as_ref()?;
                Some((view.source_id, view.frames.clone()))
            }) else {
                show_toast(toasts, next_toast_id, ToastKind::Error, "No envelope view loaded.");
                return;
            };
            if frames.is_empty() {
                show_toast(
                    toasts,
                    next_toast_id,
                    ToastKind::Error,
                    "Envelope did not contain any frames.",
                );
                return;
            }

            let Some(window) = web_sys::window() else {
                return;
            };
            let confirmed = window
                .confirm_with_message(&format!(
                    "Extract {} frame(s) from \"{source_name}\" into new messages?\n\nCompressed frames will be auto-decompressed when possible.",
                    frames.len()
                ))
                .unwrap_or(false);
            if !confirmed {
                return;
            }

            let template = frame_name_template_text.get_untracked();
            let refresh_messages = refresh_messages.clone();
            spawn_local(async move {
                let mut created: usize = 0;
                let mut compressed: usize = 0;
                let mut json: usize = 0;

                for (idx, frame) in frames.iter().copied().enumerate() {
                    let payload_len = frame.payload_len;
                    let mut name =
                        format_frame_name_template(&template, &source_name, idx, payload_len);
                    if frame.is_compressed() {
                        compressed = compressed.saturating_add(1);
                        name.push_str(" (compressed)");
                    }
                    if frame.is_json() {
                        json = json.saturating_add(1);
                        name.push_str(" (json)");
                    }

                    match messages::create_envelope_frame_ref_in_same_class(
                        source_id,
                        &name,
                        frame.payload_offset,
                        frame.payload_len,
                        frame.flags,
                        frame.is_compressed(),
                    )
                    .await
                    {
                        Ok(_id) => created = created.saturating_add(1),
                        Err(msg) => {
                            show_toast(toasts, next_toast_id, ToastKind::Error, msg);
                            return;
                        }
                    }
                }

                let _ = messages::set_current_message(Some(source_id));
                refresh_messages().await;

                let msg = match (compressed, json) {
                    (0, 0) => format!("Extracted {created} frame(s) into new messages."),
                    (_, 0) => format!(
                        "Extracted {created} frame(s) into new messages. ({compressed} compressed.)"
                    ),
                    (0, _) => {
                        format!("Extracted {created} frame(s) into new messages. ({json} json.)")
                    }
                    (_, _) => format!(
                        "Extracted {created} frame(s) into new messages. ({compressed} compressed, {json} json.)"
                    ),
                };
                show_toast(toasts, next_toast_id, ToastKind::Success, msg);
            });
        })
    };

    let on_upload_change = {
        let refresh_messages = refresh_messages.clone();
        let load_patch_from_view = load_patch_from_view.clone();
        UnsyncCallback::new(move |ev: leptos::ev::Event| {
            let input: web_sys::HtmlInputElement = event_target(&ev);
            let Some(files) = input.files() else {
                return;
            };
            let Some(file) = files.get(0) else {
                return;
            };
            let filename = file.name();

            let reader = match web_sys::FileReader::new() {
                Ok(r) => r,
                Err(_) => {
                    show_toast(
                        toasts,
                        next_toast_id,
                        ToastKind::Error,
                        "Failed to create FileReader.",
                    );
                    return;
                }
            };
            let reader_for_cb = reader.clone();
            let refresh_messages = refresh_messages.clone();
            let load_patch_from_view = load_patch_from_view.clone();

            let onload = Closure::<dyn FnMut(web_sys::ProgressEvent)>::new(move |_| {
                let result = match reader_for_cb.result() {
                    Ok(v) => v,
                    Err(_) => {
                        show_toast(
                            toasts,
                            next_toast_id,
                            ToastKind::Error,
                            "Failed to read file contents.",
                        );
                        return;
                    }
                };
                let u8_array = js_sys::Uint8Array::new(&result);
                let mut bytes = vec![0u8; u8_array.length() as usize];
                u8_array.copy_to(&mut bytes);

                raw_input.set(encode_base64(&bytes));
                let import_name = import_name_text.get_untracked();
                let name = if import_name.trim().is_empty() {
                    format!("Upload: {filename}")
                } else {
                    import_name.trim().to_string()
                };
                let bytes_len = bytes.len();
                let bytes_value = js_sys::Uint8Array::from(bytes.as_slice());
                let refresh_messages = refresh_messages.clone();
                let load_patch_from_view = load_patch_from_view.clone();
                spawn_local(async move {
                    match messages::create_message(&name, bytes_len, bytes_value).await {
                        Ok(id) => {
                            refresh_messages().await;
                            current_message_id.set(Some(id));
                            load_patch_from_view(
                                &format!("upload → message \"{name}\""),
                                ByteView::from_vec(bytes),
                                Vec::new(),
                            );
                            message_name_text.set(name);
                        }
                        Err(msg) => show_toast(toasts, next_toast_id, ToastKind::Error, msg),
                    }
                });
            });

            reader.set_onload(Some(onload.as_ref().unchecked_ref()));
            onload.forget();

            if reader.read_as_array_buffer(&file).is_err() {
                show_toast(
                    toasts,
                    next_toast_id,
                    ToastKind::Error,
                    "Failed to start reading file.",
                );
            }
        })
    };

    let on_toggle_theme = UnsyncCallback::new(move |_| {
        let _ = start_theme_transition(180);
        let next = theme.get_untracked().toggle();
        theme.set(next);
        let _ = messages::store_theme_pref(next.as_str());
    });
    let theme_is_dark = Memo::new(move |_| theme.get() == Theme::Dark);

    let on_store_frame_name_template = UnsyncCallback::new(move |_| {
        let template = frame_name_template_text.get_untracked();
        if let Err(msg) = messages::store_frame_name_template(&template) {
            show_toast(toasts, next_toast_id, ToastKind::Error, msg);
        }
    });

    let on_rename_message = {
        let refresh_messages = refresh_messages.clone();
        UnsyncCallback::new(move |(id, name): (MessageId, String)| {
            let name = name.trim();
            if name.is_empty() {
                return;
            }
            let name = name.to_string();
            let refresh_messages = refresh_messages.clone();
            spawn_local(async move {
                if let Err(msg) = messages::rename_message(id, &name).await {
                    show_toast(toasts, next_toast_id, ToastKind::Error, msg);
                    return;
                }
                refresh_messages().await;
            });
        })
    };

    let on_rename_class = {
        let refresh_messages = refresh_messages.clone();
        UnsyncCallback::new(move |(class_id, name): (MessageId, String)| {
            let name = name.trim();
            if name.is_empty() {
                return;
            }
            let name = name.to_string();
            let refresh_messages = refresh_messages.clone();
            spawn_local(async move {
                if let Err(msg) = messages::rename_class(class_id, &name).await {
                    show_toast(toasts, next_toast_id, ToastKind::Error, msg);
                    return;
                }
                refresh_messages().await;
            });
        })
    };

    let bytes_count = Memo::new(move |_| {
        patch_state
            .with(|p| p.as_ref().map(|p| p.root_bytes().len()))
            .or_else(|| raw_bytes.with(|b| b.as_ref().map(|b| b.len())))
            .or_else(|| {
                let id = current_message_id.get()?;
                messages_list.with(|list| list.iter().find(|m| m.id == id).map(|m| m.bytes_len))
            })
    });
    let field_count = Memo::new(move |_| {
        patch_state.with(|p| {
            let patch = p.as_ref()?;
            let fields = patch.message_fields(patch.root()).ok()?;
            let mut live: usize = 0;
            for &fid in fields {
                if matches!(patch.field_is_deleted(fid), Ok(true)) {
                    continue;
                }
                live = live.saturating_add(1);
            }
            Some(live)
        })
    });
    let dirty_count = Memo::new(move |_| dirty_fields.with(|s| s.len()));

    let on_copy_hex = UnsyncCallback::new(move |_| {
        let bytes_from_patch = patch_state.with(|p| {
            p.as_ref().map(|patch| {
                let bytes = patch.root_bytes();
                (hex::encode_upper(bytes), bytes.len())
            })
        });
        let bytes_from_raw = raw_bytes.with(|b| {
            b.as_ref().map(|v| {
                let bytes = v.as_slice();
                (hex::encode_upper(bytes), bytes.len())
            })
        });

        let Some((text, len)) = bytes_from_patch.or(bytes_from_raw) else {
            let Some(id) = current_message_id.get_untracked() else {
                show_toast(toasts, next_toast_id, ToastKind::Error, "No message selected.");
                return;
            };
            spawn_local(async move {
                let loaded = match messages::load_message_bytes(id).await {
                    Ok(v) => v,
                    Err(msg) => {
                        show_toast(toasts, next_toast_id, ToastKind::Error, msg);
                        return;
                    }
                };
                let bytes = loaded.bytes.as_slice();
                let text = hex::encode_upper(bytes);
                let len = bytes.len();
                match clipboard_write_text(&text) {
                    Ok(_promise) => {
                        let pending = dirty_count.get_untracked();
                        let msg = if pending == 0 {
                            format!("Copy hex requested: {len} bytes.")
                        } else {
                            format!("Copy hex requested: {len} bytes. ({pending} edit(s) pending.)")
                        };
                        show_toast(toasts, next_toast_id, ToastKind::Success, msg);
                    }
                    Err(msg) => show_toast(toasts, next_toast_id, ToastKind::Error, msg),
                }
            });
            return;
        };

        match clipboard_write_text(&text) {
            Ok(_promise) => {
                let pending = dirty_count.get_untracked();
                let msg = if pending == 0 {
                    format!("Copy hex requested: {len} bytes.")
                } else {
                    format!("Copy hex requested: {len} bytes. ({pending} edit(s) pending.)")
                };
                show_toast(toasts, next_toast_id, ToastKind::Success, msg);
            }
            Err(msg) => show_toast(toasts, next_toast_id, ToastKind::Error, msg),
        }
    });

    let on_copy_base64 = UnsyncCallback::new(move |_| {
        let bytes_from_patch = patch_state.with(|p| {
            p.as_ref().map(|patch| {
                let bytes = patch.root_bytes();
                (encode_base64(bytes), bytes.len())
            })
        });
        let bytes_from_raw = raw_bytes.with(|b| {
            b.as_ref().map(|v| {
                let bytes = v.as_slice();
                (encode_base64(bytes), bytes.len())
            })
        });

        let Some((text, len)) = bytes_from_patch.or(bytes_from_raw) else {
            let Some(id) = current_message_id.get_untracked() else {
                show_toast(toasts, next_toast_id, ToastKind::Error, "No message selected.");
                return;
            };
            spawn_local(async move {
                let loaded = match messages::load_message_bytes(id).await {
                    Ok(v) => v,
                    Err(msg) => {
                        show_toast(toasts, next_toast_id, ToastKind::Error, msg);
                        return;
                    }
                };
                let bytes = loaded.bytes.as_slice();
                let text = encode_base64(bytes);
                let len = bytes.len();
                match clipboard_write_text(&text) {
                    Ok(_promise) => {
                        let pending = dirty_count.get_untracked();
                        let msg = if pending == 0 {
                            format!("Copy base64 requested: {len} bytes.")
                        } else {
                            format!(
                                "Copy base64 requested: {len} bytes. ({pending} edit(s) pending.)"
                            )
                        };
                        show_toast(toasts, next_toast_id, ToastKind::Success, msg);
                    }
                    Err(msg) => show_toast(toasts, next_toast_id, ToastKind::Error, msg),
                }
            });
            return;
        };

        match clipboard_write_text(&text) {
            Ok(_promise) => {
                let pending = dirty_count.get_untracked();
                let msg = if pending == 0 {
                    format!("Copy base64 requested: {len} bytes.")
                } else {
                    format!("Copy base64 requested: {len} bytes. ({pending} edit(s) pending.)")
                };
                show_toast(toasts, next_toast_id, ToastKind::Success, msg);
            }
            Err(msg) => show_toast(toasts, next_toast_id, ToastKind::Error, msg),
        }
    });

    let on_copy_share_url = UnsyncCallback::new(move |_| {
        let bytes_from_patch = patch_state.with(|p| {
            p.as_ref().map(|patch| {
                let bytes = patch.root_bytes();
                (encode_base64_url(bytes), bytes.len())
            })
        });
        let bytes_from_raw = raw_bytes.with(|b| {
            b.as_ref().map(|v| {
                let bytes = v.as_slice();
                (encode_base64_url(bytes), bytes.len())
            })
        });

        let Some((b64, len)) = bytes_from_patch.or(bytes_from_raw) else {
            let Some(id) = current_message_id.get_untracked() else {
                show_toast(toasts, next_toast_id, ToastKind::Error, "No message selected.");
                return;
            };
            spawn_local(async move {
                let loaded = match messages::load_message_bytes(id).await {
                    Ok(v) => v,
                    Err(msg) => {
                        show_toast(toasts, next_toast_id, ToastKind::Error, msg);
                        return;
                    }
                };
                let bytes = loaded.bytes.as_slice();
                let b64 = encode_base64_url(bytes);
                let len = bytes.len();

                let hash = format!("base64={b64}");
                let url = match build_share_url(&hash) {
                    Ok(v) => v,
                    Err(msg) => {
                        show_toast(toasts, next_toast_id, ToastKind::Error, msg);
                        return;
                    }
                };

                match clipboard_write_text(&url) {
                    Ok(_promise) => {
                        let msg = format!("Copy URL requested: {len} bytes.");
                        show_toast(toasts, next_toast_id, ToastKind::Success, msg);
                    }
                    Err(msg) => show_toast(toasts, next_toast_id, ToastKind::Error, msg),
                }
            });
            return;
        };

        let hash = format!("base64={b64}");
        let url = match build_share_url(&hash) {
            Ok(v) => v,
            Err(msg) => {
                show_toast(toasts, next_toast_id, ToastKind::Error, msg);
                return;
            }
        };

        match clipboard_write_text(&url) {
            Ok(_promise) => {
                let msg = format!("Copy URL requested: {len} bytes.");
                show_toast(toasts, next_toast_id, ToastKind::Success, msg);
            }
            Err(msg) => show_toast(toasts, next_toast_id, ToastKind::Error, msg),
        }
    });

    let on_download_bin = UnsyncCallback::new(move |_| {
        let Some(id) = current_message_id.get_untracked() else {
            show_toast(toasts, next_toast_id, ToastKind::Error, "No message selected.");
            return;
        };

        let filename = messages::download_filename(&message_name_text.get_untracked(), id);

        let from_patch = patch_state.with(|p| {
            p.as_ref().map(|patch| {
                let bytes = patch.root_bytes();
                (download_bytes(&filename, bytes), bytes.len())
            })
        });
        let from_raw = raw_bytes.with(|b| {
            b.as_ref().map(|v| {
                let bytes = v.as_slice();
                (download_bytes(&filename, bytes), bytes.len())
            })
        });

        let Some((res, len)) = from_patch.or(from_raw) else {
            spawn_local(async move {
                let loaded = match messages::load_message_bytes(id).await {
                    Ok(v) => v,
                    Err(msg) => {
                        show_toast(toasts, next_toast_id, ToastKind::Error, msg);
                        return;
                    }
                };
                let bytes = loaded.bytes.as_slice();
                let len = bytes.len();
                match download_bytes(&filename, bytes) {
                    Ok(()) => {
                        let pending = dirty_count.get_untracked();
                        let msg = if pending == 0 {
                            format!("Started download: {filename} ({len} bytes).")
                        } else {
                            format!(
                                "Started download: {filename} ({len} bytes). ({pending} edit(s) pending.)"
                            )
                        };
                        show_toast(toasts, next_toast_id, ToastKind::Success, msg);
                    }
                    Err(msg) => show_toast(toasts, next_toast_id, ToastKind::Error, msg),
                }
            });
            return;
        };

        match res {
            Ok(()) => {
                let pending = dirty_count.get_untracked();
                let msg = if pending == 0 {
                    format!("Started download: {filename} ({len} bytes).")
                } else {
                    format!(
                        "Started download: {filename} ({len} bytes). ({pending} edit(s) pending.)"
                    )
                };
                show_toast(toasts, next_toast_id, ToastKind::Success, msg);
            }
            Err(msg) => show_toast(toasts, next_toast_id, ToastKind::Error, msg),
        }
    });

    let on_save_expand_defaults = UnsyncCallback::new(move |_| {
        let Some(id) = current_message_id.get_untracked() else {
            show_toast(toasts, next_toast_id, ToastKind::Error, "No message selected.");
            return;
        };
        if read_only.get_untracked() {
            show_toast(
                toasts,
                next_toast_id,
                ToastKind::Error,
                "Cannot save expand defaults while viewing envelope frames.",
            );
            return;
        }

        let Some(mut paths) = patch_state.with_untracked(|p| {
            let patch = p.as_ref()?;
            Some(expanded.with_untracked(|expanded| {
                let mut paths = Vec::new();
                for &fid in expanded {
                    let Some(path) = build_selection_path(patch, fid) else {
                        continue;
                    };
                    paths.push(encode_selection_path(&path));
                }
                paths
            }))
        }) else {
            show_toast(toasts, next_toast_id, ToastKind::Error, "No protobuf message loaded.");
            return;
        };

        paths.sort_unstable();
        paths.dedup();
        let count = paths.len();

        let class_id = messages_list
            .with_untracked(|list| list.iter().find(|m| m.id == id).map(|m| m.class_id))
            .unwrap_or(id);
        spawn_local(async move {
            if let Err(msg) = messages::store_auto_expand_paths(class_id, &paths).await {
                show_toast(toasts, next_toast_id, ToastKind::Error, msg);
                return;
            }

            if count == 0 {
                show_toast(
                    toasts,
                    next_toast_id,
                    ToastKind::Success,
                    "Cleared auto-expand defaults.",
                );
            } else {
                show_toast(
                    toasts,
                    next_toast_id,
                    ToastKind::Success,
                    format!("Saved {count} auto-expand path(s)."),
                );
            }
        });
    });

    let revert_pending_edits = Rc::new(move || {
        let pending = dirty_fields.with_untracked(|s| s.len());
        if pending == 0 {
            return;
        }

        let bytes_view = patch_bytes.get_untracked();
        let prev_selected = selected.get_untracked();
        let prev_path = patch_state.with(|p| {
            let patch = p.as_ref()?;
            let fid = prev_selected?;
            build_selection_path(patch, fid)
        });

        let mut undo_error: Option<String> = None;
        let mut resolved: Option<(Option<FieldId>, FxHashSet<FieldId>)> = None;

        patch_state.update(|p| {
            let Some(mut patch) = p.take() else {
                undo_error = Some("Undo failed: no message loaded.".to_string());
                return;
            };

            if patch.txn_active() {
                patch.txn_rollback();
            } else {
                let Some(bytes_view) = bytes_view.as_ref() else {
                    undo_error = Some("Undo failed: missing root bytes view.".to_string());
                    *p = Some(patch);
                    return;
                };
                // SAFETY: `patch_bytes` keeps the backing bytes alive while `patch_state` is set.
                let source =
                    unsafe { protobuf_edit::Buf::from_borrowed_slice(bytes_view.as_slice()) };
                match Patch::from_buf(source) {
                    Ok(v) => patch = v,
                    Err(e) => {
                        undo_error = Some(format!("Undo failed: {e:?}"));
                        *p = Some(patch);
                        return;
                    }
                };
            }

            let _ = patch.enable_read_cache();

            resolved = Some(match prev_path.as_ref() {
                Some(path) => match resolve_selection_path(&mut patch, path, false) {
                    Ok(Some((fid, expanded))) => (Some(fid), expanded),
                    Ok(None) => (None, FxHashSet::default()),
                    Err(_) => (None, FxHashSet::default()),
                },
                None => (None, FxHashSet::default()),
            });

            *p = Some(patch);
        });

        if let Some(msg) = undo_error {
            show_toast(toasts, next_toast_id, ToastKind::Error, msg);
            return;
        }

        let (new_selected, new_expanded) = resolved.unwrap_or((None, FxHashSet::default()));
        selected.set(new_selected);
        hovered.set(None);
        expanded.set(new_expanded);
        dirty_fields.set(FxHashSet::default());
        show_toast(
            toasts,
            next_toast_id,
            ToastKind::Success,
            format!("Reverted {pending} pending edit(s)."),
        );
    });

    let save_and_reparse = {
        let refresh_messages = refresh_messages.clone();
        Rc::new(move || {
            let before_len = bytes_count.get_untracked().unwrap_or(0);
            let message_id = current_message_id.get_untracked();
            let prev_selected = selected.get_untracked();
            let prev_path = patch_state.with(|p| {
                let patch = p.as_ref()?;
                let fid = prev_selected?;
                build_selection_path(patch, fid)
            });

            let t0 = js_sys::Date::now();
            let res: Result<(Patch, ByteView), TreeError> = patch_state.with(|p| {
                let Some(patch) = p.as_ref() else {
                    return Err(TreeError::DecodeError);
                };
                let bytes = patch.save()?;
                let bytes = ByteView::from_vec(bytes.into_vec());
                // SAFETY: `patch_bytes` stores the backing bytes for the lifetime of `patch_state`.
                let source = unsafe { protobuf_edit::Buf::from_borrowed_slice(bytes.as_slice()) };
                let patch = Patch::from_buf(source)?;
                Ok((patch, bytes))
            });
            let elapsed_ms = (js_sys::Date::now() - t0).max(0.0);

            match res {
                Ok((mut patch, bytes_view)) => {
                    let _ = patch.enable_read_cache();
                    let field_count =
                        patch.message_fields(patch.root()).map(|f| f.len()).unwrap_or(0);
                    let bytes_len = patch.root_bytes().len();

                    if let Some(id) = message_id {
                        let bytes_value = js_sys::Uint8Array::from(bytes_view.as_slice());
                        let refresh_messages = refresh_messages.clone();
                        spawn_local(async move {
                            match messages::update_message_bytes(id, bytes_len, bytes_value).await {
                                Ok(()) => refresh_messages().await,
                                Err(msg) => {
                                    show_toast(toasts, next_toast_id, ToastKind::Error, msg)
                                }
                            }
                        });
                    }

                    let (new_selected, new_expanded) = match prev_path {
                        Some(path) => match resolve_selection_path(&mut patch, &path, false) {
                            Ok(Some((fid, expanded))) => (Some(fid), expanded),
                            Ok(None) => (None, FxHashSet::default()),
                            Err(_) => (None, FxHashSet::default()),
                        },
                        None => (None, FxHashSet::default()),
                    };

                    patch_bytes.set(Some(bytes_view));
                    patch_state.set(Some(patch));
                    reset_ui_state_keep_selected(new_selected, new_expanded);
                    show_toast(
                        toasts,
                        next_toast_id,
                        ToastKind::Success,
                        format!(
                            "Saved & reparsed: {bytes_len} bytes (was {before_len}), {field_count} field(s) in {elapsed_ms:.1}ms."
                        ),
                    );
                }
                Err(e) => show_toast(
                    toasts,
                    next_toast_id,
                    ToastKind::Error,
                    format!("Save & reparse failed: {e:?}"),
                ),
            }
        })
    };

    let on_save_reparse = {
        let save_and_reparse = save_and_reparse.clone();
        UnsyncCallback::new(move |_| save_and_reparse())
    };

    let on_bump_modified = UnsyncCallback::new(move |_| {
        let Some(id) = current_message_id.get_untracked() else {
            show_toast(toasts, next_toast_id, ToastKind::Error, "No message selected.");
            return;
        };
        let refresh_messages = refresh_messages.clone();
        spawn_local(async move {
            if let Err(msg) = messages::bump_message_modified(id).await {
                show_toast(toasts, next_toast_id, ToastKind::Error, msg);
                return;
            }
            refresh_messages().await;
            show_toast(
                toasts,
                next_toast_id,
                ToastKind::Success,
                "Updated modified time (reordered messages).",
            );
        });
    });

    let _stop_hotkeys = {
        let save_and_reparse = save_and_reparse.clone();
        let revert_pending_edits = revert_pending_edits.clone();
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
                        revert_pending_edits();
                    }
                    return;
                }

                if (ev.ctrl_key() || ev.meta_key()) && key.eq_ignore_ascii_case("s") {
                    ev.prevent_default();
                    if patch_state.with_untracked(|p| p.is_some())
                        && dirty_count.get_untracked() > 0
                    {
                        save_and_reparse();
                    }
                    return;
                }

                match key.as_str() {
                    "Escape" => {
                        ev.prevent_default();
                        selected.set(None);
                    }
                    "ArrowDown" => {
                        ev.prevent_default();
                        let visible = patch_state.with_untracked(|p| {
                            let Some(patch) = p.as_ref() else {
                                return Vec::new();
                            };
                            expanded.with_untracked(|expanded| {
                                let mut out = Vec::new();
                                collect_visible_fields(patch, patch.root(), expanded, &mut out);
                                out
                            })
                        });
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
                        let visible = patch_state.with_untracked(|p| {
                            let Some(patch) = p.as_ref() else {
                                return Vec::new();
                            };
                            expanded.with_untracked(|expanded| {
                                let mut out = Vec::new();
                                collect_visible_fields(patch, patch.root(), expanded, &mut out);
                                out
                            })
                        });
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
                            Err(e) => show_toast(
                                toasts,
                                next_toast_id,
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

    let envelope_frames_panel = move || {
        view! {
            <EnvelopeFramesPanel
                envelope_view=envelope_view
                selected=envelope_selected
                on_close=on_close_frames
                on_decompress=on_decompress_selected_frame
                on_open=open_envelope_frame
                on_extract=extract_envelope_frame
                on_extract_all=on_extract_all_frames
            />
        }
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
                patch_state=patch_state
                selected=selected
                hovered=hovered
                expanded=expanded
                dirty_fields=dirty_fields
                toasts=toasts
                next_toast_id=next_toast_id
            />
        }
    };

    view! {
        <div class="app">
            <div class="main">
                <div class="workspace">
                        <MessageSidebar
                            messages_list=messages_list
                            current_message_id=current_message_id
                            message_name_text=message_name_text
                            import_name_text=import_name_text
                            raw_input=raw_input
                            frame_name_template_text=frame_name_template_text
                            theme_is_dark=theme_is_dark
                            on_select_message=on_select_message
                            on_message_name_change=on_message_name_change
                            on_rename_message=on_rename_message
                            on_rename_class=on_rename_class
                            on_new_message=on_new_message
                            on_delete_selected_messages=on_delete_selected_messages
                            on_view_frames=on_view_frames
                            on_import=on_import_click
                        on_import_envelope=on_import_envelope_click
                        on_upload_change=on_upload_change
                        on_toggle_theme=on_toggle_theme
                        on_store_frame_name_template=on_store_frame_name_template
                    />

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
                                <HexGrid
                                    patch_state=patch_state
                                    raw_bytes=raw_bytes
                                    highlights=highlights
                                    text_mode=hex_text_mode
                                    selected=selected
                                    expanded=expanded
                                    container_ref=hex_container_ref
                                />
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
                                    <Breadcrumb patch_state=patch_state selected=selected />

                                    <Show
                                        when=move || envelope_view.with(|s| s.is_some())
                                        fallback=|| ()
                                    >
                                        {envelope_frames_panel}
                                    </Show>

                                    <div class="field-list" node_ref=tree_container_ref tabindex="0">
                                        <Show
                                            when=move || patch_state.with(|p| p.is_some())
                                            fallback=structure_tree_fallback
                                        >
                                            {field_tree_view}
                                        </Show>
                                    </div>

                                    <InspectorDrawer
                                        patch_state=patch_state
                                        read_only=read_only
                                        selected=selected
                                        expanded=expanded
                                        dirty_fields=dirty_fields
                                        toasts=toasts
                                        next_toast_id=next_toast_id
                                    />
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <StatusBar
                bytes_count=bytes_count
                field_count=field_count
                highlight_range_count=highlight_range_count
                selected=selected
                dirty_count=dirty_count
                current_message_id=current_message_id
                read_only=read_only
                patch_state=patch_state
                on_copy_hex=on_copy_hex
                on_copy_base64=on_copy_base64
                on_copy_share_url=on_copy_share_url
                on_download_bin=on_download_bin
                on_save_expand_defaults=on_save_expand_defaults
                on_save_reparse=on_save_reparse
                on_bump_modified=on_bump_modified
            />

            <ToastContainer toasts=toasts />
        </div>
    }
}
