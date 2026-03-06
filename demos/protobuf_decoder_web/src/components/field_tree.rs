use crate::state::{UiState, WorkspaceState};
use crate::toast::{show_toast, ToastKind};
use leptos::prelude::*;
use protobuf_edit::{FieldId, MessageId, Patch, TreeError, WireType};

#[component]
pub(crate) fn FieldTree(msg: MessageId, depth: usize) -> AnyView {
    let workspace = expect_context::<WorkspaceState>();
    let patch_state = workspace.patch_state;

    let fields = Memo::new(move |_| {
        patch_state.with(|p| {
            let Some(patch) = p.as_ref() else {
                return Vec::new();
            };
            let Ok(fields) = patch.message_fields(msg) else {
                return Vec::new();
            };
            let mut out = Vec::with_capacity(fields.len());
            for &fid in fields {
                if matches!(patch.field_is_deleted(fid), Ok(true)) {
                    continue;
                }
                out.push(fid);
            }
            out
        })
    });

    view! {
        <For
            each=move || fields.get()
            key=|fid| fid.as_inner()
            children=move |fid| view! {
                <FieldRow field=fid depth=depth />
            }
        />
    }
    .into_any()
}

#[component]
fn FieldRow(field: FieldId, depth: usize) -> AnyView {
    let workspace = expect_context::<WorkspaceState>();
    let ui = expect_context::<UiState>();
    let patch_state = workspace.patch_state;
    let selected = workspace.selected;
    let hovered = workspace.hovered;
    let expanded = workspace.expanded;
    let dirty_fields = workspace.dirty_fields;
    let toasts = ui.toasts;
    let next_toast_id = ui.next_toast_id;

    let tag_info = Memo::new(move |_| {
        patch_state.with(|p| {
            let patch = p.as_ref()?;
            let tag = patch.field_tag(field).ok()?;
            let n = tag.field_number().as_inner();
            let wt = tag.wire_type();
            Some((n, wt))
        })
    });

    let is_selected = move || selected.get() == Some(field);
    let is_expanded = move || expanded.with(|s| s.contains(&field));
    let is_dirty = move || dirty_fields.with(|s| s.contains(&field));

    let is_expandable =
        Memo::new(move |_| matches!(tag_info.get().map(|(_, wt)| wt), Some(WireType::Len)));

    let child_msg = Memo::new(move |_| {
        if !is_expanded() {
            return None;
        }
        patch_state.with(|p| {
            let patch = p.as_ref()?;
            patch.field_child_message(field).ok().flatten()
        })
    });

    let payload_summary = Memo::new(move |_| {
        patch_state.with(|p| {
            let Some(patch) = p.as_ref() else {
                return "—".to_string();
            };
            match tag_info.get() {
                Some((_n, WireType::Varint)) => match patch.varint(field) {
                    Ok(v) => format!("{v}"),
                    Err(_) => "varint(?)".to_string(),
                },
                Some((_n, WireType::Len)) => match patch.bytes(field) {
                    Ok(bytes) => format_len_summary(bytes),
                    Err(_) => "len(?)".to_string(),
                },
                Some((_n, WireType::I32)) => match fixed32_bits(patch, field) {
                    Ok(bits) => format!("0x{bits:08X}"),
                    Err(_) => "i32(?)".to_string(),
                },
                Some((_n, WireType::I64)) => match fixed64_bits(patch, field) {
                    Ok(bits) => format!("0x{bits:016X}"),
                    Err(_) => "i64(?)".to_string(),
                },
                None => "—".to_string(),
            }
        })
    });

    let badge_class = move || match tag_info.get().map(|(_, wt)| wt) {
        Some(WireType::Varint) => "tag-badge tag-badge--varint",
        Some(WireType::I64) => "tag-badge tag-badge--i64",
        Some(WireType::Len) => "tag-badge tag-badge--len",
        Some(WireType::I32) => "tag-badge tag-badge--i32",
        None => "tag-badge",
    };

    let badge_label = move || match tag_info.get() {
        Some((n, wt)) => format!("{n} {wt:?}"),
        None => "?".to_string(),
    };

    let row_class = move || {
        if is_selected() { "field-row field-row--selected" } else { "field-row" }
    };

    let indent_px = (depth as i32).saturating_mul(14);

    let on_toggle_expand = move |ev: leptos::ev::MouseEvent| {
        ev.stop_propagation();
        if !is_expandable.get() {
            return;
        }

        if is_expanded() {
            expanded.update(|s| {
                s.remove(&field);
            });
            return;
        }

        let mut parsed: Option<Result<MessageId, TreeError>> = None;
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
    };

    view! {
        <>
            <div
                class=row_class
                style:margin-left=format!("{indent_px}px")
                on:click=move |_| selected.set(Some(field))
                on:mouseenter=move |_| hovered.set(Some(field))
                on:mouseleave=move |_| hovered.set(None)
            >
                <span class="expand-toggle" on:click=on_toggle_expand>
                    <span class="dirty-dot">{move || if is_dirty() { "●" } else { "" }}</span>
                    <span class="expand-icon">
                        {move || {
                            if !is_expandable.get() {
                                return "".to_string();
                            }
                            if is_expanded() { "▾".to_string() } else { "▸".to_string() }
                        }}
                    </span>
                </span>
                <span class=badge_class>{badge_label}</span>
                <span class="payload-summary">{move || payload_summary.get()}</span>
            </div>

            <Show when=move || child_msg.get().is_some() fallback=|| ()>
                {move || {
                    let child = child_msg.get().expect("Show ensures child_msg is Some");
                    view! { <FieldTree msg=child depth=depth + 1 /> }
                }}
            </Show>
        </>
    }
    .into_any()
}

fn format_len_summary(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "0B".to_string();
    }

    let len = bytes.len();
    let mut prefix = len.to_string();
    prefix.push('B');

    if let Ok(s) = core::str::from_utf8(bytes) {
        let looks_printable = s.chars().all(|c| c.is_ascii_graphic() || c == ' ');
        if looks_printable {
            let preview: String = s.chars().take(32).collect();
            prefix.push_str(" \"");
            prefix.push_str(&preview);
            if preview.len() != s.len() {
                prefix.push('…');
            }
            prefix.push('"');
        }
    }

    prefix
}

fn fixed32_bits(patch: &Patch, field: FieldId) -> Result<u32, TreeError> {
    patch.i32_bits(field)
}

fn fixed64_bits(patch: &Patch, field: FieldId) -> Result<u64, TreeError> {
    patch.i64_bits(field)
}
