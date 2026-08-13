use crate::state::{UiState, WorkspaceState};
use crate::toast::ToastKind;
use leptos::html;
use leptos::prelude::*;
use protobuf_edit::patch::{FieldId, MessageId};
use protobuf_edit::{Patch, TreeError, WireType};

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
            for fid in fields {
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
    let parse_failed = workspace.parse_failed;
    let dirty_fields = workspace.dirty_fields;
    let toast = ui.toast;

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

    // The expand affordance of a Len field is three-state: undetermined
    // until a click settles it (a successful parse leaves a child, a
    // failed one lands in `parse_failed`), then definitely yes or no.
    // No payload pre-scan: the answer is revealed lazily.
    let is_failed = Memo::new(move |_| parse_failed.with(|s| s.contains(&field)));

    // Deliberately not a memo: expansion parses the child through
    // `try_update_untracked` (no patch_state notification, to avoid a
    // whole-tree rerender), which would leave a memo stale on collapse.
    // The icon closure re-runs on every `expanded` change and reads the
    // current child then.
    let has_child = move || {
        patch_state.with(|p| {
            p.as_ref()
                .is_some_and(|patch| matches!(patch.field_child_message(field), Ok(Some(_))))
        })
    };

    let is_expandable = Memo::new(move |_| {
        matches!(tag_info.get().map(|(_, wt)| wt), Some(WireType::Len)) && !is_failed.get()
    });

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
                Some((_n, WireType::Varint)) => {
                    patch.varint(field).map_or_else(|_| "varint(?)".to_string(), |v| format!("{v}"))
                }
                Some((_n, WireType::Len)) => {
                    patch.bytes(field).map_or_else(|_| "len(?)".to_string(), format_len_summary)
                }
                Some((_n, WireType::I32)) => fixed32_bits(patch, field)
                    .map_or_else(|_| "i32(?)".to_string(), |bits| format!("0x{bits:08X}")),
                Some((_n, WireType::I64)) => fixed64_bits(patch, field)
                    .map_or_else(|_| "i64(?)".to_string(), |bits| format!("0x{bits:016X}")),
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

    // Keep the selected row visible during keyboard navigation; `nearest`
    // makes this a no-op when the row is already on screen (mouse clicks).
    let row_ref = NodeRef::<html::Div>::new();
    Effect::new(move |_| {
        if selected.get() != Some(field) {
            return;
        }
        if let Some(el) = row_ref.get() {
            let options = web_sys::ScrollIntoViewOptions::new();
            options.set_block(web_sys::ScrollLogicalPosition::Nearest);
            el.scroll_into_view_with_scroll_into_view_options(&options);
        }
    });

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

        match crate::workspace::parse_child_untracked(patch_state, field) {
            Ok(_child) => expanded.update(|s| {
                s.insert(field);
            }),
            Err(e) => {
                // Settle the affordance as "no": the arrow disappears.
                parse_failed.update(|s| {
                    s.insert(field);
                });
                toast.show(ToastKind::Alert, format!("Failed to parse child message: {e:?}"));
            }
        }
    };

    view! {
        <>
            <div
                node_ref=row_ref
                class=row_class
                style:margin-left=format!("{indent_px}px")
                on:click=move |_| selected.set(Some(field))
                on:mouseenter=move |_| hovered.set(Some(field))
                on:mouseleave=move |_| hovered.set(None)
            >
                <span class="expand-toggle" on:click=on_toggle_expand>
                    <span class="dirty-dot">{move || if is_dirty() { "●" } else { "" }}</span>
                    <span class=move || {
                        // Hollow glyph alone is hard to tell from the
                        // solid one at this size; the dimmed class is
                        // the second, load-bearing signal.
                        if is_expandable.get() && !is_expanded() && !has_child() {
                            "expand-icon expand-icon--maybe"
                        } else {
                            "expand-icon"
                        }
                    }>
                        {move || {
                            if !is_expandable.get() {
                                ""
                            } else if is_expanded() {
                                "▾"
                            } else if has_child() {
                                "▸"
                            } else {
                                // Undetermined: hollow (same-size white
                                // variant of U+25B8) until a click
                                // settles it as solid or gone.
                                "▹"
                            }
                        }}
                    </span>
                </span>
                <span class=badge_class>{badge_label}</span>
                <span class="payload-summary">{move || payload_summary.get()}</span>
            </div>

            {move || {
                child_msg.get().map(|child| view! { <FieldTree msg=child depth=depth + 1 /> })
            }}
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

    if let Some(text) = printable_ascii(bytes) {
        let cut = text.len().min(32);
        prefix.push_str(" \"");
        prefix.push_str(&text[..cut]);
        if cut != text.len() {
            prefix.push('…');
        }
        prefix.push('"');
    }

    prefix
}

/// Views `bytes` as a string when every byte is printable ASCII
/// (0x20..=0x7E) — the summary-preview gate. Runs on every rendered
/// Len field, so it is one byte scan with early exit instead of a
/// UTF-8 pass plus a per-char printability pass: all-printable-ASCII
/// input is valid UTF-8 by construction.
fn printable_ascii(bytes: &[u8]) -> Option<&str> {
    if bytes.iter().any(|&b| !matches!(b, 0x20..=0x7E)) {
        return None;
    }
    // SAFETY: ASCII-only bytes are valid UTF-8.
    Some(unsafe { core::str::from_utf8_unchecked(bytes) })
}

fn fixed32_bits(patch: &Patch, field: FieldId) -> Result<u32, TreeError> {
    patch.i32_bits(field)
}

fn fixed64_bits(patch: &Patch, field: FieldId) -> Result<u64, TreeError> {
    patch.i64_bits(field)
}
