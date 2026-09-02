use crate::state::{UiState, WorkspaceState};
use crate::toast::ToastKind;
use crate::workspace::shown_children;
use leptos::html;
use leptos::prelude::*;
use protobuf_edit::session::Handle;
use protobuf_edit::wire::grouped::RecordKind;

/// One tree layer: the top layer for `parent == None`, a container's
/// interior otherwise.
#[component]
pub(crate) fn FieldTree(parent: Option<Handle>, depth: usize) -> AnyView {
    let workspace = expect_context::<WorkspaceState>();
    let session_state = workspace.session;

    let fields = Memo::new(move |_| {
        session_state.with(|s| {
            let Some(session) = s.as_ref() else {
                return Vec::new();
            };
            shown_children(session, parent).collect()
        })
    });

    view! {
        <For
            each=move || fields.get()
            key=|handle| *handle
            children=move |handle| view! {
                <FieldRow field=handle depth=depth />
            }
        />
    }
    .into_any()
}

#[component]
fn FieldRow(field: Handle, depth: usize) -> AnyView {
    let workspace = expect_context::<WorkspaceState>();
    let ui = expect_context::<UiState>();
    let session_state = workspace.session;
    let selected = workspace.selected;
    let hovered = workspace.hovered;
    let expanded = workspace.expanded;
    let parse_failed = workspace.parse_failed;
    let dirty_fields = workspace.dirty_fields;
    let toast = ui.toast;

    let tag_info = Memo::new(move |_| {
        session_state.with(|s| {
            let session = s.as_ref()?;
            let n = session.field(field).ok()?.as_inner();
            let kind = session.kind(field).ok()?;
            Some((n, kind))
        })
    });

    let is_selected = move || selected.get() == Some(field);
    let is_expanded = move || expanded.with(|s| s.contains(&field));
    let is_dirty = move || dirty_fields.with(|s| s.contains(&field));

    // The expand affordance of a container is three-state: undetermined
    // until a click settles it (a successful descend leaves children, a
    // faulted one lands in `parse_failed`), then definitely yes or no.
    // No payload pre-scan: the answer is revealed lazily.
    let is_failed = Memo::new(move |_| parse_failed.with(|s| s.contains(&field)));

    // Deliberately not a memo: expansion descends the container through
    // `try_update_untracked` (no session notification, to avoid a
    // whole-tree rerender), which would leave a memo stale on collapse.
    // The icon closure re-runs on every `expanded` change and reads the
    // current children then.
    let has_child = move || {
        session_state.with(|s| {
            s.as_ref().is_some_and(|session| shown_children(session, Some(field)).next().is_some())
        })
    };

    let is_expandable = Memo::new(move |_| {
        matches!(
            tag_info.get().map(|(_, kind)| kind),
            Some(RecordKind::Len | RecordKind::Group)
        ) && !is_failed.get()
    });

    let payload_summary = Memo::new(move |_| {
        session_state.with(|s| {
            let Some(session) = s.as_ref() else {
                return "—".to_string();
            };
            match tag_info.get() {
                Some((_n, RecordKind::Varint)) => session
                    .varint_word(field)
                    .map_or_else(|_| "varint(?)".to_string(), |v| format!("{v}")),
                Some((_n, RecordKind::Len)) => session
                    .payload_bytes(field)
                    .map_or_else(|_| "len(?)".to_string(), format_len_summary),
                Some((_n, RecordKind::I32)) => session
                    .i32_bits(field)
                    .map_or_else(|_| "i32(?)".to_string(), |bits| format!("0x{bits:08X}")),
                Some((_n, RecordKind::I64)) => session
                    .i64_bits(field)
                    .map_or_else(|_| "i64(?)".to_string(), |bits| format!("0x{bits:016X}")),
                Some((_n, RecordKind::Group)) => {
                    format!("group · {} field(s)", shown_children(session, Some(field)).count())
                }
                None => "—".to_string(),
            }
        })
    });

    let badge_class = move || match tag_info.get().map(|(_, kind)| kind) {
        Some(RecordKind::Varint) => "tag-badge tag-badge--varint",
        Some(RecordKind::I64) => "tag-badge tag-badge--i64",
        // Groups borrow the LEN palette: both are containers.
        Some(RecordKind::Len | RecordKind::Group) => "tag-badge tag-badge--len",
        Some(RecordKind::I32) => "tag-badge tag-badge--i32",
        None => "tag-badge",
    };

    let badge_label = move || match tag_info.get() {
        Some((n, kind)) => format!("{n} {kind}"),
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

        match crate::workspace::descend_untracked(session_state, field) {
            Ok(()) => expanded.update(|s| {
                s.insert(field);
            }),
            Err(e) => {
                // Settle the affordance as "no": the arrow disappears.
                parse_failed.update(|s| {
                    s.insert(field);
                });
                toast.show(ToastKind::Alert, format!("Failed to open container: {e}"));
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
                is_expanded().then(|| view! { <FieldTree parent=Some(field) depth=depth + 1 /> })
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
