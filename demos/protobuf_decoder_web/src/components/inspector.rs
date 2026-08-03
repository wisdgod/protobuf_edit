use crate::error::UiError;
use crate::state::{UiState, WorkspaceState};
use crate::toast::{ToastManager, ToastKind};
use base64::Engine as _;
use leptos::html;
use leptos::prelude::*;
use leptos_use::use_event_listener;
use protobuf_edit::patch::FieldId;
use protobuf_edit::{Buf, Patch, Tag, TreeError, WireType};

#[derive(Clone, Copy, PartialEq, Eq)]
enum BytesView {
    Hex,
    Utf8,
    Base64,
}

impl BytesView {
    const fn as_value(self) -> &'static str {
        match self {
            Self::Hex => "hex",
            Self::Utf8 => "utf8",
            Self::Base64 => "base64",
        }
    }

    fn from_value(value: &str) -> Option<Self> {
        match value {
            "hex" => Some(Self::Hex),
            "utf8" => Some(Self::Utf8),
            "base64" => Some(Self::Base64),
            _ => None,
        }
    }
}

/// Runs one edit against the live patch inside an ensured transaction.
///
/// Every mutating inspector action shares this shape; the transaction is
/// begun lazily so Ctrl+Z can roll all pending edits back to the last save.
fn edit_patch<T>(
    patch_state: RwSignal<Option<Patch>, LocalStorage>,
    f: impl FnOnce(&mut Patch) -> Result<T, TreeError>,
) -> Result<T, TreeError> {
    patch_state
        .try_update(|p| {
            let patch = p.as_mut().ok_or(TreeError::InvalidId)?;
            if !patch.txn_active() {
                patch.txn_begin();
            }
            f(patch)
        })
        .unwrap_or(Err(TreeError::InvalidId))
}

/// Multi-format preview line for a validated bytes payload.
fn bytes_hint(bytes: &[u8], current: BytesView) -> String {
    if bytes.len() > 4096 {
        return format!("{} byte(s) | preview skipped", bytes.len());
    }

    let mut parts: Vec<String> = Vec::new();
    parts.push(format!("{} byte(s)", bytes.len()));

    let utf8_result = core::str::from_utf8(bytes);
    let readable = utf8_result.is_ok_and(is_readable_utf8);

    if current != BytesView::Utf8 {
        match utf8_result {
            Ok(s) if readable => {
                parts.push(format!("utf8: \"{}\"", truncate_for_hint(s, 80)));
            }
            Ok(s) => {
                parts.push(format!("utf8 (unreadable): \"{}\"", truncate_for_hint(s, 40)));
            }
            Err(_) => {
                parts.push("utf8: invalid".to_string());
            }
        }
    }
    if current != BytesView::Hex {
        parts.push(format!("hex: {}", truncate_for_hint(&hex::encode(bytes), 80)));
    }
    if current != BytesView::Base64 {
        let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);
        parts.push(format!("base64: {}", truncate_for_hint(&b64, 80)));
    }
    parts.join(" | ")
}

/// Standard error line under an input, shown while its validation fails.
fn validation_error<T: Send + Sync + 'static>(
    validation: Memo<Result<Option<T>, UiError>>,
) -> impl IntoView {
    view! {
        <Show when=move || validation.with(Result::is_err) fallback=|| ()>
            <div class="inspector-error">
                {move || {
                    validation
                        .with(|v| v.as_ref().err().cloned())
                        .unwrap_or(UiError::Borrowed(""))
                }}
            </div>
        </Show>
    }
}

#[component]
pub(crate) fn InspectorDrawer() -> impl IntoView {
    let workspace = expect_context::<WorkspaceState>();
    let ui = expect_context::<UiState>();
    let patch_state = workspace.patch_state;
    let selected = workspace.selected;
    let expanded = workspace.expanded;
    let dirty_fields = workspace.dirty_fields;
    let inspector_open = workspace.inspector_open;
    let toast = ui.toast;
    let locale = ui.locale;
    let read_only = ui.read_only;

    let panel_ref = NodeRef::<html::Div>::new();
    let panel_height = workspace.inspector_height;
    let resizing = RwSignal::new(false);

    // Window-level listeners keep the drag alive outside the panel; mouseup
    // anywhere ends it. The panel bottom is anchored, so its rect bottom is
    // stable while dragging.
    let _stop_resize_move = use_event_listener(
        web_sys::window().expect("window is available"),
        leptos::ev::mousemove,
        move |ev: web_sys::MouseEvent| {
            if !resizing.get_untracked() {
                return;
            }
            let Some(el) = panel_ref.get() else {
                return;
            };
            let rect = el.get_bounding_client_rect();
            let max = el.parent_element().map_or(f64::MAX, |parent| {
                (parent.get_bounding_client_rect().height() - 120.0).max(120.0)
            });
            let h = (rect.bottom() - f64::from(ev.client_y())).clamp(120.0, max);
            panel_height.set(h);
        },
    );

    let _stop_resize_up = use_event_listener(
        web_sys::window().expect("window is available"),
        leptos::ev::mouseup,
        move |_| {
            if resizing.get_untracked() {
                resizing.set(false);
            }
        },
    );

    let varint_text = RwSignal::new(String::new());
    let bytes_view: RwSignal<BytesView> = RwSignal::new(BytesView::Hex);
    let bytes_text = RwSignal::new(String::new());
    let fixed_text = RwSignal::new(String::new());

    let varint_base: RwSignal<Option<u64>> = RwSignal::new(None);
    let fixed_base: RwSignal<Option<u64>> = RwSignal::new(None);

    let insert_field_number = RwSignal::new(String::new());
    let insert_wire: RwSignal<WireType> = RwSignal::new(WireType::Varint);
    let insert_varint_text = RwSignal::new(String::new());
    let insert_bytes_view: RwSignal<BytesView> = RwSignal::new(BytesView::Hex);
    let insert_bytes_text = RwSignal::new(String::new());
    let insert_fixed_text = RwSignal::new(String::new());

    let selected_wire = Memo::new(move |_| {
        let fid = selected.get()?;
        patch_state.with(|p| {
            let patch = p.as_ref()?;
            patch.field_tag(fid).ok().map(protobuf_edit::Tag::wire_type)
        })
    });

    // Backfills the editor inputs from the field's current value; shared by
    // the selection effect and Clear (which reverts to the source value).
    let refresh_from_patch = move |patch: &Patch, fid: FieldId| {
        let Ok(tag) = patch.field_tag(fid) else {
            return;
        };
        match tag.wire_type() {
            WireType::Varint => {
                if let Ok(v) = patch.varint(fid) {
                    varint_text.set(v.to_string());
                    varint_base.set(Some(v));
                }
            }
            WireType::Len => {
                if let Ok(bytes) = patch.bytes(fid) {
                    match core::str::from_utf8(bytes) {
                        Ok(s) if is_readable_utf8(s) => {
                            bytes_view.set(BytesView::Utf8);
                            bytes_text.set(s.to_string());
                        }
                        _ => {
                            bytes_view.set(BytesView::Hex);
                            bytes_text.set(hex::encode(bytes));
                        }
                    }
                }
            }
            WireType::I32 => {
                if let Ok(bits) = patch.i32_bits(fid) {
                    fixed_text.set(format!("0x{bits:08X}"));
                    fixed_base.set(Some(u64::from(bits)));
                }
            }
            WireType::I64 => {
                if let Ok(bits) = patch.i64_bits(fid) {
                    fixed_text.set(format!("0x{bits:016X}"));
                    fixed_base.set(Some(bits));
                }
            }
        }
    };

    Effect::new(move |_| {
        let Some(fid) = selected.get() else {
            varint_text.set(String::new());
            bytes_text.set(String::new());
            fixed_text.set(String::new());
            varint_base.set(None);
            fixed_base.set(None);
            return;
        };

        patch_state.with(|p| {
            if let Some(patch) = p.as_ref() {
                refresh_from_patch(patch, fid);
            }
        });
    });

    let clear_enabled = Memo::new(move |_| {
        let Some(fid) = selected.get() else {
            return false;
        };
        dirty_fields.with(|s| s.contains(&fid))
    });

    let varint_validation: Memo<Result<Option<u64>, UiError>> = Memo::new(move |_| {
        let Some(wt) = selected_wire.get() else {
            return Ok(None);
        };
        if wt != WireType::Varint {
            return Ok(None);
        }
        let raw = varint_text.get();
        let v = parse_u64(&raw)
            .map_err(|()| UiError::from("Invalid varint. Use decimal or 0x-prefixed hex."))?;
        Ok(Some(v))
    });

    let bytes_validation: Memo<Result<Option<Vec<u8>>, UiError>> = Memo::new(move |_| {
        let Some(wt) = selected_wire.get() else {
            return Ok(None);
        };
        if wt != WireType::Len {
            return Ok(None);
        }
        decode_bytes_view(&bytes_text.get(), bytes_view.get()).map(Some)
    });

    let fixed_validation: Memo<Result<Option<u64>, UiError>> = Memo::new(move |_| {
        let Some(wt) = selected_wire.get() else {
            return Ok(None);
        };
        if !matches!(wt, WireType::I32 | WireType::I64) {
            return Ok(None);
        }

        let raw = fixed_text.get();
        let v = parse_u64(&raw)
            .map_err(|()| UiError::from("Invalid fixed value. Use decimal or 0x-prefixed hex."))?;
        if wt == WireType::I32 && v > u64::from(u32::MAX) {
            return Err("Invalid fixed32: value out of range for u32.".into());
        }
        Ok(Some(v))
    });

    let apply_enabled = Memo::new(move |_| {
        let Some(wt) = selected_wire.get() else {
            return false;
        };

        match wt {
            WireType::Varint => {
                let Ok(Some(v)) = varint_validation.get() else {
                    return false;
                };
                let Some(base) = varint_base.get() else {
                    return true;
                };
                v != base
            }
            WireType::Len => {
                let Some(fid) = selected.get() else {
                    return false;
                };
                // `.with` avoids cloning the decoded payload on every
                // keystroke (Memo::get is clone semantics).
                bytes_validation.with(|v| {
                    let Ok(Some(bytes)) = v else {
                        return false;
                    };
                    patch_state.with(|p| {
                        p.as_ref().is_some_and(|patch| patch.bytes(fid) != Ok(bytes.as_slice()))
                    })
                })
            }
            WireType::I32 | WireType::I64 => {
                let Ok(Some(v)) = fixed_validation.get() else {
                    return false;
                };
                let Some(base) = fixed_base.get() else {
                    return true;
                };
                v != base
            }
        }
    });

    let on_apply = move |_| {
        if !apply_enabled.get_untracked() {
            return;
        }

        let Some(fid) = selected.get_untracked() else {
            return;
        };

        let Some(wt) = selected_wire.get_untracked() else {
            toast.show(ToastKind::Alert, "No field selected.");
            return;
        };

        // Reuse the validation memos: the inputs were already parsed for the
        // enabled state, so re-parsing here could only disagree with it.
        match wt {
            WireType::Varint => {
                let Ok(Some(value)) = varint_validation.get_untracked() else {
                    toast.show(
                        ToastKind::Alert,
                        "Invalid varint value. Use decimal or 0x-prefixed hex.",
                    );
                    return;
                };

                match edit_patch(patch_state, |patch| patch.set_varint(fid, value)) {
                    Ok(()) => {
                        dirty_fields.update(|s| {
                            s.insert(fid);
                        });
                        varint_base.set(Some(value));
                    }
                    Err(e) => toast.show(ToastKind::Alert, format!("Failed to apply edit: {e:?}")),
                }
            }
            WireType::Len => {
                let bytes = match bytes_validation.get_untracked() {
                    Ok(Some(bytes)) => bytes,
                    Ok(None) => return,
                    Err(msg) => {
                        toast.show(ToastKind::Alert, msg);
                        return;
                    }
                };

                let view = bytes_view.get_untracked();
                let canonical_text = match encode_bytes_view(&bytes, view) {
                    Ok(s) => s,
                    Err(msg) => {
                        toast.show(ToastKind::Alert, msg);
                        return;
                    }
                };

                let descendants = patch_state.with_untracked(|p| {
                    p.as_ref().map(|patch| collect_child_subtree(patch, fid)).unwrap_or_default()
                });

                let mut buf = Buf::new();
                if let Err(e) = buf.extend_from_slice(&bytes) {
                    toast.show(ToastKind::Alert, format!("Failed to allocate buffer: {e:?}"));
                    return;
                }

                match edit_patch(patch_state, |patch| patch.set_bytes(fid, buf)) {
                    Ok(()) => {
                        expanded.update(|s| {
                            s.remove(&fid);
                            for d in &descendants {
                                s.remove(d);
                            }
                        });
                        dirty_fields.update(|s| {
                            for d in &descendants {
                                s.remove(d);
                            }
                            s.insert(fid);
                        });
                        bytes_text.set(canonical_text);
                    }
                    Err(e) => toast.show(ToastKind::Alert, format!("Failed to apply edit: {e:?}")),
                }
            }
            WireType::I32 | WireType::I64 => {
                let Ok(Some(value)) = fixed_validation.get_untracked() else {
                    toast.show(
                        ToastKind::Alert,
                        "Invalid fixed value. Use decimal or 0x-prefixed hex.",
                    );
                    return;
                };

                let (res, text) = if wt == WireType::I32 {
                    let bits = value as u32;
                    (
                        edit_patch(patch_state, |patch| patch.set_i32_bits(fid, bits)),
                        format!("0x{bits:08X}"),
                    )
                } else {
                    (
                        edit_patch(patch_state, |patch| patch.set_i64_bits(fid, value)),
                        format!("0x{value:016X}"),
                    )
                };

                match res {
                    Ok(()) => {
                        dirty_fields.update(|s| {
                            s.insert(fid);
                        });
                        fixed_text.set(text);
                        fixed_base.set(Some(value));
                    }
                    Err(e) => toast.show(ToastKind::Alert, format!("Failed to apply edit: {e:?}")),
                }
            }
        }
    };

    let on_delete = move |_| {
        let Some(fid) = selected.get_untracked() else {
            return;
        };

        let descendants = patch_state.with_untracked(|p| {
            p.as_ref().map(|patch| collect_child_subtree(patch, fid)).unwrap_or_default()
        });

        match edit_patch(patch_state, |patch| patch.delete_field(fid)) {
            Ok(()) => {
                expanded.update(|s| {
                    s.remove(&fid);
                    for d in &descendants {
                        s.remove(d);
                    }
                });
                dirty_fields.update(|s| {
                    for d in &descendants {
                        s.remove(d);
                    }
                    s.insert(fid);
                });
                selected.set(None);
            }
            Err(e) => toast.show(ToastKind::Alert, format!("Failed to delete field: {e:?}")),
        }
    };

    let on_clear = move |_| {
        let Some(fid) = selected.get_untracked() else {
            return;
        };

        let (was_inserted, descendants) = patch_state.with_untracked(|p| {
            let Some(patch) = p.as_ref() else {
                return (false, Vec::new());
            };
            let was_inserted = matches!(patch.field_spans(fid), Ok(None));
            let descendants = collect_child_subtree(patch, fid);
            (was_inserted, descendants)
        });

        match edit_patch(patch_state, |patch| patch.clear_field_edit(fid)) {
            Ok(()) => {
                expanded.update(|s| {
                    s.remove(&fid);
                    for d in &descendants {
                        s.remove(d);
                    }
                });
                dirty_fields.update(|s| {
                    s.remove(&fid);
                    for d in &descendants {
                        s.remove(d);
                    }
                });

                if was_inserted {
                    selected.set(None);
                    return;
                }

                patch_state.with_untracked(|p| {
                    if let Some(patch) = p.as_ref() {
                        refresh_from_patch(patch, fid);
                    }
                });
            }
            Err(e) => toast.show(ToastKind::Alert, format!("Failed to clear edit: {e:?}")),
        }
    };

    let insert_target = Memo::new(move |_| {
        patch_state.with(|p| {
            let patch = p.as_ref()?;
            let Some(fid) = selected.get() else {
                return Some((patch.root(), "root message"));
            };

            if let Ok(tag) = patch.field_tag(fid)
                && tag.wire_type() == WireType::Len
                && expanded.with(|s| s.contains(&fid))
                && let Ok(Some(child)) = patch.field_child_message(fid)
            {
                return Some((child, "child message of selected field"));
            }

            let parent = patch.field_parent_message(fid).ok()?;
            Some((parent, "parent message of selected field"))
        })
    });

    let insert_tag_validation: Memo<Result<Option<Tag>, UiError>> = Memo::new(move |_| {
        if patch_state.with(std::option::Option::is_none) {
            return Ok(None);
        }

        let raw = insert_field_number.get();
        if raw.trim().is_empty() {
            return Ok(None);
        }

        let n64 = parse_u64(&raw)
            .map_err(|()| UiError::from("Invalid field number. Use decimal or 0x-prefixed hex."))?;
        let n: u32 = n64.try_into().map_err(|_| UiError::from("Field number out of range."))?;

        let wt = insert_wire.get();
        let tag = Tag::try_from_parts(n, wt)
            .ok_or_else(|| UiError::from("Field number must be in 1..=(1<<29)-1."))?;
        Ok(Some(tag))
    });

    let insert_varint_validation: Memo<Result<Option<u64>, UiError>> = Memo::new(move |_| {
        if patch_state.with(std::option::Option::is_none) {
            return Ok(None);
        }
        if insert_wire.get() != WireType::Varint {
            return Ok(None);
        }
        let raw = insert_varint_text.get();
        if raw.trim().is_empty() {
            return Ok(None);
        }
        let v = parse_u64(&raw)
            .map_err(|()| UiError::from("Invalid varint. Use decimal or 0x-prefixed hex."))?;
        Ok(Some(v))
    });

    let insert_bytes_validation: Memo<Result<Option<Vec<u8>>, UiError>> = Memo::new(move |_| {
        if patch_state.with(std::option::Option::is_none) {
            return Ok(None);
        }
        if insert_wire.get() != WireType::Len {
            return Ok(None);
        }
        decode_bytes_view(&insert_bytes_text.get(), insert_bytes_view.get()).map(Some)
    });

    let insert_fixed_validation: Memo<Result<Option<u64>, UiError>> = Memo::new(move |_| {
        if patch_state.with(std::option::Option::is_none) {
            return Ok(None);
        }

        let wt = insert_wire.get();
        if !matches!(wt, WireType::I32 | WireType::I64) {
            return Ok(None);
        }

        let raw = insert_fixed_text.get();
        if raw.trim().is_empty() {
            return Ok(None);
        }
        let v = parse_u64(&raw)
            .map_err(|()| UiError::from("Invalid fixed value. Use decimal or 0x-prefixed hex."))?;

        if wt == WireType::I32 && v > u64::from(u32::MAX) {
            return Err("Invalid fixed32: value out of range for u32.".into());
        }
        Ok(Some(v))
    });

    let insert_enabled = Memo::new(move |_| {
        if patch_state.with(std::option::Option::is_none) {
            return false;
        }
        let Ok(Some(_tag)) = insert_tag_validation.get() else {
            return false;
        };
        match insert_wire.get() {
            WireType::Varint => matches!(insert_varint_validation.get(), Ok(Some(_))),
            WireType::Len => matches!(insert_bytes_validation.get(), Ok(Some(_))),
            WireType::I32 | WireType::I64 => matches!(insert_fixed_validation.get(), Ok(Some(_))),
        }
    });

    let on_insert = move |_| {
        if !insert_enabled.get_untracked() {
            return;
        }

        let Some((target, _)) = insert_target.get_untracked() else {
            toast.show(ToastKind::Alert, "No data loaded.");
            return;
        };

        let Ok(Some(tag)) = insert_tag_validation.get_untracked() else {
            toast.show(ToastKind::Alert, "Invalid tag.");
            return;
        };

        let wt = insert_wire.get_untracked();

        let res = match wt {
            WireType::Varint => {
                let Ok(Some(value)) = insert_varint_validation.get_untracked() else {
                    toast.show(ToastKind::Alert, "Invalid varint.");
                    return;
                };
                edit_patch(patch_state, |patch| patch.insert_varint(target, tag, value))
            }
            WireType::Len => {
                let Ok(Some(bytes)) = insert_bytes_validation.get_untracked() else {
                    toast.show(ToastKind::Alert, "Invalid bytes payload.");
                    return;
                };

                let mut buf = Buf::new();
                if let Err(e) = buf.extend_from_slice(&bytes) {
                    toast.show(ToastKind::Alert, format!("Failed to allocate buffer: {e:?}"));
                    return;
                }

                edit_patch(patch_state, |patch| patch.insert_bytes(target, tag, buf))
            }
            WireType::I32 | WireType::I64 => {
                let Ok(Some(value)) = insert_fixed_validation.get_untracked() else {
                    toast.show(ToastKind::Alert, "Invalid fixed value.");
                    return;
                };
                if wt == WireType::I32 {
                    edit_patch(patch_state, |patch| {
                        patch.insert_i32_bits(target, tag, value as u32)
                    })
                } else {
                    edit_patch(patch_state, |patch| patch.insert_i64_bits(target, tag, value))
                }
            }
        };

        match res {
            Ok(fid) => {
                dirty_fields.update(|s| {
                    s.insert(fid);
                });
                selected.set(Some(fid));
            }
            Err(e) => toast.show(ToastKind::Alert, format!("Insert failed: {e:?}")),
        }
    };

    let meta = Memo::new(move |_| {
        let fid = selected.get()?;
        patch_state.with(|p| {
            let patch = p.as_ref()?;
            let tag = patch.field_tag(fid).ok()?;
            Some((fid, tag))
        })
    });

    let header_title = Memo::new(move |_| {
        let t = locale.get().t();
        if let Some((_fid, tag)) = meta.get() {
            let field_number = tag.field_number().as_inner();
            let wt = tag.wire_type();
            return format!("{}: {} {field_number} ({wt:?})", t.inspector, t.field);
        }
        t.inspector.to_string()
    });

    let on_close = UnsyncCallback::new(move |()| {
        selected.set(None);
        inspector_open.set(false);
    });

    let on_bytes_view_change = bytes_view_change_handler(bytes_view, bytes_text, toast);
    let on_insert_bytes_view_change =
        bytes_view_change_handler(insert_bytes_view, insert_bytes_text, toast);
    let on_insert_wire_change = UnsyncCallback::new(move |ev: leptos::ev::Event| {
        let v = event_target_value(&ev);
        let Some(wt) = wire_type_from_value(v.trim()) else {
            return;
        };
        insert_wire.set(wt);
    });

    let panel_header = move || {
        view! {
            <div class="inspector-panel-header">
                <div class="inspector-panel-title">{move || header_title.get()}</div>
                <div class="inspector-panel-actions">
                    <Show when=move || meta.get().is_some() fallback=|| ()>
                        <button class="btn btn--danger btn--small" on:click=on_delete>
                            {move || locale.get().t().delete_field}
                        </button>
                        <button
                            class="btn btn--secondary btn--small"
                            on:click=on_clear
                            disabled=move || !clear_enabled.get()
                        >
                            {move || locale.get().t().clear}
                        </button>
                        <button
                            class="btn btn--primary btn--small"
                            on:click=on_apply
                            disabled=move || !apply_enabled.get()
                        >
                            {move || locale.get().t().apply}
                        </button>
                    </Show>
                    <button
                        class="btn btn--secondary btn--small"
                        title=move || locale.get().t().close_deselect_title
                        on:click=move |_| on_close.run(())
                    >
                        "\u{00D7}"
                    </button>
                </div>
            </div>
        }
    };

    let selected_field_view = move || {
        // `Show` gates on `meta.is_some()`, but re-evaluation order between
        // `when` and children is not guaranteed; never panic here.
        let (_fid, tag) = meta.get()?;

        let wt = tag.wire_type();

        Some(view! {
            <>
                <div class="inspector-editor">
                    <Show when=move || wt == WireType::Varint fallback=|| ()>
                        <label class="inspector-label">"Varint"</label>
                        <input
                            class="input inspector-input"
                            prop:value=move || varint_text.get()
                            on:input=move |ev| varint_text.set(event_target_value(&ev))
                        />
                        {validation_error(varint_validation)}
                        <Show when=move || varint_validation.get().is_ok() fallback=|| ()>
                            <div class="inspector-hint">
                                {move || {
                                    let Ok(Some(v)) = varint_validation.get() else {
                                        return "—".to_string();
                                    };
                                    let zz = protobuf_edit::varint::zigzag_decode64(v);
                                    format!("zigzag i64: {zz} | hex: 0x{v:X}")
                                }}
                            </div>
                        </Show>
                    </Show>

                    <Show when=move || wt == WireType::Len fallback=|| ()>
                        <label class="inspector-label">"Bytes"</label>
                        <select
                            class="select inspector-select"
                            prop:value=move || bytes_view.get().as_value()
                            on:change=move |ev| on_bytes_view_change.run(ev)
                        >
                            <option value={BytesView::Hex.as_value()}>"Hex"</option>
                            <option value={BytesView::Utf8.as_value()}>"UTF-8"</option>
                            <option value={BytesView::Base64.as_value()}>"Base64"</option>
                        </select>
                        <textarea
                            class="input inspector-textarea"
                            prop:value=move || bytes_text.get()
                            on:input=move |ev| bytes_text.set(event_target_value(&ev))
                        />
                        {validation_error(bytes_validation)}
                        <Show when=move || bytes_validation.with(Result::is_ok) fallback=|| ()>
                            <div class="inspector-hint">
                                {move || {
                                    // `.with` keeps the (possibly large)
                                    // decoded payload unclones per keystroke.
                                    bytes_validation.with(|v| {
                                        let Ok(Some(bytes)) = v else {
                                            return "—".to_string();
                                        };
                                        bytes_hint(bytes, bytes_view.get())
                                    })
                                }}
                            </div>
                        </Show>
                    </Show>

                    <Show when=move || matches!(wt, WireType::I32 | WireType::I64) fallback=|| ()>
                        <label class="inspector-label">"Fixed"</label>
                        <input
                            class="input inspector-input"
                            prop:value=move || fixed_text.get()
                            on:input=move |ev| fixed_text.set(event_target_value(&ev))
                        />
                        {validation_error(fixed_validation)}
                        <Show when=move || fixed_validation.get().is_ok() fallback=|| ()>
                            <div class="inspector-hint">
                                {move || {
                                    let Ok(Some(v)) = fixed_validation.get() else {
                                        return "—".to_string();
                                    };
                                    match wt {
                                        WireType::I32 => {
                                            let bits = v as u32;
                                            let signed = bits as i32;
                                            let float = f32::from_bits(bits);
                                            format!("u32: {bits} | i32: {signed} | f32: {float}")
                                        }
                                        WireType::I64 => {
                                            let signed = v as i64;
                                            let float = f64::from_bits(v);
                                            format!("u64: {v} | i64: {signed} | f64: {float}")
                                        }
                                        _ => "—".to_string(),
                                    }
                                }}
                            </div>
                        </Show>
                    </Show>
                </div>
            </>
        })
    };

    let insert_section = move || {
        view! {
            <div class="inspector-section">
                <div class="inspector-header">
                    <div class="inspector-title">{move || locale.get().t().insert_field}</div>
                    <div class="inspector-actions">
                        <button
                            class="btn btn--primary"
                            on:click=on_insert
                            disabled=move || !insert_enabled.get()
                        >
                            {move || locale.get().t().insert}
                        </button>
                    </div>
                </div>

                <div class="inspector-meta">
                    <div>
                        {move || {
                            let t = locale.get().t();
                            insert_target
                                .get()
                                .map_or_else(
                                    || format!("{}: —", t.target),
                                    |(msg, label)| format!("{}: {label} ({msg:?})", t.target),
                                )
                        }}
                    </div>
                    <div>{move || locale.get().t().insert_span_note}</div>
                </div>

                <div class="inspector-editor">
                    <label class="inspector-label">{move || locale.get().t().field_number}</label>
                    <input
                        class="input inspector-input"
                        placeholder="1"
                        prop:value=move || insert_field_number.get()
                        on:input=move |ev| insert_field_number.set(event_target_value(&ev))
                    />
                    {validation_error(insert_tag_validation)}

                    <label class="inspector-label">{move || locale.get().t().wire_type}</label>
                    <select
                        class="select inspector-select"
                        prop:value=move || wire_type_value(insert_wire.get())
                        on:change=move |ev| on_insert_wire_change.run(ev)
                    >
                        <option value={wire_type_value(WireType::Varint)}>"Varint"</option>
                        <option value={wire_type_value(WireType::Len)}>"Len"</option>
                        <option value={wire_type_value(WireType::I32)}>"I32 (fixed32)"</option>
                        <option value={wire_type_value(WireType::I64)}>"I64 (fixed64)"</option>
                    </select>

                    <Show when=move || insert_wire.get() == WireType::Varint fallback=|| ()>
                        <label class="inspector-label">{move || locale.get().t().value}</label>
                        <input
                            class="input inspector-input"
                            placeholder="0"
                            prop:value=move || insert_varint_text.get()
                            on:input=move |ev| insert_varint_text.set(event_target_value(&ev))
                        />
                        {validation_error(insert_varint_validation)}
                        <Show
                            when=move || matches!(insert_varint_validation.get(), Ok(Some(_)))
                            fallback=|| ()
                        >
                            <div class="inspector-hint">
                                {move || {
                                    let Ok(Some(v)) = insert_varint_validation.get() else {
                                        return "—".to_string();
                                    };
                                    let zz = protobuf_edit::varint::zigzag_decode64(v);
                                    format!("zigzag i64: {zz} | hex: 0x{v:X}")
                                }}
                            </div>
                        </Show>
                    </Show>

                    <Show when=move || insert_wire.get() == WireType::Len fallback=|| ()>
                        <label class="inspector-label">"Bytes"</label>
                        <select
                            class="select inspector-select"
                            prop:value=move || insert_bytes_view.get().as_value()
                            on:change=move |ev| on_insert_bytes_view_change.run(ev)
                        >
                            <option value={BytesView::Hex.as_value()}>"Hex"</option>
                            <option value={BytesView::Utf8.as_value()}>"UTF-8"</option>
                            <option value={BytesView::Base64.as_value()}>"Base64"</option>
                        </select>
                        <textarea
                            class="input inspector-textarea"
                            prop:value=move || insert_bytes_text.get()
                            on:input=move |ev| insert_bytes_text.set(event_target_value(&ev))
                        />
                        {validation_error(insert_bytes_validation)}
                        <Show
                            when=move || matches!(insert_bytes_validation.get(), Ok(Some(_)))
                            fallback=|| ()
                        >
                            <div class="inspector-hint">
                                {move || {
                                    let Some(len) = insert_bytes_validation
                                        .with(|v| match v {
                                            Ok(Some(bytes)) => Some(bytes.len()),
                                            _ => None,
                                        })
                                    else {
                                        return "—".to_string();
                                    };
                                    format!("{len} byte(s)")
                                }}
                            </div>
                        </Show>
                    </Show>

                    <Show
                        when=move || matches!(insert_wire.get(), WireType::I32 | WireType::I64)
                        fallback=|| ()
                    >
                        <label class="inspector-label">{move || locale.get().t().bits}</label>
                        <input
                            class="input inspector-input"
                            placeholder="0x0"
                            prop:value=move || insert_fixed_text.get()
                            on:input=move |ev| insert_fixed_text.set(event_target_value(&ev))
                        />
                        {validation_error(insert_fixed_validation)}
                        <Show
                            when=move || matches!(insert_fixed_validation.get(), Ok(Some(_)))
                            fallback=|| ()
                        >
                            <div class="inspector-hint">
                                {move || {
                                    let Ok(Some(v)) = insert_fixed_validation.get() else {
                                        return "—".to_string();
                                    };
                                    match insert_wire.get() {
                                        WireType::I32 => {
                                            let bits = v as u32;
                                            format!("u32: {bits} | hex: 0x{bits:08X}")
                                        }
                                        WireType::I64 => format!("u64: {v} | hex: 0x{v:016X}"),
                                        _ => "—".to_string(),
                                    }
                                }}
                            </div>
                        </Show>
                    </Show>
                </div>
            </div>
        }
    };

    let body = move || {
        view! {
            <div class="inspector">
                <Show when=move || meta.get().is_some() fallback=|| ()>
                    {selected_field_view}
                </Show>
                {insert_section}
            </div>
        }
    };

    // The drawer only exists while there is something to show: a selected
    // field or the manually opened inspector. Read-only mode hides all
    // editing UI, so the drawer never mounts there.
    view! {
        <Show
            when=move || {
                !read_only.get() && (selected.get().is_some() || inspector_open.get())
            }
            fallback=|| ()
        >
            <div
                node_ref=panel_ref
                class="inspector-panel"
                style:height=move || format!("{:.0}px", panel_height.get())
            >
                <div
                    class="split-handle split-handle--h"
                    on:mousedown=move |ev: leptos::ev::MouseEvent| {
                        ev.prevent_default();
                        resizing.set(true);
                    }
                ></div>
                {panel_header}
                <div class="inspector-body">{body}</div>
            </div>
        </Show>
    }
}

fn bytes_view_change_handler(
    bytes_view: RwSignal<BytesView>,
    bytes_text: RwSignal<String>,
    toast: ToastManager,
) -> UnsyncCallback<leptos::ev::Event> {
    UnsyncCallback::new(move |ev: leptos::ev::Event| {
        let v = event_target_value(&ev);
        let Some(new_view) = BytesView::from_value(v.trim()) else {
            return;
        };
        let old_view = bytes_view.get_untracked();
        if new_view == old_view {
            return;
        }

        let raw = bytes_text.get_untracked();
        let bytes = match decode_bytes_view(&raw, old_view) {
            Ok(v) => v,
            Err(msg) => {
                toast.show(ToastKind::Alert, msg);
                return;
            }
        };
        let new_text = match encode_bytes_view(&bytes, new_view) {
            Ok(s) => s,
            Err(msg) => {
                toast.show(ToastKind::Alert, msg);
                return;
            }
        };
        bytes_view.set(new_view);
        bytes_text.set(new_text);
    })
}

fn parse_u64(text: &str) -> Result<u64, ()> {
    let t = text.trim();
    t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")).map_or_else(
        || t.parse::<u64>().map_err(|_| ()),
        |hex| u64::from_str_radix(hex, 16).map_err(|_| ()),
    )
}

fn decode_hex_bytes(text: &str) -> Result<Vec<u8>, ()> {
    let trimmed = text.trim();
    let no_ws: String = trimmed.chars().filter(|c| !c.is_whitespace()).collect();
    let hex = no_ws.strip_prefix("0x").or_else(|| no_ws.strip_prefix("0X")).unwrap_or(&no_ws);
    if hex.is_empty() {
        return Ok(Vec::new());
    }
    hex::decode(hex).map_err(|_| ())
}

fn decode_base64_bytes(text: &str) -> Result<Vec<u8>, UiError> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }

    let no_ws: String = trimmed.chars().filter(|c| !c.is_whitespace()).collect();
    if no_ws.is_empty() {
        return Ok(Vec::new());
    }

    if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(&no_ws) {
        return Ok(bytes);
    }
    if let Ok(bytes) = base64::engine::general_purpose::URL_SAFE.decode(&no_ws) {
        return Ok(bytes);
    }

    Err("Invalid base64.".into())
}

fn decode_bytes_view(text: &str, view: BytesView) -> Result<Vec<u8>, UiError> {
    match view {
        BytesView::Hex => {
            validate_hex_bytes(text, None)?;
            decode_hex_bytes(text).map_err(|()| "Invalid hex bytes.".into())
        }
        BytesView::Utf8 => Ok(text.as_bytes().to_vec()),
        BytesView::Base64 => decode_base64_bytes(text),
    }
}

fn encode_bytes_view(bytes: &[u8], view: BytesView) -> Result<String, &'static str> {
    match view {
        BytesView::Hex => Ok(hex::encode(bytes)),
        BytesView::Utf8 => core::str::from_utf8(bytes)
            .map(std::string::ToString::to_string)
            .map_err(|_| "Bytes are not valid UTF-8."),
        BytesView::Base64 => Ok(base64::engine::general_purpose::STANDARD.encode(bytes)),
    }
}

fn validate_hex_bytes(text: &str, exact_len: Option<usize>) -> Result<(), UiError> {
    let mut chars = text.chars().filter(|c| !c.is_whitespace());
    let first = chars.next();
    let second = chars.next();

    let mut digit_count: usize = 0;
    if first == Some('0') && matches!(second, Some('x' | 'X')) {
    } else {
        for c in [first, second].into_iter().flatten() {
            if !c.is_ascii_hexdigit() {
                return Err("Invalid hex: non-hex character.".into());
            }
            digit_count += 1;
        }
    }

    for c in chars {
        if !c.is_ascii_hexdigit() {
            return Err("Invalid hex: non-hex character.".into());
        }
        digit_count += 1;
    }

    if !digit_count.is_multiple_of(2) {
        return Err("Invalid hex: expected an even number of digits.".into());
    }

    let bytes_len = digit_count / 2;
    if let Some(exact) = exact_len
        && bytes_len != exact
    {
        return Err(format!("Invalid length: expected {exact} byte(s), got {bytes_len}.").into());
    }

    Ok(())
}

fn is_readable_utf8(s: &str) -> bool {
    s.chars().all(|ch| !ch.is_control() || ch == '\n' || ch == '\r' || ch == '\t')
}

fn truncate_for_hint(text: &str, max_chars: usize) -> String {
    let mut out = String::new();
    let mut iter = text.chars();
    for _ in 0..max_chars {
        let Some(c) = iter.next() else {
            return out;
        };
        out.push(c);
    }
    if iter.next().is_some() {
        out.push('…');
    }
    out
}

const fn wire_type_value(wt: WireType) -> &'static str {
    match wt {
        WireType::Varint => "varint",
        WireType::Len => "len",
        WireType::I32 => "i32",
        WireType::I64 => "i64",
    }
}

fn wire_type_from_value(value: &str) -> Option<WireType> {
    match value {
        "varint" => Some(WireType::Varint),
        "len" => Some(WireType::Len),
        "i32" => Some(WireType::I32),
        "i64" => Some(WireType::I64),
        _ => None,
    }
}

fn collect_reachable_fields(
    patch: &Patch,
    msg: protobuf_edit::patch::MessageId,
    out: &mut Vec<FieldId>,
) {
    let Ok(fields) = patch.message_fields(msg) else {
        return;
    };
    for fid in fields {
        out.push(fid);
        let Ok(Some(child)) = patch.field_child_message(fid) else {
            continue;
        };
        collect_reachable_fields(patch, child, out);
    }
}

fn collect_child_subtree(patch: &Patch, field: FieldId) -> Vec<FieldId> {
    let Ok(Some(child)) = patch.field_child_message(field) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    collect_reachable_fields(patch, child, &mut out);
    out
}
