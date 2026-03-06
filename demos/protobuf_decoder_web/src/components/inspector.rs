use crate::error::UiError;
use crate::state::{UiState, WorkspaceState};
use crate::toast::{show_toast, Toast, ToastKind};
use base64::Engine as _;
use leptos::prelude::*;
use protobuf_edit::{Buf, FieldId, Patch, Tag, TreeError, WireType};

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

#[component]
pub(crate) fn InspectorDrawer() -> impl IntoView {
    let workspace = expect_context::<WorkspaceState>();
    let ui = expect_context::<UiState>();
    let patch_state = workspace.patch_state;
    let read_only = workspace.read_only;
    let selected = workspace.selected;
    let expanded = workspace.expanded;
    let dirty_fields = workspace.dirty_fields;
    let toasts = ui.toasts;
    let next_toast_id = ui.next_toast_id;
    let collapsed = RwSignal::new(false);

    let varint_text = RwSignal::new(String::new());
    let bytes_view: RwSignal<BytesView> = RwSignal::new(BytesView::Hex);
    let bytes_text = RwSignal::new(String::new());
    let fixed_text = RwSignal::new(String::new());

    let varint_base: RwSignal<Option<u64>> = RwSignal::new(None);
    let bytes_base: RwSignal<Vec<u8>> = RwSignal::new(Vec::new());
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
            patch.field_tag(fid).ok().map(|tag| tag.wire_type())
        })
    });

    Effect::new(move |_| {
        let Some(fid) = selected.get() else {
            varint_text.set(String::new());
            bytes_text.set(String::new());
            fixed_text.set(String::new());
            varint_base.set(None);
            bytes_base.set(Vec::new());
            fixed_base.set(None);
            return;
        };

        patch_state.with(|p| {
            let Some(patch) = p.as_ref() else {
                return;
            };
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
                        let owned = bytes.to_vec();
                        if let Ok(s) = core::str::from_utf8(&owned) {
                            bytes_view.set(BytesView::Utf8);
                            bytes_text.set(s.to_string());
                        } else {
                            bytes_view.set(BytesView::Hex);
                            bytes_text.set(hex::encode(&owned));
                        }
                        bytes_base.set(owned);
                    }
                }
                WireType::I32 => {
                    if let Ok(bits) = patch.i32_bits(fid) {
                        fixed_text.set(format!("0x{bits:08X}"));
                        fixed_base.set(Some(bits as u64));
                    }
                }
                WireType::I64 => {
                    if let Ok(bits) = patch.i64_bits(fid) {
                        fixed_text.set(format!("0x{bits:016X}"));
                        fixed_base.set(Some(bits));
                    }
                }
            }
        });
    });

    let clear_enabled = Memo::new(move |_| {
        if read_only.get() {
            return false;
        }
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
            .map_err(|_| UiError::from("Invalid varint. Use decimal or 0x-prefixed hex."))?;
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
            .map_err(|_| UiError::from("Invalid fixed value. Use decimal or 0x-prefixed hex."))?;
        if wt == WireType::I32 && v > u32::MAX as u64 {
            return Err("Invalid fixed32: value out of range for u32.".into());
        }
        Ok(Some(v))
    });

    let apply_enabled = Memo::new(move |_| {
        if read_only.get() {
            return false;
        }
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
                let Ok(Some(bytes)) = bytes_validation.get() else {
                    return false;
                };
                bytes_base.with(|base| bytes.as_slice() != base.as_slice())
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
        if read_only.get() {
            show_toast(
                toasts,
                next_toast_id,
                ToastKind::Error,
                "Envelope frame view is read-only. Extract the frame to a message to edit.",
            );
            return;
        }
        if !apply_enabled.get_untracked() {
            return;
        }

        let Some(fid) = selected.get_untracked() else {
            return;
        };

        let Some(wt) = selected_wire.get_untracked() else {
            show_toast(toasts, next_toast_id, ToastKind::Error, "No field selected.");
            return;
        };

        match wt {
            WireType::Varint => {
                let raw = varint_text.get_untracked();
                let Ok(value) = parse_u64(&raw) else {
                    show_toast(
                        toasts,
                        next_toast_id,
                        ToastKind::Error,
                        "Invalid varint value. Use decimal or 0x-prefixed hex.",
                    );
                    return;
                };

                let mut res: Option<Result<(), TreeError>> = None;
                patch_state.update(|p| {
                    let Some(patch) = p.as_mut() else {
                        res = Some(Err(TreeError::DecodeError));
                        return;
                    };
                    if !patch.txn_active() {
                        patch.txn_begin();
                    }
                    res = Some(patch.set_varint(fid, value));
                });

                match res.unwrap_or(Err(TreeError::DecodeError)) {
                    Ok(()) => {
                        dirty_fields.update(|s| {
                            s.insert(fid);
                        });
                        varint_base.set(Some(value));
                        show_toast(
                            toasts,
                            next_toast_id,
                            ToastKind::Success,
                            format!("Applied varint edit: {value}."),
                        );
                    }
                    Err(e) => show_toast(
                        toasts,
                        next_toast_id,
                        ToastKind::Error,
                        format!("Failed to apply edit: {e:?}"),
                    ),
                }
            }
            WireType::Len => {
                let raw = bytes_text.get_untracked();
                let view = bytes_view.get_untracked();
                let bytes = match decode_bytes_view(&raw, view) {
                    Ok(v) => v,
                    Err(msg) => {
                        show_toast(toasts, next_toast_id, ToastKind::Error, msg);
                        return;
                    }
                };

                let canonical_text = match encode_bytes_view(&bytes, view) {
                    Ok(s) => s,
                    Err(msg) => {
                        show_toast(toasts, next_toast_id, ToastKind::Error, msg);
                        return;
                    }
                };

                let bytes_len = bytes.len();

                let descendants = patch_state.with(|p| {
                    let Some(patch) = p.as_ref() else {
                        return Vec::new();
                    };
                    collect_child_subtree(patch, fid)
                });

                let mut buf = Buf::new();
                if let Err(e) = buf.extend_from_slice(&bytes) {
                    show_toast(
                        toasts,
                        next_toast_id,
                        ToastKind::Error,
                        format!("Failed to allocate buffer: {e:?}"),
                    );
                    return;
                }

                let mut res: Option<Result<(), TreeError>> = None;
                patch_state.update(|p| {
                    let Some(patch) = p.as_mut() else {
                        res = Some(Err(TreeError::DecodeError));
                        return;
                    };
                    if !patch.txn_active() {
                        patch.txn_begin();
                    }
                    res = Some(patch.set_bytes(fid, buf));
                });

                match res.unwrap_or(Err(TreeError::DecodeError)) {
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
                        bytes_base.set(bytes);
                        show_toast(
                            toasts,
                            next_toast_id,
                            ToastKind::Success,
                            format!("Applied bytes edit: {bytes_len} byte(s)."),
                        );
                    }
                    Err(e) => show_toast(
                        toasts,
                        next_toast_id,
                        ToastKind::Error,
                        format!("Failed to apply edit: {e:?}"),
                    ),
                }
            }
            WireType::I32 => {
                let raw = fixed_text.get_untracked();
                let Ok(value) = parse_u64(&raw) else {
                    show_toast(
                        toasts,
                        next_toast_id,
                        ToastKind::Error,
                        "Invalid fixed32 value. Use decimal or 0x-prefixed hex.",
                    );
                    return;
                };

                if value > u32::MAX as u64 {
                    show_toast(toasts, next_toast_id, ToastKind::Error, "Fixed32 out of range.");
                    return;
                }
                let bits = value as u32;

                let mut res: Option<Result<(), TreeError>> = None;
                patch_state.update(|p| {
                    let Some(patch) = p.as_mut() else {
                        res = Some(Err(TreeError::DecodeError));
                        return;
                    };
                    if !patch.txn_active() {
                        patch.txn_begin();
                    }
                    res = Some(patch.set_i32_bits(fid, bits));
                });

                match res.unwrap_or(Err(TreeError::DecodeError)) {
                    Ok(()) => {
                        dirty_fields.update(|s| {
                            s.insert(fid);
                        });
                        fixed_text.set(format!("0x{bits:08X}"));
                        fixed_base.set(Some(value));
                        show_toast(
                            toasts,
                            next_toast_id,
                            ToastKind::Success,
                            format!("Applied fixed32 edit: 0x{bits:08X}."),
                        );
                    }
                    Err(e) => show_toast(
                        toasts,
                        next_toast_id,
                        ToastKind::Error,
                        format!("Failed to apply edit: {e:?}"),
                    ),
                }
            }
            WireType::I64 => {
                let raw = fixed_text.get_untracked();
                let Ok(value) = parse_u64(&raw) else {
                    show_toast(
                        toasts,
                        next_toast_id,
                        ToastKind::Error,
                        "Invalid fixed64 value. Use decimal or 0x-prefixed hex.",
                    );
                    return;
                };

                let mut res: Option<Result<(), TreeError>> = None;
                patch_state.update(|p| {
                    let Some(patch) = p.as_mut() else {
                        res = Some(Err(TreeError::DecodeError));
                        return;
                    };
                    if !patch.txn_active() {
                        patch.txn_begin();
                    }
                    res = Some(patch.set_i64_bits(fid, value));
                });

                match res.unwrap_or(Err(TreeError::DecodeError)) {
                    Ok(()) => {
                        dirty_fields.update(|s| {
                            s.insert(fid);
                        });
                        fixed_text.set(format!("0x{value:016X}"));
                        fixed_base.set(Some(value));
                        show_toast(
                            toasts,
                            next_toast_id,
                            ToastKind::Success,
                            format!("Applied fixed64 edit: 0x{value:016X}."),
                        );
                    }
                    Err(e) => show_toast(
                        toasts,
                        next_toast_id,
                        ToastKind::Error,
                        format!("Failed to apply edit: {e:?}"),
                    ),
                }
            }
        }
    };

    let on_delete = move |_| {
        if read_only.get() {
            show_toast(
                toasts,
                next_toast_id,
                ToastKind::Error,
                "Envelope frame view is read-only. Extract the frame to a message to edit.",
            );
            return;
        }
        let Some(fid) = selected.get_untracked() else {
            return;
        };

        let descendants = patch_state.with(|p| {
            let Some(patch) = p.as_ref() else {
                return Vec::new();
            };
            collect_child_subtree(patch, fid)
        });

        let mut res: Option<Result<(), TreeError>> = None;
        patch_state.update(|p| {
            let Some(patch) = p.as_mut() else {
                res = Some(Err(TreeError::DecodeError));
                return;
            };
            if !patch.txn_active() {
                patch.txn_begin();
            }
            res = Some(patch.delete_field(fid));
        });

        match res.unwrap_or(Err(TreeError::DecodeError)) {
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
                show_toast(toasts, next_toast_id, ToastKind::Success, "Deleted field.");
            }
            Err(e) => show_toast(
                toasts,
                next_toast_id,
                ToastKind::Error,
                format!("Failed to delete field: {e:?}"),
            ),
        }
    };

    let on_clear = move |_| {
        if read_only.get() {
            show_toast(
                toasts,
                next_toast_id,
                ToastKind::Error,
                "Envelope frame view is read-only. Extract the frame to a message to edit.",
            );
            return;
        }
        let Some(fid) = selected.get_untracked() else {
            return;
        };

        let (was_inserted, descendants) = patch_state.with(|p| {
            let Some(patch) = p.as_ref() else {
                return (false, Vec::new());
            };
            let was_inserted = matches!(patch.field_spans(fid), Ok(None));
            let descendants = collect_child_subtree(patch, fid);
            (was_inserted, descendants)
        });

        let mut res: Option<Result<(), TreeError>> = None;
        patch_state.update(|p| {
            let Some(patch) = p.as_mut() else {
                res = Some(Err(TreeError::DecodeError));
                return;
            };
            if !patch.txn_active() {
                patch.txn_begin();
            }
            res = Some(patch.clear_field_edit(fid));
        });

        match res.unwrap_or(Err(TreeError::DecodeError)) {
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
                    show_toast(
                        toasts,
                        next_toast_id,
                        ToastKind::Success,
                        "Removed inserted field.",
                    );
                    return;
                }

                patch_state.with(|p| {
                    let Some(patch) = p.as_ref() else {
                        return;
                    };
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
                                bytes_view.set(BytesView::Hex);
                                let owned = bytes.to_vec();
                                bytes_text.set(hex::encode(&owned));
                                bytes_base.set(owned);
                            }
                        }
                        WireType::I32 => {
                            if let Ok(bits) = patch.i32_bits(fid) {
                                fixed_text.set(format!("0x{bits:08X}"));
                                fixed_base.set(Some(bits as u64));
                            }
                        }
                        WireType::I64 => {
                            if let Ok(bits) = patch.i64_bits(fid) {
                                fixed_text.set(format!("0x{bits:016X}"));
                                fixed_base.set(Some(bits));
                            }
                        }
                    }
                });

                show_toast(toasts, next_toast_id, ToastKind::Success, "Cleared field edit.");
            }
            Err(e) => show_toast(
                toasts,
                next_toast_id,
                ToastKind::Error,
                format!("Failed to clear edit: {e:?}"),
            ),
        }
    };

    let on_parse_child = move |_| {
        let Some(fid) = selected.get_untracked() else {
            return;
        };

        let Some(wt) = selected_wire.get_untracked() else {
            return;
        };
        if wt != WireType::Len {
            return;
        }

        let mut res: Option<Result<(), TreeError>> = None;
        patch_state.update(|p| {
            let Some(patch) = p.as_mut() else {
                res = Some(Err(TreeError::DecodeError));
                return;
            };
            res = Some(patch.parse_child_message(fid).map(|_| ()));
        });

        match res.unwrap_or(Err(TreeError::DecodeError)) {
            Ok(()) => {
                expanded.update(|s| {
                    s.insert(fid);
                });
            }
            Err(e) => show_toast(
                toasts,
                next_toast_id,
                ToastKind::Error,
                format!("Failed to parse as message: {e:?}"),
            ),
        }
    };

    let insert_target = Memo::new(move |_| {
        patch_state.with(|p| {
            let patch = p.as_ref()?;
            let Some(fid) = selected.get() else {
                return Some((patch.root(), "root message".to_string()));
            };

            if let Ok(tag) = patch.field_tag(fid)
                && tag.wire_type() == WireType::Len
                && expanded.with(|s| s.contains(&fid))
                && let Ok(Some(child)) = patch.field_child_message(fid)
            {
                return Some((child, "child message of selected field".to_string()));
            }

            let parent = patch.field_parent_message(fid).ok()?;
            Some((parent, "parent message of selected field".to_string()))
        })
    });

    let insert_tag_validation: Memo<Result<Option<Tag>, UiError>> = Memo::new(move |_| {
        if patch_state.with(|p| p.is_none()) {
            return Ok(None);
        }

        let raw = insert_field_number.get();
        if raw.trim().is_empty() {
            return Ok(None);
        }

        let n64 = parse_u64(&raw)
            .map_err(|_| UiError::from("Invalid field number. Use decimal or 0x-prefixed hex."))?;
        let n: u32 = n64.try_into().map_err(|_| UiError::from("Field number out of range."))?;

        let wt = insert_wire.get();
        let tag = Tag::try_from_parts(n, wt)
            .ok_or_else(|| UiError::from("Field number must be in 1..=(1<<29)-1."))?;
        Ok(Some(tag))
    });

    let insert_varint_validation: Memo<Result<Option<u64>, UiError>> = Memo::new(move |_| {
        if patch_state.with(|p| p.is_none()) {
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
            .map_err(|_| UiError::from("Invalid varint. Use decimal or 0x-prefixed hex."))?;
        Ok(Some(v))
    });

    let insert_bytes_validation: Memo<Result<Option<Vec<u8>>, UiError>> = Memo::new(move |_| {
        if patch_state.with(|p| p.is_none()) {
            return Ok(None);
        }
        if insert_wire.get() != WireType::Len {
            return Ok(None);
        }
        decode_bytes_view(&insert_bytes_text.get(), insert_bytes_view.get()).map(Some)
    });

    let insert_fixed_validation: Memo<Result<Option<u64>, UiError>> = Memo::new(move |_| {
        if patch_state.with(|p| p.is_none()) {
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
            .map_err(|_| UiError::from("Invalid fixed value. Use decimal or 0x-prefixed hex."))?;

        if wt == WireType::I32 && v > u32::MAX as u64 {
            return Err("Invalid fixed32: value out of range for u32.".into());
        }
        Ok(Some(v))
    });

    let insert_enabled = Memo::new(move |_| {
        if read_only.get() {
            return false;
        }
        if patch_state.with(|p| p.is_none()) {
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
        if read_only.get() {
            show_toast(
                toasts,
                next_toast_id,
                ToastKind::Error,
                "Envelope frame view is read-only. Extract the frame to a message to edit.",
            );
            return;
        }
        if !insert_enabled.get_untracked() {
            return;
        }

        let Some((target, target_label)) = insert_target.get_untracked() else {
            show_toast(toasts, next_toast_id, ToastKind::Error, "No data loaded.");
            return;
        };

        let Ok(Some(tag)) = insert_tag_validation.get_untracked() else {
            show_toast(toasts, next_toast_id, ToastKind::Error, "Invalid tag.");
            return;
        };

        let wt = insert_wire.get_untracked();

        let mut res: Option<Result<FieldId, TreeError>> = None;
        match wt {
            WireType::Varint => {
                let Ok(Some(value)) = insert_varint_validation.get_untracked() else {
                    show_toast(toasts, next_toast_id, ToastKind::Error, "Invalid varint.");
                    return;
                };
                patch_state.update(|p| {
                    let Some(patch) = p.as_mut() else {
                        res = Some(Err(TreeError::DecodeError));
                        return;
                    };
                    if !patch.txn_active() {
                        patch.txn_begin();
                    }
                    res = Some(patch.insert_varint(target, tag, value));
                });
            }
            WireType::Len => {
                let Ok(Some(bytes)) = insert_bytes_validation.get_untracked() else {
                    show_toast(toasts, next_toast_id, ToastKind::Error, "Invalid bytes payload.");
                    return;
                };

                let mut buf = Buf::new();
                if let Err(e) = buf.extend_from_slice(&bytes) {
                    show_toast(
                        toasts,
                        next_toast_id,
                        ToastKind::Error,
                        format!("Failed to allocate buffer: {e:?}"),
                    );
                    return;
                }

                patch_state.update(|p| {
                    let Some(patch) = p.as_mut() else {
                        res = Some(Err(TreeError::DecodeError));
                        return;
                    };
                    if !patch.txn_active() {
                        patch.txn_begin();
                    }
                    res = Some(patch.insert_bytes(target, tag, buf));
                });
            }
            WireType::I32 => {
                let Ok(Some(value)) = insert_fixed_validation.get_untracked() else {
                    show_toast(toasts, next_toast_id, ToastKind::Error, "Invalid fixed value.");
                    return;
                };
                if value > u32::MAX as u64 {
                    show_toast(toasts, next_toast_id, ToastKind::Error, "Fixed32 out of range.");
                    return;
                }
                let bits = value as u32;
                patch_state.update(|p| {
                    let Some(patch) = p.as_mut() else {
                        res = Some(Err(TreeError::DecodeError));
                        return;
                    };
                    if !patch.txn_active() {
                        patch.txn_begin();
                    }
                    res = Some(patch.insert_i32_bits(target, tag, bits));
                });
            }
            WireType::I64 => {
                let Ok(Some(value)) = insert_fixed_validation.get_untracked() else {
                    show_toast(toasts, next_toast_id, ToastKind::Error, "Invalid fixed value.");
                    return;
                };
                patch_state.update(|p| {
                    let Some(patch) = p.as_mut() else {
                        res = Some(Err(TreeError::DecodeError));
                        return;
                    };
                    if !patch.txn_active() {
                        patch.txn_begin();
                    }
                    res = Some(patch.insert_i64_bits(target, tag, value));
                });
            }
        }

        match res.unwrap_or(Err(TreeError::DecodeError)) {
            Ok(fid) => {
                dirty_fields.update(|s| {
                    s.insert(fid);
                });
                selected.set(Some(fid));
                let field_number = tag.field_number().as_inner();
                show_toast(
                    toasts,
                    next_toast_id,
                    ToastKind::Success,
                    format!("Inserted field {field_number} ({wt:?}) into {target_label}."),
                );
            }
            Err(e) => {
                show_toast(toasts, next_toast_id, ToastKind::Error, format!("Insert failed: {e:?}"))
            }
        }
    };

    let meta = Memo::new(move |_| {
        let fid = selected.get()?;

        patch_state.with(|p| {
            let patch = p.as_ref()?;

            let tag = patch.field_tag(fid).ok()?;
            let parent = patch.field_parent_message(fid).ok()?;
            let spans = patch.field_spans(fid).ok().flatten();
            let root_spans = patch.field_root_spans(fid).ok().flatten();

            let payload_len = match tag.wire_type() {
                WireType::Varint => patch.varint(fid).ok().map(|v| encoded_len_varint(v) as u32),
                WireType::Len => patch.bytes(fid).ok().map(|b| b.len() as u32),
                WireType::I32 => Some(4),
                WireType::I64 => Some(8),
            };

            Some((fid, tag, parent, spans, root_spans, payload_len))
        })
    });

    let header_title = Memo::new(move |_| {
        if let Some((_fid, tag, _parent, _spans, _root_spans, _payload_len)) = meta.get() {
            let field_number = tag.field_number().as_inner();
            let wt = tag.wire_type();
            return format!("Inspector: Field {field_number} ({wt:?})");
        }
        "Inspector".to_string()
    });

    let on_toggle_collapsed = UnsyncCallback::new(move |_| {
        collapsed.update(|v| *v = !*v);
    });

    let on_bytes_view_change =
        bytes_view_change_handler(bytes_view, bytes_text, toasts, next_toast_id);
    let on_insert_bytes_view_change =
        bytes_view_change_handler(insert_bytes_view, insert_bytes_text, toasts, next_toast_id);
    let on_insert_wire_change = UnsyncCallback::new(move |ev: leptos::ev::Event| {
        let v = event_target_value(&ev);
        let Some(wt) = wire_type_from_value(v.trim()) else {
            return;
        };
        insert_wire.set(wt);
    });

    let empty_view = move || {
        view! {
            <div class="inspector-empty">
                {move || {
                    if selected.get().is_some() {
                        "No field selected."
                    } else {
                        "Select a field to inspect."
                    }
                }}
            </div>
        }
    };

    let panel_header = view! {
        <div class="inspector-panel-header">
            <div class="inspector-panel-title">{move || header_title.get()}</div>
            <div class="inspector-panel-actions">
                <button
                    class="btn btn--secondary"
                    on:click=move |_| on_toggle_collapsed.run(())
                >
                    {move || if collapsed.get() { "Show" } else { "Hide" }}
                </button>
                <Show when=move || !collapsed.get() && meta.get().is_some() fallback=|| ()>
                    <button
                        class="btn btn--danger"
                        on:click=on_delete
                        disabled=move || read_only.get()
                    >
                        "Delete"
                    </button>
                    <button
                        class="btn btn--secondary"
                        on:click=on_clear
                        disabled=move || !clear_enabled.get()
                    >
                        "Clear"
                    </button>
                    <button
                        class="btn btn--primary"
                        on:click=on_apply
                        disabled=move || !apply_enabled.get()
                    >
                        "Apply"
                    </button>
                </Show>
            </div>
        </div>
    };

    let read_only_hint = view! {
        <Show when=move || read_only.get() fallback=|| ()>
            <div class="inspector-hint">
                "Envelope frame view is read-only. Use \"Extract\" to open the frame payload as an editable message."
            </div>
        </Show>
    };

    let selected_field_view = move || {
        let (fid, tag, parent, spans, root_spans, payload_len) =
            meta.get().expect("Show ensures meta is Some");

        let wt = tag.wire_type();

        let local_span = spans.map(|s| s.field);
        let root_span = root_spans.map(|s| s.field);

        view! {
            <>
                <details class="inspector-section inspector-section--meta">
                    <summary class="inspector-summary">"Meta"</summary>
                    <div class="inspector-meta">
                        <div>{format!("FieldId: {fid:?}")}</div>
                        <div>{format!("Parent MessageId: {parent:?}")}</div>
                        <div>
                            {format!(
                                "Span (local): {}",
                                local_span
                                    .map(|s| format!("{}..{}", s.start(), s.end()))
                                    .unwrap_or_else(|| "—".to_string())
                            )}
                        </div>
                        <div>
                            {format!(
                                "Span (root): {}",
                                root_span
                                    .map(|s| format!("{}..{}", s.start(), s.end()))
                                    .unwrap_or_else(|| "—".to_string())
                            )}
                        </div>
                        <div>
                            {format!(
                                "Payload: {}",
                                payload_len
                                    .map(|n| format!("{n} byte(s)"))
                                    .unwrap_or_else(|| "—".to_string())
                            )}
                        </div>
                    </div>
                </details>

                <div class="inspector-editor">
                    <Show when=move || wt == WireType::Varint fallback=|| ()>
                        <label class="inspector-label">"Varint"</label>
                        <input
                            class="input inspector-input"
                            prop:value=move || varint_text.get()
                            on:input=move |ev| varint_text.set(event_target_value(&ev))
                        />
                        <Show when=move || varint_validation.get().is_err() fallback=|| ()>
                            <div class="inspector-error">
                                {move || match varint_validation.get() {
                                    Err(msg) => msg,
                                    Ok(_) => UiError::Borrowed(""),
                                }}
                            </div>
                        </Show>
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
                        <Show when=move || bytes_validation.get().is_err() fallback=|| ()>
                            <div class="inspector-error">
                                {move || match bytes_validation.get() {
                                    Err(msg) => msg,
                                    Ok(_) => UiError::Borrowed(""),
                                }}
                            </div>
                        </Show>
                        <Show when=move || bytes_validation.get().is_ok() fallback=|| ()>
                            <div class="inspector-hint">
                                {move || {
                                    let Ok(Some(bytes)) = bytes_validation.get() else {
                                        return "—".to_string();
                                    };
                                    if bytes.len() > 4096 {
                                        return format!("{} byte(s) | preview skipped", bytes.len());
                                    }

                                    let utf8 = match core::str::from_utf8(&bytes) {
                                        Ok(s) => format!("utf8: \"{}\"", truncate_for_hint(s, 80)),
                                        Err(_) => "utf8: invalid".to_string(),
                                    };
                                    let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
                                    format!("{utf8} | base64: {}", truncate_for_hint(&b64, 80))
                                }}
                            </div>
                        </Show>
                        <button class="btn btn--secondary inspector-btn" on:click=on_parse_child>
                            "Parse as Message"
                        </button>
                    </Show>

                    <Show when=move || matches!(wt, WireType::I32 | WireType::I64) fallback=|| ()>
                        <label class="inspector-label">"Fixed"</label>
                        <input
                            class="input inspector-input"
                            prop:value=move || fixed_text.get()
                            on:input=move |ev| fixed_text.set(event_target_value(&ev))
                        />
                        <Show when=move || fixed_validation.get().is_err() fallback=|| ()>
                            <div class="inspector-error">
                                {move || match fixed_validation.get() {
                                    Err(msg) => msg,
                                    Ok(_) => UiError::Borrowed(""),
                                }}
                            </div>
                        </Show>
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
        }
    };

    let insert_section = view! {
        <details class="inspector-section">
            <summary class="inspector-summary">"Insert Field"</summary>
            <div class="inspector-header">
                <div class="inspector-title">"Insert Field"</div>
                <div class="inspector-actions">
                    <button
                        class="btn btn--primary"
                        on:click=on_insert
                        disabled=move || !insert_enabled.get()
                    >
                        "Insert"
                    </button>
                </div>
            </div>

            <div class="inspector-meta">
                <div>
                    {move || {
                        insert_target
                            .get()
                            .map(|(msg, label)| format!("Target: {label} ({msg:?})"))
                            .unwrap_or_else(|| "Target: —".to_string())
                    }}
                </div>
                <div>"Inserted fields have no spans until Save & Reparse."</div>
            </div>

            <div class="inspector-editor">
                <label class="inspector-label">"Field number"</label>
                <input
                    class="input inspector-input"
                    placeholder="1"
                    prop:value=move || insert_field_number.get()
                    on:input=move |ev| insert_field_number.set(event_target_value(&ev))
                />
                <Show when=move || insert_tag_validation.get().is_err() fallback=|| ()>
                    <div class="inspector-error">
                        {move || match insert_tag_validation.get() {
                            Err(msg) => msg,
                            Ok(_) => UiError::Borrowed(""),
                        }}
                    </div>
                </Show>

                <label class="inspector-label">"Wire type"</label>
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
                    <label class="inspector-label">"Value"</label>
                    <input
                        class="input inspector-input"
                        placeholder="0"
                        prop:value=move || insert_varint_text.get()
                        on:input=move |ev| insert_varint_text.set(event_target_value(&ev))
                    />
                    <Show when=move || insert_varint_validation.get().is_err() fallback=|| ()>
                        <div class="inspector-error">
                            {move || match insert_varint_validation.get() {
                                Err(msg) => msg,
                                Ok(_) => UiError::Borrowed(""),
                            }}
                        </div>
                    </Show>
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
                    <Show when=move || insert_bytes_validation.get().is_err() fallback=|| ()>
                        <div class="inspector-error">
                            {move || match insert_bytes_validation.get() {
                                Err(msg) => msg,
                                Ok(_) => UiError::Borrowed(""),
                            }}
                        </div>
                    </Show>
                    <Show
                        when=move || matches!(insert_bytes_validation.get(), Ok(Some(_)))
                        fallback=|| ()
                    >
                        <div class="inspector-hint">
                            {move || {
                                let Ok(Some(bytes)) = insert_bytes_validation.get() else {
                                    return "—".to_string();
                                };
                                format!("{} byte(s)", bytes.len())
                            }}
                        </div>
                    </Show>
                </Show>

                <Show
                    when=move || matches!(insert_wire.get(), WireType::I32 | WireType::I64)
                    fallback=|| ()
                >
                    <label class="inspector-label">"Bits"</label>
                    <input
                        class="input inspector-input"
                        placeholder="0x0"
                        prop:value=move || insert_fixed_text.get()
                        on:input=move |ev| insert_fixed_text.set(event_target_value(&ev))
                    />
                    <Show when=move || insert_fixed_validation.get().is_err() fallback=|| ()>
                        <div class="inspector-error">
                            {move || match insert_fixed_validation.get() {
                                Err(msg) => msg,
                                Ok(_) => UiError::Borrowed(""),
                            }}
                        </div>
                    </Show>
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
        </details>
    };

    let body = view! {
        <div class="inspector">
            {read_only_hint}
            <Show when=move || meta.get().is_some() fallback=empty_view>
                {selected_field_view}
            </Show>
            {insert_section}
        </div>
    };

    view! {
        <div class="inspector-panel" class:inspector-panel--collapsed=move || collapsed.get()>
            {panel_header}
            <div class:hidden=move || collapsed.get()>{body}</div>
        </div>
    }
}

fn bytes_view_change_handler(
    bytes_view: RwSignal<BytesView>,
    bytes_text: RwSignal<String>,
    toasts: RwSignal<Vec<Toast>>,
    next_toast_id: RwSignal<u64>,
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
                show_toast(toasts, next_toast_id, ToastKind::Error, msg);
                return;
            }
        };
        let new_text = match encode_bytes_view(&bytes, new_view) {
            Ok(s) => s,
            Err(msg) => {
                show_toast(toasts, next_toast_id, ToastKind::Error, msg);
                return;
            }
        };
        bytes_view.set(new_view);
        bytes_text.set(new_text);
    })
}

fn parse_u64(text: &str) -> Result<u64, ()> {
    let t = text.trim();
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).map_err(|_| ())
    } else {
        t.parse::<u64>().map_err(|_| ())
    }
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
            decode_hex_bytes(text).map_err(|_| "Invalid hex bytes.".into())
        }
        BytesView::Utf8 => Ok(text.as_bytes().to_vec()),
        BytesView::Base64 => decode_base64_bytes(text),
    }
}

fn encode_bytes_view(bytes: &[u8], view: BytesView) -> Result<String, &'static str> {
    match view {
        BytesView::Hex => Ok(hex::encode(bytes)),
        BytesView::Utf8 => core::str::from_utf8(bytes)
            .map(|s| s.to_string())
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

fn encoded_len_varint(v: u64) -> usize {
    protobuf_edit::varint::encoded_len64(v) as usize
}

fn wire_type_value(wt: WireType) -> &'static str {
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

fn collect_reachable_fields(patch: &Patch, msg: protobuf_edit::MessageId, out: &mut Vec<FieldId>) {
    let Ok(fields) = patch.message_fields(msg) else {
        return;
    };
    for &fid in fields {
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
