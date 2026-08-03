use leptos::html;
use leptos::prelude::*;
use protobuf_edit::WireType;
use std::cmp::min;

use crate::bytes::ByteView;
use crate::components::HexContextMenu;
use crate::hex_copy::CopyFormat;
use crate::services::ExportService;
use crate::state::WorkspaceState;
use crate::workspace::{drilldown_byte, HighlightKind, HighlightRange};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HexTextMode {
    Ascii,
    Unicode,
}

impl HexTextMode {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Ascii => "ASCII",
            Self::Unicode => "Unicode",
        }
    }

    pub const fn toggle(self) -> Self {
        match self {
            Self::Ascii => Self::Unicode,
            Self::Unicode => Self::Ascii,
        }
    }
}

const fn hex_digit(nibble: u8) -> u8 {
    match nibble {
        0..=9 => b'0' + nibble,
        10..=15 => b'A' + (nibble - 10),
        _ => b'?',
    }
}

static HEX_CELL_TABLE: [[u8; 3]; 256] = {
    let mut table = [[0u8; 3]; 256];
    let mut i: usize = 0;
    while i < 256 {
        let b = i as u8;
        table[i] = [hex_digit(b >> 4), hex_digit(b & 0x0F), b' '];
        i += 1;
    }
    table
};

fn hex_cell(byte: u8) -> &'static str {
    // Safety: table contains only ASCII bytes, so it is always valid UTF-8.
    unsafe { core::str::from_utf8_unchecked(&HEX_CELL_TABLE[byte as usize]) }
}

static ASCII_CELL_TABLE: [[u8; 1]; 256] = {
    let mut table = [[0u8; 1]; 256];
    let mut i: usize = 0;
    while i < 256 {
        let b = i as u8;
        let ch = if b >= 0x20 && b <= 0x7E { b } else { b'.' };
        table[i] = [ch];
        i += 1;
    }
    table
};

fn ascii_cell(byte: u8) -> &'static str {
    // Safety: table contains only ASCII bytes, so it is always valid UTF-8.
    unsafe { core::str::from_utf8_unchecked(&ASCII_CELL_TABLE[byte as usize]) }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Utf8Cell {
    Static(&'static str),
    Char(char),
    Placeholder,
}

fn utf8_cell(bytes: &[u8], idx: usize) -> Utf8Cell {
    let byte = bytes[idx];

    if byte < 0x80 {
        return Utf8Cell::Static(ascii_cell(byte));
    }

    let search_start = idx.saturating_sub(3);
    for lead_idx in (search_start..=idx).rev() {
        let lead = bytes[lead_idx];
        let expected_len = if lead & 0xE0 == 0xC0 {
            2usize
        } else if lead & 0xF0 == 0xE0 {
            3usize
        } else if lead & 0xF8 == 0xF0 {
            4usize
        } else {
            continue;
        };

        let end = lead_idx + expected_len;
        if idx >= end || end > bytes.len() {
            continue;
        }

        let slice = &bytes[lead_idx..end];
        if slice.iter().skip(1).any(|b| (b & 0xC0) != 0x80) {
            continue;
        }

        let Ok(text) = core::str::from_utf8(slice) else {
            continue;
        };

        let Some(ch) = text.chars().next() else {
            continue;
        };
        if ch.is_control() {
            return Utf8Cell::Static(".");
        }

        if idx == lead_idx {
            return Utf8Cell::Char(ch);
        }
        return Utf8Cell::Placeholder;
    }

    Utf8Cell::Static(ascii_cell(byte))
}

/// Byte index of the event target, if it is a hex cell.
///
/// Cells carry `data-i`; all mouse handling is delegated to the container so
/// the grid does not allocate three closures per rendered byte span.
fn cell_index_of(ev: &web_sys::MouseEvent) -> Option<usize> {
    use wasm_bindgen::JsCast as _;
    let el = ev.target()?.dyn_into::<web_sys::Element>().ok()?;
    el.get_attribute("data-i")?.parse().ok()
}

#[component]
pub fn HexGrid(container_ref: NodeRef<html::Div>) -> impl IntoView {
    let workspace = expect_context::<WorkspaceState>();
    let export_svc = expect_context::<ExportService>();
    let patch_state = workspace.patch_state;
    let patch_bytes = workspace.patch_bytes;
    let raw_bytes = workspace.raw_bytes;
    let selected_highlights = workspace.selected_highlights;
    let hovered_range = workspace.hovered_range;
    let text_mode = workspace.hex_text_mode;
    let selected = workspace.selected;
    let expanded = workspace.expanded;
    let hex_selection = workspace.hex_selection;
    const ROW_HEIGHT_PX: f64 = 20.0;
    const BYTES_PER_ROW: usize = 16;

    let first_row: RwSignal<usize> = RwSignal::new(0);

    // Selection drag state (local to HexGrid, not in WorkspaceState).
    let selection_anchor: RwSignal<Option<usize>> = RwSignal::new(None);
    let is_selecting: RwSignal<bool> = RwSignal::new(false);
    let ctx_menu_visible: RwSignal<bool> = RwSignal::new(false);
    let ctx_menu_pos: RwSignal<(i32, i32)> = RwSignal::new((0, 0));

    let clamp_scroll = move |row: usize, total: usize, el: &web_sys::HtmlElement| -> (usize, i32) {
        if total == 0 {
            return (0, 0);
        }

        let client_height = f64::from(el.client_height());
        let total_height = total as f64 * ROW_HEIGHT_PX;
        let max_scroll_top =
            if total_height > client_height { total_height - client_height } else { 0.0 };

        let target_scroll = (row as f64 * ROW_HEIGHT_PX).min(max_scroll_top);
        let clamped_row = (target_scroll / ROW_HEIGHT_PX).floor() as usize;
        (clamped_row, target_scroll as i32)
    };

    // The grid renders bytes, and patch_bytes mirrors the patch's root bytes,
    // so nothing here needs to subscribe to patch_state mutations.
    let total_rows = move || {
        patch_bytes
            .with(|b| b.as_ref().map(ByteView::len))
            .or_else(|| raw_bytes.with(|b| b.as_ref().map(ByteView::len)))
            .map_or(0, |len| len.div_ceil(BYTES_PER_ROW))
    };

    let total_rows_untracked = move || {
        patch_bytes
            .with_untracked(|b| b.as_ref().map(ByteView::len))
            .or_else(|| raw_bytes.with_untracked(|b| b.as_ref().map(ByteView::len)))
            .map_or(0, |len| len.div_ceil(BYTES_PER_ROW))
    };

    let visible_count = move || {
        container_ref
            .get()
            .map_or(40, |el| (f64::from(el.client_height()) / ROW_HEIGHT_PX).ceil() as usize + 16)
    };

    let selected_root_span = Memo::new(move |_| {
        patch_state.with(|p| {
            let patch = p.as_ref()?;
            let fid = selected.get()?;
            match patch.field_root_spans(fid) {
                Ok(Some(spans)) => Some(spans.field),
                _ => None,
            }
        })
    });

    let on_grid_dblclick = move |ev: web_sys::MouseEvent| {
        let Some(idx) = cell_index_of(&ev) else {
            return;
        };
        // Drilldown only fills the lazy child-parse cache; visibility flows
        // through `expanded`/`selected`, so skip the patch_state notification.
        let outcome = patch_state
            .try_update_untracked(|p| p.as_mut().map(|patch| drilldown_byte(patch, idx)))
            .flatten();
        let Some((selected_field, to_expand)) = outcome else {
            return;
        };
        expanded.update(|set| {
            for fid in to_expand {
                set.insert(fid);
            }
        });
        selected.set(selected_field);
    };

    let on_grid_mousedown = move |ev: web_sys::MouseEvent| {
        ctx_menu_visible.set(false);
        if ev.button() != 0 {
            return;
        }
        let Some(idx) = cell_index_of(&ev) else {
            return;
        };
        if ev.shift_key() {
            if let Some(anchor) = selection_anchor.get_untracked() {
                let start = anchor.min(idx);
                let end = anchor.max(idx) + 1;
                hex_selection.set(Some((start, end)));
            }
        } else {
            selection_anchor.set(Some(idx));
            is_selecting.set(true);
            hex_selection.set(Some((idx, idx + 1)));
        }
    };

    let on_grid_mouseover = move |ev: web_sys::MouseEvent| {
        if !is_selecting.get_untracked() {
            return;
        }
        let Some(anchor) = selection_anchor.get_untracked() else {
            return;
        };
        let Some(idx) = cell_index_of(&ev) else {
            return;
        };
        let start = anchor.min(idx);
        let end = anchor.max(idx) + 1;
        hex_selection.set(Some((start, end)));
    };

    let on_copy_format = Callback::new(move |fmt: CopyFormat| {
        let Some((start, end)) = hex_selection.get_untracked() else {
            return;
        };
        export_svc.copy_range_as(start, end, fmt);
    });

    // Track only the selected span (and the container mounting): forcing
    // layout + hijacking the scroll position on unrelated patch mutations was
    // both wasted reflow and a UX bug.
    Effect::new(move |_| {
        let Some(span) = selected_root_span.get() else {
            return;
        };
        let row = span.start() as usize / BYTES_PER_ROW;
        if let Some(el) = container_ref.get() {
            let (row, scroll_top) = clamp_scroll(row, total_rows_untracked(), &el);
            el.set_scroll_top(scroll_top);
            first_row.set(row);
        }
    });

    let bytes_key = Memo::new(move |_| {
        patch_bytes
            .with(|b| {
                b.as_ref().map(|view| {
                    let bytes = view.as_slice();
                    (bytes.as_ptr() as usize, bytes.len())
                })
            })
            .or_else(|| {
                raw_bytes.with(|b| {
                    b.as_ref().map(|view| {
                        let bytes = view.as_slice();
                        (bytes.as_ptr() as usize, bytes.len())
                    })
                })
            })
    });

    // Byte content can only change together with `bytes_key`, so resetting
    // the scroll here doubles as the clamp for shrinking content.
    Effect::new(move |_| {
        let _ = bytes_key.get();
        first_row.set(0);
        if let Some(el) = container_ref.get() {
            el.set_scroll_top(0);
        }
    });

    view! {
        <div
            node_ref=container_ref
            class="hex-container"
            tabindex="0"
            on:scroll=move |ev| {
                let el: web_sys::HtmlElement = event_target(&ev);
                let new_first_row = (f64::from(el.scroll_top()) / ROW_HEIGHT_PX).floor() as usize;
                if first_row.get_untracked() != new_first_row {
                    first_row.set(new_first_row);
                }
            }
            on:mousedown=on_grid_mousedown
            on:mouseover=on_grid_mouseover
            on:dblclick=on_grid_dblclick
            on:mouseup=move |_| {
                is_selecting.set(false);
            }
            on:mouseleave=move |_| {
                is_selecting.set(false);
            }
            on:contextmenu=move |ev: web_sys::MouseEvent| {
                if hex_selection.with_untracked(std::option::Option::is_some) {
                    ev.prevent_default();
                    ctx_menu_pos.set((ev.client_x(), ev.client_y()));
                    ctx_menu_visible.set(true);
                }
            }
        >
            <Show
                when=move || { total_rows() > 0 }
                fallback=move || view! { <div class="panel-header">"No data loaded."</div> }
            >
                <div
                    style:height=move || {
                        format!("{}px", (first_row.get() as f64 * ROW_HEIGHT_PX) as usize)
                    }
                ></div>
                <For
                    each=move || {
                        let start = first_row.get();
                        let end = min(start + visible_count(), total_rows());
                        start..end
                    }
                    key=|row| *row
                    children=move |row| view! {
                        <HexRow
                            row_index=row
                            patch_bytes=patch_bytes
                            raw_bytes=raw_bytes
                            selected_highlights=selected_highlights
                            hovered_range=hovered_range
                            text_mode=text_mode
                            hex_selection=hex_selection
                        />
                    }
                />
                <div
                    style:height=move || {
                        let rendered_end = first_row.get() + visible_count();
                        let remaining = total_rows().saturating_sub(rendered_end);
                        format!("{}px", (remaining as f64 * ROW_HEIGHT_PX) as usize)
                    }
                ></div>
            </Show>

            <HexContextMenu visible=ctx_menu_visible position=ctx_menu_pos on_select=on_copy_format />
        </div>
    }
}

#[component]
fn HexRow(
    row_index: usize,
    patch_bytes: RwSignal<Option<ByteView>, LocalStorage>,
    raw_bytes: RwSignal<Option<ByteView>, LocalStorage>,
    selected_highlights: Memo<Vec<HighlightRange>>,
    hovered_range: Memo<Option<HighlightRange>>,
    text_mode: RwSignal<HexTextMode>,
    hex_selection: RwSignal<Option<(usize, usize)>>,
) -> impl IntoView {
    const BYTES_PER_ROW: usize = 16;

    let row_start = row_index * BYTES_PER_ROW;
    let row_end = row_start + BYTES_PER_ROW;

    let row_highlights = Memo::new(move |_| {
        selected_highlights.with(|ranges| {
            ranges.iter().copied().filter(|h| h.intersects(row_start, row_end)).collect::<Vec<_>>()
        })
    });

    // Hover moves at mouse frequency but only ever touches the rows the
    // hovered field intersects; keeping it separate leaves all other rows'
    // cells untouched.
    let row_hover =
        Memo::new(move |_| hovered_range.get().filter(|h| h.intersects(row_start, row_end)));

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct CellData {
        idx: usize,
        byte: u8,
        kind: Option<HighlightKind>,
        range_selected: bool,
        utf8: Utf8Cell,
    }

    let highlight_kind_at =
        move |i: usize, spans: &[HighlightRange], hover: Option<HighlightRange>| {
            let mut best: Option<HighlightKind> = None;
            for h in spans.iter().copied().chain(hover) {
                if !h.contains(i) {
                    continue;
                }
                best = best.map_or(Some(h.kind), |prev| {
                    if h.kind.priority() > prev.priority() { Some(h.kind) } else { Some(prev) }
                });
            }
            best
        };

    let row_cells: Memo<Vec<CellData>> = Memo::new(move |_| {
        let sel = hex_selection.get();
        let hover = row_hover.get();
        let mode = text_mode.get();
        row_highlights.with(|spans| {
            let build_cells = |bytes: &[u8]| {
                let end = min(row_end, bytes.len());
                if row_start >= end {
                    return Vec::new();
                }
                let mut out = Vec::with_capacity(end.saturating_sub(row_start));
                for (offset, &byte) in bytes[row_start..end].iter().enumerate() {
                    let idx = row_start + offset;
                    out.push(CellData {
                        idx,
                        byte,
                        kind: highlight_kind_at(idx, spans, hover),
                        range_selected: sel.is_some_and(|(a, b)| idx >= a && idx < b),
                        // UTF-8 grouping is only rendered in Unicode mode;
                        // skip the per-byte decode work otherwise.
                        utf8: match mode {
                            HexTextMode::Ascii => Utf8Cell::Static(ascii_cell(byte)),
                            HexTextMode::Unicode => utf8_cell(bytes, idx),
                        },
                    });
                }
                out
            };

            patch_bytes.with(|b| {
                b.as_ref().map_or_else(
                    || {
                        raw_bytes
                            .with(|b| b.as_ref().map(|view| build_cells(view.as_slice())))
                            .unwrap_or_default()
                    },
                    |view| build_cells(view.as_slice()),
                )
            })
        })
    });

    // Range selection is additive (`hex-byte--range-selected` class binding
    // on the span): the field-selection background stays visible and only
    // the range underline stacks on top.
    let class_for = move |kind: Option<HighlightKind>| -> &'static str {
        match kind {
            None => "hex-byte",
            Some(HighlightKind::Ancestor) => "hex-byte hex-byte--ancestor",
            Some(HighlightKind::Hovered) => "hex-byte hex-byte--hovered",
            Some(HighlightKind::SelectedTag) => "hex-byte hex-byte--tag",
            Some(HighlightKind::SelectedLenPrefix) => "hex-byte hex-byte--selected-len-prefix",
            Some(HighlightKind::SelectedField(WireType::Varint)) => {
                "hex-byte hex-byte--selected-varint"
            }
            Some(HighlightKind::SelectedField(WireType::I64)) => "hex-byte hex-byte--selected-i64",
            Some(HighlightKind::SelectedField(WireType::Len)) => "hex-byte hex-byte--selected-len",
            Some(HighlightKind::SelectedField(WireType::I32)) => "hex-byte hex-byte--selected-i32",
        }
    };

    view! {
        <div class="hex-row">
            <span class="hex-offset">{format!("{row_start:05X}")}</span>
            <span class="hex-bytes">
                {move || {
                    row_cells.with(|cells| {
                        cells
                            .iter()
                            .map(|cell| {
                                let cls = class_for(cell.kind);
                                view! {
                                    <span
                                        class=cls
                                        class:hex-byte--range-selected=cell.range_selected
                                        data-i=cell.idx
                                    >
                                        {hex_cell(cell.byte)}
                                    </span>
                                }
                                .into_any()
                            })
                            .collect::<Vec<_>>()
                    })
                }}
            </span>
            <span class="hex-text">
                {move || {
                    row_cells.with(|cells| {
                        cells
                            .iter()
                            .map(|cell| {
                                let cls = class_for(cell.kind);
                                let range = cell.range_selected;
                                // Ascii mode resolves to `Static` cells inside
                                // `row_cells`, so one match covers both modes.
                                match cell.utf8 {
                                    Utf8Cell::Static(text) => view! {
                                        <span
                                            class=cls
                                            class:hex-byte--range-selected=range
                                            data-i=cell.idx
                                        >
                                            {text}
                                        </span>
                                    }
                                    .into_any(),
                                    Utf8Cell::Char(ch) => view! {
                                        <span
                                            class=cls
                                            class:hex-byte--range-selected=range
                                            data-i=cell.idx
                                        >
                                            {ch.to_string()}
                                        </span>
                                    }
                                    .into_any(),
                                    Utf8Cell::Placeholder => view! {
                                        <span
                                            class=cls
                                            class:hex-byte--placeholder=true
                                            class:hex-byte--range-selected=range
                                            data-i=cell.idx
                                        ></span>
                                    }
                                    .into_any(),
                                }
                            })
                            .collect::<Vec<_>>()
                    })
                }}
            </span>
        </div>
    }
}
