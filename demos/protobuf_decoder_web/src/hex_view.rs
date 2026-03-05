use leptos::html;
use leptos::prelude::*;
use protobuf_edit::{FieldId, Patch, ValueSpans, WireType};
use std::cmp::min;

use crate::bytes::ByteView;
use crate::fx::FxHashSet;

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HighlightKind {
    Ancestor,
    Hovered,
    SelectedTag,
    SelectedLenPrefix,
    SelectedField(WireType),
}

impl HighlightKind {
    const fn priority(self) -> u8 {
        match self {
            Self::Ancestor => 1,
            Self::Hovered => 2,
            Self::SelectedField(_) => 3,
            Self::SelectedLenPrefix => 4,
            Self::SelectedTag => 5,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HighlightRange {
    pub start: usize,
    pub end: usize,
    pub kind: HighlightKind,
}

impl HighlightRange {
    pub const fn contains(self, i: usize) -> bool {
        self.start <= i && i < self.end
    }

    pub const fn intersects(self, start: usize, end: usize) -> bool {
        self.start < end && self.end > start
    }
}

pub fn compute_highlights(
    patch: &Patch,
    selected: Option<FieldId>,
    hovered: Option<FieldId>,
) -> Vec<HighlightRange> {
    let mut out = Vec::new();

    if let Some(fid) = selected {
        if let (Ok(tag), Ok(Some(spans))) = (patch.field_tag(fid), patch.field_root_spans(fid)) {
            out.push(HighlightRange {
                start: spans.field.start() as usize,
                end: spans.field.end() as usize,
                kind: HighlightKind::SelectedField(tag.wire_type()),
            });
            if let ValueSpans::Len { len, .. } = spans.value {
                out.push(HighlightRange {
                    start: len.start() as usize,
                    end: len.end() as usize,
                    kind: HighlightKind::SelectedLenPrefix,
                });
            }
            out.push(HighlightRange {
                start: spans.tag.start() as usize,
                end: spans.tag.end() as usize,
                kind: HighlightKind::SelectedTag,
            });
        }

        if let Ok(mut msg) = patch.field_parent_message(fid) {
            while let Ok(Some(parent_field)) = patch.message_parent_field(msg) {
                if let Ok(Some(spans)) = patch.field_root_spans(parent_field) {
                    out.push(HighlightRange {
                        start: spans.field.start() as usize,
                        end: spans.field.end() as usize,
                        kind: HighlightKind::Ancestor,
                    });
                }
                if let Ok(parent_msg) = patch.field_parent_message(parent_field) {
                    msg = parent_msg;
                } else {
                    break;
                }
            }
        }
    }

    if let Some(fid) = hovered
        && let Ok(Some(spans)) = patch.field_root_spans(fid)
    {
        out.push(HighlightRange {
            start: spans.field.start() as usize,
            end: spans.field.end() as usize,
            kind: HighlightKind::Hovered,
        });
    }

    out
}

#[component]
pub fn HexGrid(
    patch_state: RwSignal<Option<Patch>, LocalStorage>,
    raw_bytes: RwSignal<Option<ByteView>, LocalStorage>,
    highlights: Memo<Vec<HighlightRange>>,
    text_mode: RwSignal<HexTextMode>,
    selected: RwSignal<Option<FieldId>>,
    expanded: RwSignal<FxHashSet<FieldId>>,
    container_ref: NodeRef<html::Div>,
) -> impl IntoView {
    const ROW_HEIGHT_PX: f64 = 20.0;
    const BYTES_PER_ROW: usize = 16;

    let first_row: RwSignal<usize> = RwSignal::new(0);

    let clamp_scroll = move |row: usize, total: usize, el: &web_sys::HtmlElement| -> (usize, i32) {
        if total == 0 {
            return (0, 0);
        }

        let client_height = el.client_height() as f64;
        let total_height = total as f64 * ROW_HEIGHT_PX;
        let max_scroll_top =
            if total_height > client_height { total_height - client_height } else { 0.0 };

        let target_scroll = (row as f64 * ROW_HEIGHT_PX).min(max_scroll_top);
        let clamped_row = (target_scroll / ROW_HEIGHT_PX).floor() as usize;
        (clamped_row, target_scroll as i32)
    };

    let total_rows = move || {
        patch_state
            .with(|p| p.as_ref().map(|p| p.root_bytes().len()))
            .or_else(|| raw_bytes.with(|b| b.as_ref().map(|v| v.len())))
            .map(|len| len.div_ceil(BYTES_PER_ROW))
            .unwrap_or(0)
    };

    let visible_count = move || {
        container_ref
            .get()
            .map(|el| (el.client_height() as f64 / ROW_HEIGHT_PX).ceil() as usize + 16)
            .unwrap_or(40)
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

    let on_byte_dblclick = Callback::new(move |idx: usize| {
        if patch_state.with(|p| p.is_none()) {
            return;
        }
        let mut outcome: Option<(Option<FieldId>, Vec<FieldId>)> = None;
        patch_state.update(|p| {
            let Some(patch) = p.as_mut() else {
                outcome = Some((None, Vec::new()));
                return;
            };
            outcome = Some(drilldown_byte(patch, idx));
        });

        let Some((selected_field, to_expand)) = outcome else {
            return;
        };
        expanded.update(|set| {
            for fid in to_expand {
                set.insert(fid);
            }
        });
        selected.set(selected_field);
    });

    Effect::new(move |_| {
        let Some(span) = selected_root_span.get() else {
            return;
        };
        let row = span.start() as usize / BYTES_PER_ROW;
        if let Some(el) = container_ref.get() {
            let (row, scroll_top) = clamp_scroll(row, total_rows(), &el);
            el.set_scroll_top(scroll_top);
            first_row.set(row);
        }
    });

    let bytes_key = Memo::new(move |_| {
        patch_state
            .with(|p| {
                p.as_ref().map(|patch| {
                    let bytes = patch.root_bytes();
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

    Effect::new(move |_| {
        let _ = bytes_key.get();
        first_row.set(0);
        if let Some(el) = container_ref.get() {
            el.set_scroll_top(0);
        }
    });

    Effect::new(move |_| {
        let total = total_rows();
        if total == 0 {
            first_row.set(0);
            if let Some(el) = container_ref.get() {
                el.set_scroll_top(0);
            }
            return;
        }

        let current = first_row.get_untracked();
        if let Some(el) = container_ref.get() {
            let total_height = total as f64 * ROW_HEIGHT_PX;
            let client_height = el.client_height() as f64;
            let max_scroll_top = (total_height - client_height).max(0.0);
            let max_first_row = (max_scroll_top / ROW_HEIGHT_PX).floor() as usize;
            if current > max_first_row {
                first_row.set(max_first_row);
                el.set_scroll_top(max_scroll_top as i32);
            }
        }
    });

    view! {
        <div
            node_ref=container_ref
            class="hex-container"
            tabindex="0"
            on:scroll=move |ev| {
                let el: web_sys::HtmlElement = event_target(&ev);
                let new_first_row = (el.scroll_top() as f64 / ROW_HEIGHT_PX).floor() as usize;
                if first_row.get_untracked() != new_first_row {
                    first_row.set(new_first_row);
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
                            patch_state=patch_state
                            raw_bytes=raw_bytes
                            highlights=highlights
                            text_mode=text_mode
                            on_byte_dblclick=on_byte_dblclick
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
        </div>
    }
}

#[component]
fn HexRow(
    row_index: usize,
    patch_state: RwSignal<Option<Patch>, LocalStorage>,
    raw_bytes: RwSignal<Option<ByteView>, LocalStorage>,
    highlights: Memo<Vec<HighlightRange>>,
    text_mode: RwSignal<HexTextMode>,
    on_byte_dblclick: Callback<usize>,
) -> impl IntoView {
    const BYTES_PER_ROW: usize = 16;

    let row_start = row_index * BYTES_PER_ROW;
    let row_end = row_start + BYTES_PER_ROW;

    let row_highlights = Memo::new(move |_| {
        highlights.with(|ranges| {
            ranges.iter().copied().filter(|h| h.intersects(row_start, row_end)).collect::<Vec<_>>()
        })
    });

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct CellData {
        idx: usize,
        byte: u8,
        kind: Option<HighlightKind>,
        utf8: Utf8Cell,
    }

    let highlight_kind_at = move |i: usize, spans: &[HighlightRange]| -> Option<HighlightKind> {
        let mut best: Option<HighlightKind> = None;
        for &h in spans {
            if !h.contains(i) {
                continue;
            }
            best = match best {
                None => Some(h.kind),
                Some(prev) => {
                    if h.kind.priority() > prev.priority() {
                        Some(h.kind)
                    } else {
                        Some(prev)
                    }
                }
            };
        }
        best
    };

    let row_cells: Memo<Vec<CellData>> = Memo::new(move |_| {
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
                        kind: highlight_kind_at(idx, spans),
                        utf8: utf8_cell(bytes, idx),
                    });
                }
                out
            };

            patch_state.with(|p| match p.as_ref() {
                Some(patch) => build_cells(patch.root_bytes()),
                None => raw_bytes
                    .with(|b| b.as_ref().map(|view| build_cells(view.as_slice())))
                    .unwrap_or_default(),
            })
        })
    });

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
        <span class="hex-offset">{format!("{:05X}", row_start)}</span>
            <span class="hex-bytes">
                {move || {
                    row_cells.with(|cells| {
                        cells
                            .iter()
                            .map(|cell| {
                                let idx = cell.idx;
                                let cls = class_for(cell.kind);
                                view! {
                                    <span class=cls on:dblclick=move |_| on_byte_dblclick.run(idx)>
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
                        let mode = text_mode.get();
                        row_cells.with(|cells| {
                            cells
                                .iter()
                                .map(|cell| {
                                    let idx = cell.idx;
                                    let cls = class_for(cell.kind);
                                    match mode {
                                        HexTextMode::Ascii => view! {
                                            <span
                                                class=cls
                                                on:dblclick=move |_| on_byte_dblclick.run(idx)
                                            >
                                                {ascii_cell(cell.byte)}
                                            </span>
                                        }
                                        .into_any(),
                                        HexTextMode::Unicode => match cell.utf8 {
                                            Utf8Cell::Static(text) => view! {
                                                <span
                                                    class=cls
                                                    on:dblclick=move |_| on_byte_dblclick.run(idx)
                                                >
                                                    {text}
                                                </span>
                                            }
                                            .into_any(),
                                            Utf8Cell::Char(ch) => view! {
                                                <span
                                                    class=cls
                                                    on:dblclick=move |_| on_byte_dblclick.run(idx)
                                                >
                                                    {ch.to_string()}
                                                </span>
                                            }
                                            .into_any(),
                                            Utf8Cell::Placeholder => view! {
                                                <span
                                                    class=cls
                                                    class:hex-byte--placeholder=true
                                                    on:dblclick=move |_| on_byte_dblclick.run(idx)
                                                ></span>
                                            }
                                            .into_any(),
                                        },
                                    }
                                })
                                .collect::<Vec<_>>()
                        })
                    }}
                </span>
        </div>
    }
}

fn drilldown_byte(patch: &mut Patch, idx: usize) -> (Option<FieldId>, Vec<FieldId>) {
    let mut msg = patch.root();
    let mut expand = Vec::new();
    let mut selected = None;
    let mut depth: u32 = 0;

    loop {
        depth = depth.saturating_add(1);
        if depth > 128 {
            break;
        }

        let fields = match patch.message_fields(msg) {
            Ok(v) => v,
            Err(_) => break,
        };

        let mut best: Option<(FieldId, protobuf_edit::Span)> = None;
        for &fid in fields {
            if matches!(patch.field_is_deleted(fid), Ok(true)) {
                continue;
            }
            let Ok(Some(spans)) = patch.field_root_spans(fid) else {
                continue;
            };
            let field_span = spans.field;
            let start = field_span.start() as usize;
            let end = field_span.end() as usize;
            if start <= idx && idx < end {
                best = match best {
                    None => Some((fid, field_span)),
                    Some((_prev, prev_span)) => {
                        if field_span.len() < prev_span.len() {
                            Some((fid, field_span))
                        } else {
                            Some((_prev, prev_span))
                        }
                    }
                };
            }
        }

        let Some((fid, _span)) = best else {
            break;
        };
        selected = Some(fid);

        let Ok(tag) = patch.field_tag(fid) else {
            break;
        };
        if tag.wire_type() != WireType::Len {
            break;
        }

        let Ok(Some(root_spans)) = patch.field_root_spans(fid) else {
            break;
        };
        let ValueSpans::Len { payload, .. } = root_spans.value else {
            break;
        };
        let payload_start = payload.start() as usize;
        let payload_end = payload.end() as usize;
        if idx < payload_start || idx >= payload_end {
            break;
        }

        match patch.parse_child_message(fid) {
            Ok(child) => {
                expand.push(fid);
                msg = child;
            }
            Err(_) => break,
        }
    }

    (selected, expand)
}
