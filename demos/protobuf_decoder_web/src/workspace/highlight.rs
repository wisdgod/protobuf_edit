use protobuf_edit::patch::{FieldId, ValueSpans};
use protobuf_edit::{Patch, WireType};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HighlightKind {
    Ancestor,
    Hovered,
    SelectedTag,
    SelectedLenPrefix,
    SelectedField(WireType),
}

impl HighlightKind {
    pub(crate) const fn priority(self) -> u8 {
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
pub(crate) struct HighlightRange {
    pub start: usize,
    pub end: usize,
    pub kind: HighlightKind,
}

impl HighlightRange {
    pub(crate) const fn contains(self, i: usize) -> bool {
        self.start <= i && i < self.end
    }

    pub(crate) const fn intersects(self, start: usize, end: usize) -> bool {
        self.start < end && self.end > start
    }
}

/// Highlight ranges for the selected field and its ancestor chain.
///
/// Kept separate from the hover range so that high-frequency hover changes
/// do not invalidate the (heavier) selection-derived ranges.
pub(crate) fn compute_selected_highlights(
    patch: &Patch,
    selected: Option<FieldId>,
) -> Vec<HighlightRange> {
    let mut out = Vec::new();

    let Some(fid) = selected else {
        return out;
    };

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

    for parent_field in super::ancestor_fields(patch, fid) {
        if let Ok(Some(spans)) = patch.field_root_spans(parent_field) {
            out.push(HighlightRange {
                start: spans.field.start() as usize,
                end: spans.field.end() as usize,
                kind: HighlightKind::Ancestor,
            });
        }
    }

    out
}

/// Root-coordinate range of the hovered field, if any.
pub(crate) fn compute_hovered_range(
    patch: &Patch,
    hovered: Option<FieldId>,
) -> Option<HighlightRange> {
    let fid = hovered?;
    let spans = patch.field_root_spans(fid).ok()??;
    Some(HighlightRange {
        start: spans.field.start() as usize,
        end: spans.field.end() as usize,
        kind: HighlightKind::Hovered,
    })
}
