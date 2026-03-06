use protobuf_edit::{FieldId, Patch, ValueSpans, WireType};

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

pub(crate) fn compute_highlights(
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
