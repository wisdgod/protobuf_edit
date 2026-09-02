use protobuf_edit::session::grouped::{RecordSpans, Session};
use protobuf_edit::session::Handle;
use protobuf_edit::wire::grouped::RecordKind;
use protobuf_edit::Span;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HighlightKind {
    Ancestor,
    Hovered,
    SelectedTag,
    SelectedLenPrefix,
    SelectedField(RecordKind),
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

fn range_of(span: Span, kind: HighlightKind) -> HighlightRange {
    HighlightRange { start: span.start() as usize, end: span.end() as usize, kind }
}

/// Highlight ranges for the selected record and its ancestor chain.
/// Command-authored rows own no hex, so they contribute nothing.
///
/// Kept separate from the hover range so that high-frequency hover
/// changes do not invalidate the (heavier) selection-derived ranges.
pub(crate) fn compute_selected_highlights(
    session: &Session,
    selected: Option<Handle>,
) -> Vec<HighlightRange> {
    let mut out = Vec::new();

    let Some(handle) = selected else {
        return out;
    };

    if let (Ok(kind), Ok(Some(span))) = (session.kind(handle), session.span(handle)) {
        out.push(range_of(span, HighlightKind::SelectedField(kind)));
    }

    if let Ok(Some(spans)) = session.source_spans(handle) {
        let (tag, prefix, end_tag) = match spans {
            RecordSpans::Varint { tag, .. }
            | RecordSpans::I64 { tag, .. }
            | RecordSpans::I32 { tag, .. } => (tag, None, None),
            RecordSpans::Len { tag, prefix, .. } => (tag, Some(prefix), None),
            RecordSpans::Group { tag, end_tag, .. } => (tag, None, Some(end_tag)),
        };
        if let Some(prefix) = prefix {
            out.push(range_of(prefix, HighlightKind::SelectedLenPrefix));
        }
        out.push(range_of(tag, HighlightKind::SelectedTag));
        if let Some(end_tag) = end_tag {
            out.push(range_of(end_tag, HighlightKind::SelectedTag));
        }
    }

    for ancestor in session.ancestors(handle).ok().into_iter().flatten() {
        if let Ok(Some(span)) = session.span(ancestor) {
            out.push(range_of(span, HighlightKind::Ancestor));
        }
    }

    out
}

/// Root-coordinate range of the hovered record, if it owns hex.
pub(crate) fn compute_hovered_range(
    session: &Session,
    hovered: Option<Handle>,
) -> Option<HighlightRange> {
    let handle = hovered?;
    let span = session.span(handle).ok()??;
    Some(range_of(span, HighlightKind::Hovered))
}
