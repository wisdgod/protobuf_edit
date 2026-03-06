use protobuf_edit::{FieldId, Patch, ValueSpans, WireType};

pub(crate) fn drilldown_byte(patch: &mut Patch, idx: usize) -> (Option<FieldId>, Vec<FieldId>) {
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
                    Some((prev, prev_span)) => {
                        if field_span.len() < prev_span.len() {
                            Some((fid, field_span))
                        } else {
                            Some((prev, prev_span))
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
