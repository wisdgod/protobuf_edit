use crate::fx::FxHashSet;
use protobuf_edit::{FieldId, Patch};

pub(crate) fn collect_visible_fields(
    patch: &Patch,
    msg: protobuf_edit::MessageId,
    expanded: &FxHashSet<FieldId>,
    out: &mut Vec<FieldId>,
) {
    let Ok(fields) = patch.message_fields(msg) else {
        return;
    };
    for &field in fields {
        if matches!(patch.field_is_deleted(field), Ok(true)) {
            continue;
        }
        out.push(field);
        if !expanded.contains(&field) {
            continue;
        }
        let Ok(Some(child)) = patch.field_child_message(field) else {
            continue;
        };
        collect_visible_fields(patch, child, expanded, out);
    }
}
