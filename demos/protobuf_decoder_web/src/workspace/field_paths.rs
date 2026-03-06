use crate::fx::FxHashSet;
use protobuf_edit::{FieldId, Patch, Tag, TreeError, WireType};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SelectionStep {
    pub tag: Tag,
    pub occurrence: u32,
}

pub(crate) fn encode_selection_path(path: &[SelectionStep]) -> String {
    use core::fmt::Write as _;

    let mut out = String::new();
    for (i, step) in path.iter().enumerate() {
        if i != 0 {
            out.push('/');
        }
        let (field_number, wire_type) = step.tag.split();
        let _ =
            write!(&mut out, "{}:{}:{}", field_number.as_inner(), wire_type as u8, step.occurrence);
    }
    out
}

pub(crate) fn decode_selection_path(input: &str) -> Option<Vec<SelectionStep>> {
    let input = input.trim();
    if input.is_empty() {
        return None;
    }

    let mut out = Vec::new();
    for part in input.split('/') {
        let mut it = part.trim().split(':');
        let field_number = it.next()?.parse::<u32>().ok()?;
        let wire_type = it.next()?.parse::<u32>().ok()?;
        let occurrence = it.next()?.parse::<u32>().ok()?;
        if it.next().is_some() {
            return None;
        }

        let field_number = protobuf_edit::FieldNumber::new(field_number)?;
        let wire_type = protobuf_edit::WireType::from_low3(wire_type)?;
        let tag = protobuf_edit::Tag::from_parts(field_number, wire_type);
        out.push(SelectionStep { tag, occurrence });
    }

    Some(out)
}

pub(crate) fn build_selection_path(patch: &Patch, selected: FieldId) -> Option<Vec<SelectionStep>> {
    let mut chain_fields: Vec<FieldId> = Vec::new();
    chain_fields.push(selected);
    let mut msg = patch.field_parent_message(selected).ok();
    while let Some(m) = msg {
        match patch.message_parent_field(m) {
            Ok(Some(parent_field)) => {
                chain_fields.push(parent_field);
                msg = patch.field_parent_message(parent_field).ok();
            }
            Ok(None) => break,
            Err(_) => break,
        }
    }
    chain_fields.reverse();

    let mut out = Vec::with_capacity(chain_fields.len());
    for fid in chain_fields {
        let tag = patch.field_tag(fid).ok()?;
        let parent = patch.field_parent_message(fid).ok()?;
        let fields = patch.message_fields(parent).ok()?;

        let mut occurrence: u32 = 0;
        let mut found = false;
        for &f in fields {
            if matches!(patch.field_is_deleted(f), Ok(true)) {
                continue;
            }
            let t = patch.field_tag(f).ok()?;
            if t != tag {
                continue;
            }
            if f == fid {
                found = true;
                break;
            }
            occurrence = occurrence.saturating_add(1);
        }
        if !found {
            return None;
        }

        out.push(SelectionStep { tag, occurrence });
    }
    Some(out)
}

fn find_field_by_tag_occurrence(
    patch: &Patch,
    msg: protobuf_edit::MessageId,
    tag: Tag,
    occurrence: u32,
) -> Result<Option<FieldId>, TreeError> {
    let fields = patch.message_fields(msg)?;
    let mut seen: u32 = 0;
    for &field in fields {
        if patch.field_is_deleted(field)? {
            continue;
        }
        if patch.field_tag(field)? != tag {
            continue;
        }
        if seen == occurrence {
            return Ok(Some(field));
        }
        seen = seen.saturating_add(1);
    }
    Ok(None)
}

pub(crate) fn resolve_selection_path(
    patch: &mut Patch,
    path: &[SelectionStep],
    expand_last_len: bool,
) -> Result<Option<(FieldId, FxHashSet<FieldId>)>, TreeError> {
    let mut msg = patch.root();
    let mut expanded: FxHashSet<FieldId> = FxHashSet::default();
    let mut current: Option<FieldId> = None;

    for (i, step) in path.iter().enumerate() {
        let Some(field) = find_field_by_tag_occurrence(patch, msg, step.tag, step.occurrence)?
        else {
            return Ok(None);
        };
        current = Some(field);

        let is_last = i + 1 == path.len();
        if is_last {
            if expand_last_len
                && step.tag.wire_type() == WireType::Len
                && patch.parse_child_message(field).is_ok()
            {
                expanded.insert(field);
            }
            break;
        }

        if step.tag.wire_type() != WireType::Len {
            break;
        }

        match patch.parse_child_message(field) {
            Ok(child) => {
                expanded.insert(field);
                msg = child;
            }
            Err(_) => break,
        }
    }

    Ok(current.map(|fid| (fid, expanded)))
}
