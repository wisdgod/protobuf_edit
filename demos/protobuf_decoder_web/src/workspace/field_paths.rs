use crate::fx::FxHashSet;
use protobuf_edit::{Buf, FieldId, FieldNumber, Patch, Tag, TreeError, WireType};

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

/// Parse a user path like ".3:0.1.2" into (field_number, occurrence) pairs.
/// Leading dot required. `:n` suffix optional (defaults to 0).
pub(crate) fn parse_user_path(input: &str) -> Option<Vec<(u32, u32)>> {
    let input = input.trim();
    let rest = input.strip_prefix('.')?;
    if rest.is_empty() {
        return Some(Vec::new());
    }

    let mut out = Vec::new();
    for part in rest.split('.') {
        let part = part.trim();
        if part.is_empty() {
            return None;
        }
        let (num_str, occ) = match part.split_once(':') {
            Some((n, o)) => (n, o.parse::<u32>().ok()?),
            None => (part, 0),
        };
        let field_number = num_str.parse::<u32>().ok()?;
        FieldNumber::new(field_number)?;
        out.push((field_number, occ));
    }
    Some(out)
}

/// Format a user-friendly path string like ".3.1.2" for a given field.
pub(crate) fn format_user_path(patch: &Patch, fid: FieldId) -> Option<String> {
    let steps = build_selection_path(patch, fid)?;
    let mut out = String::new();
    for step in &steps {
        let (field_number, _wire_type) = step.tag.split();
        out.push('.');
        use core::fmt::Write as _;
        let _ = write!(out, "{}", field_number.as_inner());
        if step.occurrence > 0 {
            let _ = write!(out, ":{}", step.occurrence);
        }
    }
    if out.is_empty() {
        return Some(".".to_string());
    }
    Some(out)
}

fn find_field_by_number_occurrence(
    patch: &Patch,
    msg: protobuf_edit::MessageId,
    field_number: u32,
    occurrence: u32,
) -> Result<Option<FieldId>, TreeError> {
    let fields = patch.message_fields(msg)?;
    let mut seen: u32 = 0;
    for &field in fields {
        if patch.field_is_deleted(field)? {
            continue;
        }
        let tag = patch.field_tag(field)?;
        if tag.field_number().as_inner() != field_number {
            continue;
        }
        if seen == occurrence {
            return Ok(Some(field));
        }
        seen = seen.saturating_add(1);
    }
    Ok(None)
}

/// Resolve a user path, auto-parsing child messages. For Len fields that
/// don't parse as protobuf directly, tries decoding the bytes as
/// hex/base64 first (via `decode_user_input`).
pub(crate) fn resolve_user_path(
    patch: &mut Patch,
    path: &[(u32, u32)],
) -> Result<Option<(FieldId, FxHashSet<FieldId>)>, TreeError> {
    let mut msg = patch.root();
    let mut expanded: FxHashSet<FieldId> = FxHashSet::default();
    let mut current: Option<FieldId> = None;

    for (i, &(field_number, occurrence)) in path.iter().enumerate() {
        let Some(field) =
            find_field_by_number_occurrence(patch, msg, field_number, occurrence)?
        else {
            return Ok(current.map(|fid| (fid, expanded)));
        };
        current = Some(field);

        let is_last = i + 1 == path.len();
        let tag = patch.field_tag(field)?;
        if tag.wire_type() != WireType::Len {
            if !is_last {
                break;
            }
            continue;
        }

        match patch.parse_child_message(field) {
            Ok(child) => {
                expanded.insert(field);
                if !is_last {
                    msg = child;
                }
            }
            Err(_) if !is_last => {
                if try_decode_and_parse(patch, field)? {
                    let child = patch.parse_child_message(field)?;
                    expanded.insert(field);
                    msg = child;
                } else {
                    break;
                }
            }
            Err(_) => {}
        }
    }

    Ok(current.map(|fid| (fid, expanded)))
}

fn try_decode_and_parse(patch: &mut Patch, field: FieldId) -> Result<bool, TreeError> {
    let bytes = patch.bytes(field)?.to_vec();
    let text = match core::str::from_utf8(&bytes) {
        Ok(s) => s.to_string(),
        Err(_) => return Ok(false),
    };

    let decoded = match crate::decode::decode_user_input(&text) {
        Ok(v) => v,
        Err(_) => return Ok(false),
    };

    if decoded == bytes {
        return Ok(false);
    }

    let buf = Buf::from(decoded);
    patch.set_bytes(field, buf)?;
    Ok(true)
}
