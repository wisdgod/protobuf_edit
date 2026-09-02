use super::{is_shown, shown_children};
use protobuf_edit::session::grouped::{Descent, EditFault, Session};
use protobuf_edit::session::Handle;
use protobuf_edit::wire::grouped::{classify, RecordKind, TagClass};
use protobuf_edit::wire::{FieldNumber, Low3};
use rustc_hash::FxHashSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SelectionStep {
    pub field: FieldNumber,
    pub kind: RecordKind,
    pub occurrence: u32,
}

const fn is_container(kind: RecordKind) -> bool {
    matches!(kind, RecordKind::Len | RecordKind::Group)
}

/// Encodes a step as `field:code:occurrence` (`code` is the kind's
/// wire code), steps joined by `/`.
pub(crate) fn encode_selection_path(path: &[SelectionStep]) -> String {
    use core::fmt::Write as _;

    let mut out = String::new();
    for (i, step) in path.iter().enumerate() {
        if i != 0 {
            out.push('/');
        }
        let _ = write!(
            &mut out,
            "{}:{}:{}",
            step.field.as_inner(),
            step.kind.low3().as_inner(),
            step.occurrence
        );
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
        let wire_code = it.next()?.parse::<u8>().ok()?;
        let occurrence = it.next()?.parse::<u32>().ok()?;
        if it.next().is_some() {
            return None;
        }

        let field = FieldNumber::new(field_number)?;
        let TagClass::Record(kind) = classify(Low3::new(wire_code)?) else {
            return None;
        };
        out.push(SelectionStep { field, kind, occurrence });
    }

    Some(out)
}

/// The presentable sibling of the layer under `parent` matching the
/// step's field, kind, and occurrence.
fn find_step(session: &Session, parent: Option<Handle>, step: &SelectionStep) -> Option<Handle> {
    shown_children(session, parent)
        .filter(|&handle| {
            session.field(handle) == Ok(step.field) && session.kind(handle) == Ok(step.kind)
        })
        .nth(step.occurrence as usize)
}

pub(crate) fn build_selection_path(
    session: &Session,
    selected: Handle,
) -> Option<Vec<SelectionStep>> {
    let mut chain: Vec<Handle> =
        core::iter::once(selected).chain(session.ancestors(selected).ok()?).collect();
    chain.reverse();

    let mut out = Vec::with_capacity(chain.len());
    for handle in chain {
        let field = session.field(handle).ok()?;
        let kind = session.kind(handle).ok()?;
        let parent = session.parent(handle).ok()?;

        // Occurrence counts presentable rows of the same field and
        // kind, so a shrouded selection has no path.
        let mut occurrence: u32 = 0;
        let mut found = false;
        for sibling in shown_children(session, parent) {
            if session.field(sibling) != Ok(field) || session.kind(sibling) != Ok(kind) {
                continue;
            }
            if sibling == handle {
                found = true;
                break;
            }
            occurrence = occurrence.saturating_add(1);
        }
        if !found {
            return None;
        }

        out.push(SelectionStep { field, kind, occurrence });
    }
    Some(out)
}

/// Walks a selection path, descending containers on the way; the
/// returned set holds every container opened for the walk. `None`
/// when the path names no record in this session.
pub(crate) fn resolve_selection_path(
    session: &mut Session,
    path: &[SelectionStep],
    expand_last_container: bool,
) -> Option<(Handle, FxHashSet<Handle>)> {
    let mut parent: Option<Handle> = None;
    let mut expanded: FxHashSet<Handle> = FxHashSet::default();
    let mut current: Option<Handle> = None;

    for (i, step) in path.iter().enumerate() {
        let handle = find_step(session, parent, step)?;
        current = Some(handle);

        let is_last = i + 1 == path.len();
        if is_last {
            if expand_last_container
                && is_container(step.kind)
                && matches!(session.descend(handle), Ok(Descent::Opened { .. }))
            {
                expanded.insert(handle);
            }
            break;
        }

        if !is_container(step.kind) {
            break;
        }
        if !matches!(session.descend(handle), Ok(Descent::Opened { .. })) {
            break;
        }
        expanded.insert(handle);
        parent = Some(handle);
    }

    current.map(|handle| (handle, expanded))
}

/// Parse a user path like ".3:0.1.2" into (`field_number`, occurrence) pairs.
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
        let field = FieldNumber::new(num_str.parse::<u32>().ok()?)?;
        out.push((field.as_inner(), occ));
    }
    Some(out)
}

/// Format a user-friendly path string like ".3.1.2" for a given record.
pub(crate) fn format_user_path(session: &Session, handle: Handle) -> Option<String> {
    let steps = build_selection_path(session, handle)?;
    let mut out = String::new();
    for step in &steps {
        out.push('.');
        use core::fmt::Write as _;
        let _ = write!(out, "{}", step.field.as_inner());
        if step.occurrence > 0 {
            let _ = write!(out, ":{}", step.occurrence);
        }
    }
    if out.is_empty() {
        return Some(".".to_string());
    }
    Some(out)
}

/// The `occurrence`-th presentable record of field `field_number` in
/// the layer under `parent`, whatever its kind.
fn find_by_number_occurrence(
    session: &Session,
    parent: Option<Handle>,
    field_number: u32,
    occurrence: u32,
) -> Option<Handle> {
    let field = FieldNumber::new(field_number)?;
    shown_children(session, parent)
        .filter(|&handle| session.field(handle) == Ok(field))
        .nth(occurrence as usize)
}

/// Resolve a user path, descending containers on the way. For LEN
/// records that don't open as protobuf directly, tries decoding the
/// payload as hex/base64 first (via `decode_user_input`).
pub(crate) fn resolve_user_path(
    session: &mut Session,
    path: &[(u32, u32)],
) -> Result<Option<(Handle, FxHashSet<Handle>)>, EditFault> {
    let mut parent: Option<Handle> = None;
    let mut expanded: FxHashSet<Handle> = FxHashSet::default();
    let mut current: Option<Handle> = None;

    for (i, &(field_number, occurrence)) in path.iter().enumerate() {
        let Some(handle) = find_by_number_occurrence(session, parent, field_number, occurrence)
        else {
            return Ok(current.map(|h| (h, expanded)));
        };
        current = Some(handle);

        let is_last = i + 1 == path.len();
        let kind = session.kind(handle)?;
        if !is_container(kind) {
            if !is_last {
                break;
            }
            continue;
        }

        let opened = matches!(session.descend(handle)?, Descent::Opened { .. });
        if opened {
            expanded.insert(handle);
            if !is_last {
                parent = Some(handle);
            }
        } else if !is_last {
            if try_decode_and_descend(session, handle)? {
                expanded.insert(handle);
                parent = Some(handle);
            } else {
                break;
            }
        }
    }

    Ok(current.map(|h| (h, expanded)))
}

fn try_decode_and_descend(session: &mut Session, handle: Handle) -> Result<bool, EditFault> {
    // The copy is required: `set_payload` below needs `&mut` while
    // the original payload borrows the session.
    let bytes = session.payload_bytes(handle)?.to_vec();
    let Ok(text) = is_valid_utf8::validate_utf8(&bytes) else {
        return Ok(false);
    };

    let Ok(decoded) = crate::decode::decode_user_input(text) else { return Ok(false) };

    if decoded == bytes {
        return Ok(false);
    }

    session.set_payload(handle, &decoded)?;
    Ok(matches!(session.descend(handle)?, Descent::Opened { .. }))
}

/// Keeps `selected` only while it still names a presentable row.
pub(crate) fn selection_if_shown(session: &Session, selected: Option<Handle>) -> Option<Handle> {
    selected.filter(|&handle| is_shown(session, handle))
}
