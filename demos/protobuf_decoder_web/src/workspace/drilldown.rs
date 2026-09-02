use super::is_shown;
use protobuf_edit::session::grouped::{Descent, RecordSpans, Session};
use protobuf_edit::session::Handle;
use protobuf_edit::wire::grouped::RecordKind;

/// Resolves a hex-grid byte to the deepest record containing it,
/// descending LEN payloads on the way (group interiors are already
/// materialized, so `narrowest` sees through them by itself).
/// Returns the record plus its container chain for the tree to
/// expand.
pub(crate) fn drilldown_byte(session: &mut Session, idx: usize) -> (Option<Handle>, Vec<Handle>) {
    let Ok(pos) = u32::try_from(idx) else {
        return (None, Vec::new());
    };

    let mut current: Option<Handle> = None;
    // After each successful descend `narrowest` lands strictly
    // deeper; the bound mirrors the tree's own depth tolerance.
    for _ in 0..128 {
        let Some(handle) = session.narrowest(pos) else { break };
        if current == Some(handle) {
            break;
        }
        current = Some(handle);

        if session.kind(handle) != Ok(RecordKind::Len) {
            break;
        }
        let payload_hit = matches!(
            session.source_spans(handle),
            Ok(Some(RecordSpans::Len { payload, .. }))
                if payload.start() <= pos && pos < payload.end()
        );
        if !payload_hit {
            break;
        }
        if !matches!(session.descend(handle), Ok(Descent::Opened { .. })) {
            break;
        }
    }

    // A shrouded record is not selectable; its nearest presentable
    // ancestor answers instead.
    while let Some(handle) = current {
        if is_shown(session, handle) {
            break;
        }
        current = session.parent(handle).ok().flatten();
    }

    let expand = current.map_or_else(Vec::new, |handle| {
        session.ancestors(handle).ok().into_iter().flatten().collect()
    });
    (current, expand)
}
