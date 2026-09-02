use protobuf_edit::session::grouped::{EditStatus, Session};
use protobuf_edit::session::Handle;
use rustc_hash::FxHashSet;

/// True when the row is presentable: not shrouded, not an insertion
/// ghost, not orphaned by a payload replacement. The session keeps
/// all of those in its chains; presentation filters here.
pub(crate) fn is_shown(session: &Session, handle: Handle) -> bool {
    matches!(
        session.status(handle),
        Ok(EditStatus::Intact | EditStatus::Replaced | EditStatus::Inserted)
    )
}

/// Presentable records of one layer, in wire order: the top layer
/// for `None`, the container's materialized children otherwise (a
/// LEN yields nothing until descended).
pub(crate) fn shown_children(
    session: &Session,
    parent: Option<Handle>,
) -> impl Iterator<Item = Handle> {
    let iter = match parent {
        None => Some(session.top()),
        Some(handle) => session.children(handle).ok(),
    };
    iter.into_iter().flatten().filter(move |&handle| is_shown(session, handle))
}

/// Every materialized descendant of `handle`, ghosts included — the
/// UI prunes its handle sets by this list when a container's payload
/// is replaced, cleared, or deleted.
pub(crate) fn collect_descendants(session: &Session, handle: Handle, out: &mut Vec<Handle>) {
    let Ok(children) = session.children(handle) else {
        return;
    };
    for child in children {
        out.push(child);
        collect_descendants(session, child, out);
    }
}

/// Presentable records in tree display order (expanded subtrees
/// inlined), for keyboard navigation.
pub(crate) fn collect_visible_fields(
    session: &Session,
    parent: Option<Handle>,
    expanded: &FxHashSet<Handle>,
    out: &mut Vec<Handle>,
) {
    for handle in shown_children(session, parent) {
        out.push(handle);
        if expanded.contains(&handle) {
            collect_visible_fields(session, Some(handle), expanded, out);
        }
    }
}
