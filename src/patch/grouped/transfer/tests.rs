//! The transfer sibling's behavioral rows.

use super::*;
#[allow(unused_imports)]
use super::super::tests::*;

fn open(data: &[u8]) -> TransferPatch<'_, 'static> {
    TransferPatch::open(data, DepthLimit::REFERENCE).expect("test document opens")
}

fn tops(p: &TransferPatch<'_, '_>) -> Vec<Handle> {
    p.top().collect()
}

#[track_caller]
fn saved(p: &TransferPatch<'_, '_>) -> Vec<u8> {
    p.save().expect("test save succeeds")
}

#[test]
fn a_copied_group_closure_rides_byte_exact_with_padded_framing() {
    // Group f1 (open tag padded) { varint f2 padded } end tag
    // padded — every framing word carries met widths.
    let group = h("8B 00 10 81 00 8C 00");
    let mut data = h("18 07 ");
    data.extend_from_slice(&group);
    let mut p = open(&data);
    let t = tops(&p);
    let copy = p.copy_record(t[1], InsertAt::HeadOf(None)).unwrap();

    assert_eq!(p.status(copy), EditStatus::Inserted);
    assert_eq!(p.span(copy), None);
    let spans = p.save_spans().unwrap();
    let (_, span) = spans.iter().find(|(handle, _)| *handle == copy).unwrap();
    let out = saved(&p);
    assert_eq!(&out[span.as_range()], group.as_slice(), "group closure fidelity");

    // The clone is structural and first-class: its interior is
    // walkable and editable, and the edit stays on the copy.
    let kid = p.children(copy).next().unwrap();
    assert_eq!(p.status(kid), EditStatus::Inserted);
    p.set_varint(kid, 5).unwrap();
    assert_eq!(saved(&p), h("8B 00 10 05 8C 00 18 07 8B 00 10 81 00 8C 00"));
}
#[test]
fn grouped_move_equals_copy_plus_delete_on_a_fresh_twin() {
    // Group f1 { group f2 { varint f3 } } · varint f4 · LEN f5.
    let data = h("0B 13 18 01 14 0C 20 07 2A 01 61");
    for source in 0..3usize {
        for target in 0..3usize {
            if source == target {
                continue;
            }
            let mut moved = open(&data);
            let t = tops(&moved);
            moved.move_record(t[source], InsertAt::After(t[target])).unwrap();

            let mut twin = open(&data);
            let t = tops(&twin);
            twin.copy_record(t[source], InsertAt::After(t[target])).unwrap();
            twin.delete(t[source]).unwrap();

            assert_eq!(
                moved.save().unwrap(),
                twin.save().unwrap(),
                "grouped move({source}) after {target} diverged from copy+delete"
            );
        }
    }
}
#[test]
fn moving_a_group_into_its_own_interior_refuses() {
    let data = h("0B 13 18 01 14 0C");
    let mut p = open(&data);
    let t = tops(&p);
    let inner_group = p.children(t[0]).next().unwrap();
    assert!(matches!(
        p.move_record(t[0], InsertAt::TailOf(Some(inner_group))),
        Err(EditFault::MoveIntoSource)
    ));
    // Moving the inner group out of its parent is lawful.
    let dest = p.move_record(inner_group, InsertAt::TailOf(None)).unwrap();
    assert_eq!(p.status(dest), EditStatus::Inserted);
    assert_eq!(saved(&p), h("0B 0C 13 18 01 14"));
}
#[cfg(feature = "inspect-grouped")]
#[test]
fn an_imported_group_rides_byte_exact_and_canonicalizes() {
    use crate::inspect::grouped::Tree;
    use crate::inspect::{Admitted, NoAdvice};

    // A foreign group with padded interior framing.
    let foreign = h("8B 00 10 81 00 8C 00");
    let input = Admitted::new(&foreign).unwrap();
    let tree = Tree::parse(input, DepthLimit::REFERENCE, &mut NoAdvice);
    let record = tree.record_ref(tree.top().next().unwrap()).unwrap();
    assert_eq!(record.group_depth(), 1);

    let data = h("18 07");
    let mut p = open(&data);
    let imported = p.copy_record_from(record, InsertAt::TailOf(None)).unwrap();
    assert_eq!(p.status(imported), EditStatus::Inserted);
    assert_eq!(saved(&p), h("18 07 8B 00 10 81 00 8C 00"));
    assert_eq!(
        p.save_canonical().unwrap(),
        h("18 07 0B 10 01 0C"),
        "the canonical save re-encodes the whole imported closure minimally"
    );
}
#[cfg(feature = "inspect-grouped")]
#[test]
fn imported_group_interiors_edit_after_descent() {
    use crate::inspect::grouped::Tree;
    use crate::inspect::{Admitted, NoAdvice};

    // A non-empty foreign group closure.
    let foreign = h("0B 10 05 1B 10 01 1C 0C");
    let input = Admitted::new(&foreign).unwrap();
    let tree = Tree::parse(input, DepthLimit::REFERENCE, &mut NoAdvice);
    let record = tree.record_ref(tree.top().next().unwrap()).unwrap();

    let data = h("08 01");
    let mut p = open(&data);
    let imported = p.copy_record_from(record, InsertAt::TailOf(None)).unwrap();
    // An undescended import stays sealed: a splice needs the parsed
    // interior chain, so the gate asks for the descent first.
    assert!(matches!(
        p.insert_varint(InsertAt::TailOf(Some(imported)), fnum(2), 9),
        Err(EditFault::TargetUnopened)
    ));
    assert_eq!(saved(&p), h("08 01 0B 10 05 1B 10 01 1C 0C"), "clean imports ride byte-exact");

    // The descent parses the slot's closure between the met tags into
    // first-class rows: edits and splices land, and the save keeps
    // both met tags around the walked interior.
    let Descent::Opened { first: Some(inner) } = p.descend(imported).unwrap() else {
        panic!("imported group interior opens")
    };
    assert_eq!(p.varint_word(inner), Some(5));
    p.set_varint(inner, 9).unwrap();
    assert_eq!(saved(&p), h("08 01 0B 10 09 1B 10 01 1C 0C"));
    p.insert_varint(InsertAt::TailOf(Some(imported)), fnum(2), 9).unwrap();
    assert_eq!(saved(&p), h("08 01 0B 10 09 1B 10 01 1C 10 09 0C"));

    // The copied backing policy opens identically.
    let mut c = TransferPatch::open(&data, DepthLimit::REFERENCE).expect("test document opens");
    let imported = c.copy_record_from(record, InsertAt::TailOf(None)).unwrap();
    let Descent::Opened { first: Some(_) } = c.descend(imported).unwrap() else {
        panic!("imported group interior opens")
    };
    c.insert_varint(InsertAt::TailOf(Some(imported)), fnum(2), 9).unwrap();
    let mut out = Vec::new();
    c.save_into(&mut out).unwrap();
    assert_eq!(out, h("08 01 0B 10 05 1B 10 01 1C 10 09 0C"));
}
#[cfg(feature = "inspect-grouped")]
#[test]
fn designation_depth_ignores_authored_copied_and_imported_structure() {
    use crate::inspect::grouped::Tree;
    use crate::inspect::{Admitted, NoAdvice};

    // group f1 { varint f2=5 } · group f3 {} — each closure depth 1.
    let data = h("0B 10 05 0C 1B 1C");
    let mut p = open(&data);
    let t = tops(&p);
    assert_eq!(p.record_ref(t[0]).unwrap().group_depth(), 1);

    // An authored group, a copied closure, and an imported closure
    // land inside the designated group; the designation still names
    // the source reading.
    p.insert_group(InsertAt::TailOf(Some(t[0])), fnum(9)).unwrap();
    p.copy_record(t[1], InsertAt::TailOf(Some(t[0]))).unwrap();
    let foreign = h("2B 2C");
    let input = Admitted::new(&foreign).unwrap();
    let tree = Tree::parse(input, DepthLimit::REFERENCE, &mut NoAdvice);
    let record = tree.record_ref(tree.top().next().unwrap()).unwrap();
    p.copy_record_from(record, InsertAt::TailOf(Some(t[0]))).unwrap();
    assert_eq!(p.record_ref(t[0]).unwrap().group_depth(), 1);
    // The effective structure did deepen: the copy nested a group.
    assert_eq!(p.save().unwrap(), h("0B 10 05 4B 4C 1B 1C 2B 2C 0C 1B 1C"));
}
#[cfg(feature = "inspect-grouped")]
#[test]
fn transfers_spend_the_destination_depth_account() {
    use crate::inspect::grouped::Tree;
    use crate::inspect::{Admitted, NoAdvice};

    // Two sibling depth-1 group closures.
    let data = h("0B 0C 13 14");
    let two = DepthLimit::new(2).unwrap();

    // Local copy, exact limit: a depth-1 closure under a depth-1
    // parent needs exactly two, and the save re-opens under the
    // same bound.
    let mut p = TransferPatch::open(&data, two).unwrap();
    let t: Vec<_> = p.top().collect();
    let alias = p.copy_record(t[0], InsertAt::TailOf(Some(t[1]))).unwrap();
    // One past: the same closure one level deeper.
    assert!(matches!(
        p.copy_record(t[0], InsertAt::TailOf(Some(alias))),
        Err(EditFault::DepthExceeded { limit: 2, need: 3 })
    ));
    let out = saved(&p);
    assert_eq!(out, h("0B 0C 13 0B 0C 14"));
    assert!(TransferPatch::open(&out, two).is_ok());

    // Local copy and move, one past the minimum bound: the input is
    // lawful at depth one, and the transfer refuses instead of
    // saving a document the same limit cannot re-open.
    let mut p = TransferPatch::open(&data, DepthLimit::MIN).unwrap();
    let t: Vec<_> = p.top().collect();
    assert!(matches!(
        p.copy_record(t[0], InsertAt::TailOf(Some(t[1]))),
        Err(EditFault::DepthExceeded { limit: 1, need: 2 })
    ));
    assert!(matches!(
        p.move_record(t[0], InsertAt::TailOf(Some(t[1]))),
        Err(EditFault::DepthExceeded { limit: 1, need: 2 })
    ));
    // The move twin at its exact limit.
    let mut p = TransferPatch::open(&data, two).unwrap();
    let t: Vec<_> = p.top().collect();
    p.move_record(t[0], InsertAt::TailOf(Some(t[1]))).unwrap();
    let out = saved(&p);
    assert_eq!(out, h("13 0B 0C 14"));
    assert!(TransferPatch::open(&out, two).is_ok());

    // Borrowed and copied imports spend the same account.
    let foreign = h("2B 2C");
    let input = Admitted::new(&foreign).unwrap();
    let tree = Tree::parse(input, DepthLimit::REFERENCE, &mut NoAdvice);
    let record = tree.record_ref(tree.top().next().unwrap()).unwrap();
    let mut p = TransferPatch::open(&data, two).unwrap();
    let t: Vec<_> = p.top().collect();
    p.copy_record_from(record, InsertAt::TailOf(Some(t[1]))).unwrap();
    let out = saved(&p);
    assert_eq!(out, h("0B 0C 13 2B 2C 14"));
    assert!(TransferPatch::open(&out, two).is_ok());
    let mut p = TransferPatch::open(&data, DepthLimit::MIN).unwrap();
    let t: Vec<_> = p.top().collect();
    assert!(matches!(
        p.copy_record_from(record, InsertAt::TailOf(Some(t[1]))),
        Err(EditFault::DepthExceeded { limit: 1, need: 2 })
    ));
    let mut c = TransferPatch::open(&data, DepthLimit::MIN).unwrap();
    let t: Vec<_> = c.top().collect();
    assert!(matches!(
        c.copy_record_from(record, InsertAt::TailOf(Some(t[1]))),
        Err(EditFault::DepthExceeded { limit: 1, need: 2 })
    ));

    // A committed-LEN parent charges its own container level: the
    // interior group sits two containers deep, so the closure needs
    // three.
    let data = h("12 02 0B 0C 1B 1C");
    let three = DepthLimit::new(3).unwrap();
    let mut p = TransferPatch::open(&data, three).unwrap();
    let t: Vec<_> = p.top().collect();
    let Descent::Opened { first: Some(inner) } = p.descend(t[0]).unwrap() else { unreachable!() };
    p.copy_record(t[1], InsertAt::TailOf(Some(inner))).unwrap();
    let out = saved(&p);
    assert_eq!(out, h("12 04 0B 1B 1C 0C 1B 1C"));
    assert!(TransferPatch::open(&out, three).is_ok());
    let mut p = TransferPatch::open(&data, two).unwrap();
    let t: Vec<_> = p.top().collect();
    let Descent::Opened { first: Some(inner) } = p.descend(t[0]).unwrap() else { unreachable!() };
    assert!(matches!(
        p.copy_record(t[1], InsertAt::TailOf(Some(inner))),
        Err(EditFault::DepthExceeded { limit: 2, need: 3 })
    ));
}
