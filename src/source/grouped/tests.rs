//! Contract pins for the grouped designation carrier: the group
//! closure's projections and depth, the canonical judgment over
//! structural interiors, the dialect narrowing, and the minting
//! refusals the grouped hosts add (clipped groups). Hosts supply
//! the mints, so each row rides the feature of the host it
//! exercises.

#[cfg(feature = "inspect-grouped")]
mod minted_by_inspect {
    // Consumed by the dialect-narrowing row alone, which needs the
    // groupless twin in the build.
    #[cfg(feature = "inspect-groupless")]
    use alloc::vec::Vec;

    use crate::DepthLimit;
    use crate::source::grouped::Fault;
    use crate::wire::grouped::RecordKind;
    use crate::inspect::grouped::Tree;
    use crate::inspect::{Admitted, NoAdvice};

    #[track_caller]
    fn tree(data: &[u8]) -> Tree<'_> {
        Tree::parse(
            Admitted::new(data).expect("test input admitted"),
            DepthLimit::REFERENCE,
            &mut NoAdvice,
        )
    }

    #[test]
    fn a_group_closure_travels_whole_with_its_depth() {
        // Group f1 { group f2 { varint f3=1 } · LEN f4 [ group bytes ] }.
        let data = [0x0B, 0x13, 0x18, 0x01, 0x14, 0x22, 0x02, 0x2B, 0x2C, 0x0C];
        let t = tree(&data);
        let record = t.record_ref(t.top().next().unwrap()).unwrap();
        assert_eq!(record.as_bytes(), data, "the closure carries its end tag");
        assert_eq!(record.kind(), RecordKind::Group);
        assert_eq!(
            record.group_depth(),
            2,
            "the LEN interior is opaque; only structural groups nest"
        );
        assert!(
            matches!(record.payload(), Err(Fault::KindMismatch { have: RecordKind::Group })),
            "a group's interior is structural wire, not a payload"
        );
    }

    #[test]
    fn a_clipped_group_refuses_to_mint() {
        // Group f1 opens, never closes: the parse clips it.
        let data = [0x0B, 0x08, 0x01];
        let t = tree(&data);
        assert!(matches!(
            t.record_ref(t.top().next().unwrap()),
            Err(Fault::IncompleteRecord { .. })
        ));
    }

    #[test]
    fn the_canonical_judgment_walks_the_structural_closure() {
        // Group f1 { LEN f2, padded prefix }: the prefix is framing
        // inside the closure, so the proof refuses there.
        let data = [0x0B, 0x12, 0x81, 0x00, 0x2A, 0x0C];
        let t = tree(&data);
        let record = t.record_ref(t.top().next().unwrap()).unwrap();
        assert!(matches!(record.try_canonical(), Err(Fault::StandardMismatch { at: 2, .. })));

        // The same shape with minimal framing proves, and the LEN
        // interior stays opaque whatever bytes it holds.
        let minimal = [0x0B, 0x12, 0x02, 0x88, 0x00, 0x0C];
        let t = tree(&minimal);
        let record = t.record_ref(t.top().next().unwrap()).unwrap();
        assert!(record.try_canonical().is_ok());
    }

    #[test]
    fn the_canonical_judgment_reaches_group_end_tags() {
        // Group f1 { } with its end tag padded to two bytes: lawful
        // tolerant wire, refused by the proof at the end tag.
        let data = [0x0B, 0x8C, 0x00];
        let t = tree(&data);
        let record = t.record_ref(t.top().next().unwrap()).unwrap();
        assert!(matches!(
            record.try_canonical(),
            Err(Fault::StandardMismatch { at: 1, stage: crate::Stage::Tag })
        ));
    }

    #[cfg(feature = "inspect-groupless")]
    #[test]
    fn narrowing_needs_the_common_kind_proof() {
        // A group refuses; a common-kind record narrows exactly.
        let data = [0x0B, 0x0C, 0x12, 0x02, 0x68, 0x69];
        let t = tree(&data);
        let tops: Vec<_> = t.top().collect();

        let group = t.record_ref(tops[0]).unwrap();
        assert!(matches!(
            group.try_groupless(),
            Err(Fault::DialectMismatch { have: RecordKind::Group })
        ));

        let len = t.record_ref(tops[1]).unwrap();
        let narrowed = len.try_groupless().unwrap();
        assert_eq!(narrowed.as_bytes(), [0x12, 0x02, 0x68, 0x69]);
        assert_eq!(narrowed.kind(), crate::wire::groupless::RecordKind::Len);
        assert_eq!(narrowed.payload().unwrap().as_bytes(), [0x68, 0x69]);
    }
}

#[cfg(feature = "retain-grouped")]
mod minted_by_retain {
    use alloc::vec;

    use crate::DepthLimit;
    use crate::retain::NoAdvice;
    use crate::retain::grouped::Retained;
    use crate::wire::grouped::RecordKind;

    #[test]
    fn the_owned_product_mints_the_closure() {
        let tree =
            Retained::parse(vec![0x0B, 0x10, 0x05, 0x0C], DepthLimit::REFERENCE, &mut NoAdvice)
                .unwrap();
        let record = tree.record_ref(tree.top().next().unwrap()).unwrap();
        assert_eq!(record.as_bytes(), [0x0B, 0x10, 0x05, 0x0C]);
        assert_eq!(record.group_depth(), 1);
        assert_eq!(record.kind(), RecordKind::Group);
    }
}

#[cfg(feature = "collect-grouped")]
mod minted_by_collect {
    use crate::collect::NoAdvice;
    use crate::collect::grouped::Collector;
    use crate::wire::grouped::RecordKind;
    use crate::{DepthLimit, Standard};

    #[test]
    fn the_collected_product_mints_the_closure() {
        let mut advice = NoAdvice;
        let mut collector = Collector::new(Standard::Tolerant, DepthLimit::REFERENCE, &mut advice);
        collector.feed(&[0x0B, 0x10, 0x05, 0x0C]).unwrap();
        let tree = collector.finish();
        let record = tree.record_ref(tree.top().next().unwrap()).unwrap();
        assert_eq!(record.as_bytes(), [0x0B, 0x10, 0x05, 0x0C]);
        assert_eq!(record.group_depth(), 1);
        assert_eq!(record.kind(), RecordKind::Group);
    }
}

#[cfg(feature = "patch-grouped")]
mod minted_by_the_one_shot_editors {
    use alloc::vec::Vec;

    use crate::DepthLimit;
    use crate::patch::grouped::Patch;

    #[test]
    fn a_grouped_editor_designates_the_closure() {
        // Group f1 { group f2 { } } · varint f3=1.
        let msg = [0x0B, 0x13, 0x14, 0x0C, 0x18, 0x01];
        let patch = Patch::open(&msg, DepthLimit::REFERENCE).unwrap();
        let tops: Vec<_> = patch.top().collect();
        let record = patch.record_ref(tops[0]).unwrap();
        assert_eq!(record.as_bytes(), [0x0B, 0x13, 0x14, 0x0C]);
        assert_eq!(record.group_depth(), 2);
    }
}

#[cfg(feature = "session-grouped")]
mod minted_by_the_revisable_editors {
    use alloc::vec::Vec;

    use crate::session::grouped::Session;
    use crate::source::grouped::Fault;
    use crate::wire::grouped::RecordKind;

    #[test]
    fn the_canonical_grouped_mint_carries_the_closure_proof() {
        let mut session = Session::open_copy(&[0x0B, 0x10, 0x05, 0x0C, 0x08, 0x01]).unwrap();
        let tops: Vec<_> = session.top().collect();
        let record = session.record_ref(tops[0]).unwrap();
        assert_eq!(record.kind(), RecordKind::Group);
        assert_eq!(record.group_depth(), 1);
        assert!(record.try_canonical().is_ok());

        // The designation names the source reading on an edited
        // handle, and shrouded rows refuse.
        session.delete(tops[0]).unwrap();
        assert!(matches!(session.record_ref(tops[0]), Err(Fault::NotSourceBacked)));
    }
}
