//! Contract pins for the groupless designation carrier: minting
//! refusals, projection contracts, the canonical judgment at each
//! padded stage, and the dialect widening. Hosts supply the mints,
//! so each row rides the feature of the host it exercises.

#[cfg(feature = "inspect-groupless")]
mod minted_by_inspect {
    use alloc::vec::Vec;

    use crate::source::groupless::Fault;
    use crate::wire::groupless::RecordKind;
    use crate::{DepthLimit, Stage};
    use crate::inspect::groupless::Tree;
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
    fn a_clipped_row_refuses_to_mint() {
        use crate::inspect::{Advice, Advisor, Ancestry};
        use crate::wire::FieldNumber;

        struct CommitAll;
        impl Advisor for CommitAll {
            fn advise(&mut self, _outer: Ancestry<'_>, _field: FieldNumber) -> Advice {
                Advice::Commit
            }
        }

        // varint f1=42 complete, then a committed LEN f2 whose
        // interior cuts a record short: the parse clips the open
        // container at the fault boundary.
        let data = [0x08, 0x2A, 0x12, 0x01, 0x08];
        let t = Tree::parse(
            Admitted::new(&data).expect("test input admitted"),
            DepthLimit::REFERENCE,
            &mut CommitAll,
        );
        let tops: Vec<_> = t.top().collect();
        assert!(t.record_ref(tops[0]).is_ok(), "the complete prefix row mints");
        assert!(
            matches!(t.record_ref(tops[1]), Err(Fault::IncompleteRecord { at: 4 })),
            "the clipped row refuses at the parse boundary"
        );
    }

    #[test]
    fn projections_answer_the_stored_facts() {
        // LEN f2 "hi" with a padded length prefix (two bytes for 2).
        let data = [0x12, 0x82, 0x00, 0x68, 0x69];
        let t = tree(&data);
        let record = t.record_ref(t.top().next().unwrap()).unwrap();
        assert_eq!(record.as_bytes(), data);
        assert_eq!(record.field().as_inner(), 2);
        assert_eq!(record.kind(), RecordKind::Len);
        let payload = record.payload().unwrap();
        assert_eq!(payload.as_bytes(), [0x68, 0x69]);
        assert_eq!(payload.len(), 2);
        assert!(!payload.is_empty());
    }

    #[test]
    fn payload_refuses_non_len_kinds() {
        let data = [0x08, 0x2A];
        let t = tree(&data);
        let record = t.record_ref(t.top().next().unwrap()).unwrap();
        assert!(matches!(record.payload(), Err(Fault::KindMismatch { have: RecordKind::Varint })));
    }

    #[test]
    fn the_canonical_judgment_refuses_each_padded_stage() {
        // Padded head tag.
        let padded_tag = [0x88, 0x00, 0x01];
        let t = tree(&padded_tag);
        let record = t.record_ref(t.top().next().unwrap()).unwrap();
        assert!(matches!(
            record.try_canonical(),
            Err(Fault::StandardMismatch { at: 0, stage: Stage::Tag })
        ));

        // Padded varint value.
        let padded_value = [0x08, 0x96, 0x81, 0x00];
        let t = tree(&padded_value);
        let record = t.record_ref(t.top().next().unwrap()).unwrap();
        assert!(matches!(
            record.try_canonical(),
            Err(Fault::StandardMismatch { at: 1, stage: Stage::Value { field } })
                if field.as_inner() == 1
        ));

        // Padded LEN length prefix.
        let padded_prefix = [0x12, 0x82, 0x00, 0x68, 0x69];
        let t = tree(&padded_prefix);
        let record = t.record_ref(t.top().next().unwrap()).unwrap();
        assert!(matches!(
            record.try_canonical(),
            Err(Fault::StandardMismatch { at: 1, stage: Stage::LenPrefix { field } })
                if field.as_inner() == 2
        ));
    }

    #[test]
    fn the_canonical_judgment_leaves_len_interiors_opaque() {
        // LEN f2 whose interior bytes are a padded varint record:
        // payload bytes, not framing — the proof lands.
        let data = [0x12, 0x04, 0x08, 0x96, 0x81, 0x00];
        let t = tree(&data);
        let record = t.record_ref(t.top().next().unwrap()).unwrap();
        let canonical = record.try_canonical().unwrap();
        assert_eq!(canonical.as_bytes(), data);
        assert_eq!(canonical.record_ref().as_bytes(), data);
        assert_eq!(canonical.field().as_inner(), 2);
        assert_eq!(canonical.kind(), RecordKind::Len);
        assert_eq!(canonical.payload().unwrap().as_bytes(), [0x08, 0x96, 0x81, 0x00]);
    }

    #[cfg(feature = "inspect-grouped")]
    #[test]
    fn widening_is_judgment_free_and_exact() {
        let data = [0x12, 0x02, 0x68, 0x69];
        let t = tree(&data);
        let record = t.record_ref(t.top().next().unwrap()).unwrap();
        let widened = record.widen();
        assert_eq!(widened.as_bytes(), data);
        assert_eq!(widened.field().as_inner(), 2);
        assert_eq!(widened.kind(), crate::wire::grouped::RecordKind::Len);
        assert_eq!(widened.group_depth(), 0);
        assert_eq!(widened.payload().unwrap().as_bytes(), [0x68, 0x69]);
    }
}

#[cfg(feature = "retain-groupless")]
mod minted_by_retain {
    use alloc::vec;

    use crate::DepthLimit;
    use crate::retain::NoAdvice;
    use crate::retain::groupless::Retained;
    use crate::source::groupless::Fault;
    use crate::wire::groupless::RecordKind;

    #[test]
    fn the_owned_product_mints_the_same_designation() {
        let tree =
            Retained::parse(vec![0x08, 0x96, 0x01], DepthLimit::REFERENCE, &mut NoAdvice).unwrap();
        let record = tree.record_ref(tree.top().next().unwrap()).unwrap();
        assert_eq!(record.as_bytes(), [0x08, 0x96, 0x01]);
        assert_eq!(record.kind(), RecordKind::Varint);
    }

    #[test]
    fn a_clipped_row_refuses_to_mint() {
        use crate::retain::{Advice, Advisor, Ancestry};
        use crate::wire::FieldNumber;

        struct CommitAll;
        impl Advisor for CommitAll {
            fn advise(&mut self, _outer: Ancestry<'_>, _field: FieldNumber) -> Advice {
                Advice::Commit
            }
        }

        // A committed LEN whose interior cuts a record short: the
        // parse clips the open container at the fault boundary.
        let tree =
            Retained::parse(vec![0x12, 0x01, 0x08], DepthLimit::REFERENCE, &mut CommitAll).unwrap();
        assert!(matches!(
            tree.record_ref(tree.top().next().unwrap()),
            Err(Fault::IncompleteRecord { at: 2 })
        ));
    }
}

#[cfg(feature = "collect-groupless")]
mod minted_by_collect {
    use crate::collect::NoAdvice;
    use crate::collect::groupless::Collector;
    use crate::wire::groupless::RecordKind;
    use crate::{DepthLimit, Standard};

    #[test]
    fn the_collected_product_mints_the_same_designation() {
        let mut advice = NoAdvice;
        let mut collector = Collector::new(Standard::Tolerant, DepthLimit::REFERENCE, &mut advice);
        collector.feed(&[0x08, 0x96, 0x01]).unwrap();
        let tree = collector.finish();
        let record = tree.record_ref(tree.top().next().unwrap()).unwrap();
        assert_eq!(record.as_bytes(), [0x08, 0x96, 0x01]);
        assert_eq!(record.kind(), RecordKind::Varint);
    }
}

#[cfg(feature = "patch-groupless")]
mod minted_by_the_one_shot_editors {
    use alloc::vec::Vec;

    use crate::DepthLimit;
    use crate::patch::groupless::{InsertAt, Patch};
    use crate::source::groupless::Fault;
    use crate::wire::FieldNumber;

    #[test]
    fn the_designation_names_source_bytes_never_the_pending_edit() {
        let msg = [0x08, 0x96, 0x81, 0x00];
        let mut patch = Patch::open(&msg, DepthLimit::REFERENCE).unwrap();
        let record = patch.top().next().unwrap();
        patch.set_varint(record, 7).unwrap();
        let designation = patch.record_ref(record).unwrap();
        assert_eq!(designation.as_bytes(), msg, "the source reading rides, padding included");
    }

    #[test]
    fn authored_and_deleted_rows_refuse_to_mint() {
        let msg = [0x08, 0x2A, 0x10, 0x2A];
        let mut patch = Patch::open(&msg, DepthLimit::REFERENCE).unwrap();
        let field = FieldNumber::new(3).unwrap();
        let authored = patch.insert_varint(InsertAt::TailOf(None), field, 5).unwrap();
        assert!(matches!(patch.record_ref(authored), Err(Fault::NotSourceBacked)));

        let tops: Vec<_> = patch.top().collect();
        patch.delete(tops[1]).unwrap();
        assert!(matches!(patch.record_ref(tops[1]), Err(Fault::NotSourceBacked)));
    }
}

#[cfg(feature = "session-groupless")]
mod minted_by_the_revisable_editors {
    use alloc::vec::Vec;

    use crate::session::groupless::Session;
    use crate::source::groupless::Fault;

    #[test]
    fn the_canonical_admission_proof_rides_the_mint() {
        let mut session = Session::open_copy(&[0x08, 0x2A, 0x12, 0x02, 0x68, 0x69]).unwrap();
        let tops: Vec<_> = session.top().collect();
        let record = session.record_ref(tops[0]).unwrap();
        assert!(record.try_canonical().is_ok(), "canonical admission is the proof");

        // The designation still names the source reading on an
        // edited handle.
        session.set_varint(tops[0], 7).unwrap();
        assert_eq!(session.record_ref(tops[0]).unwrap().as_bytes(), [0x08, 0x2A]);
    }

    #[test]
    fn shrouded_and_orphaned_rows_refuse_to_mint() {
        use crate::session::groupless::Descent;

        let mut session = Session::open_copy(&[0x08, 0x2A, 0x12, 0x02, 0x08, 0x01]).unwrap();
        let tops: Vec<_> = session.top().collect();
        session.delete(tops[0]).unwrap();
        assert!(matches!(session.record_ref(tops[0]), Err(Fault::NotSourceBacked)));

        // Replacing a descended LEN's payload orphans its interior;
        // the orphan no longer designates.
        let Descent::Opened { first: Some(inner) } = session.descend(tops[1]).unwrap() else {
            unreachable!()
        };
        assert!(session.record_ref(inner).is_ok(), "the live interior row designates");
        session.set_payload(tops[1], &[0x08, 0x02]).unwrap();
        assert!(matches!(session.record_ref(inner), Err(Fault::NotSourceBacked)));
    }
}
