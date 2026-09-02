//! The auto-trait face as contract: every public type's `Send` and
//! `Sync` standing is adjudicated here, so a drift — a `Cell`
//! slipping into a borrowed machine, or the share counter leaving
//! the owned one — is a red test, not a silent semver break.
//!
//! The intent matrix: every public type is `Send + Sync` — the
//! borrowed machines close over `&[u8]` and plain data — except
//! the owned editing core: `session::DocBytes` counts shares in a
//! `Cell` by design (single-threaded editing), so it and the
//! sessions that own it are deliberately neither. The session
//! views (`Children`, `Ancestors`, `Descent`) borrow the row
//! table, not the shared carrier, so they stay on the positive
//! side. The negative side — `session::DocBytes`,
//! `session::grouped::Session`, `session::groupless::Session`,
//! their borrowed-payload and mixed-backing siblings
//! (`session::grouped::BorrowSession`,
//! `session::groupless::BorrowSession`,
//! `session::grouped::MixSession`,
//! `session::groupless::MixSession`, which own the same carrier),
//! and the payload frames that exclusively borrow the copy-only
//! and mixed machines (`session::grouped::PayloadFrame`,
//! `session::groupless::PayloadFrame`,
//! `session::grouped::SizedPayloadFrame`,
//! `session::groupless::SizedPayloadFrame`,
//! `session::grouped::MixPayloadFrame`,
//! `session::groupless::MixPayloadFrame`,
//! `session::grouped::MixSizedPayloadFrame`,
//! `session::groupless::MixSizedPayloadFrame`), and the transfer
//! siblings that own or exclusively borrow the same carrier
//! (`session::grouped::transfer::TransferSession`,
//! `session::groupless::transfer::TransferSession`,
//! `session::grouped::transfer::TransferBorrowSession`,
//! `session::groupless::transfer::TransferBorrowSession`,
//! `session::grouped::transfer::PayloadFrame`,
//! `session::groupless::transfer::PayloadFrame`,
//! `session::grouped::transfer::SizedPayloadFrame`,
//! `session::groupless::transfer::SizedPayloadFrame`, and the
//! priced transfer wrappers and their frames over the same carrier:
//! `session::grouped::transfer::PricedTransferSession`,
//! `session::groupless::transfer::PricedTransferSession`,
//! `session::grouped::transfer::PricedPayloadFrame`,
//! `session::groupless::transfer::PricedPayloadFrame`,
//! `session::grouped::transfer::PricedSizedPayloadFrame`,
//! `session::groupless::transfer::PricedSizedPayloadFrame`) — is pinned
//! by `compile_fail` doctests on those types themselves; the
//! positive side is pinned here, fully qualified, and the roster
//! is held complete by the public-type census in `coordinates.rs`
//! (qualified names, because bare ones shadow across dialects).

const fn send_and_sync<T: Send + Sync>() {}

#[test]
fn the_strata_vocabulary_is_send_and_sync() {
    send_and_sync::<protobuf_edit::DepthLimit>();
    send_and_sync::<protobuf_edit::FaultClass>();
    send_and_sync::<protobuf_edit::Stage>();
    send_and_sync::<protobuf_edit::Standard>();
    send_and_sync::<protobuf_edit::Span>();
    send_and_sync::<protobuf_edit::wire::FieldNumber>();
    send_and_sync::<protobuf_edit::wire::PayloadLen>();
    send_and_sync::<protobuf_edit::wire::Low3>();
    send_and_sync::<protobuf_edit::path::Segment<'static>>();
    send_and_sync::<protobuf_edit::path::Crossing>();
    send_and_sync::<protobuf_edit::path::PathId>();
    send_and_sync::<protobuf_edit::path::Program<'static>>();
    send_and_sync::<protobuf_edit::path::ProgramError>();
}

// The conditional substrate leaves follow their own gates: each
// row compiles under its leaf's direct-selection feature (the
// all-features battery pins the union; narrow cells compile the
// subset their gates admit).
#[cfg(feature = "wire-grouped")]
#[test]
fn the_grouped_wire_table_is_send_and_sync() {
    send_and_sync::<protobuf_edit::wire::grouped::RecordKind>();
    send_and_sync::<protobuf_edit::wire::grouped::TagClass>();
}

#[cfg(feature = "wire-groupless")]
#[test]
fn the_groupless_wire_table_is_send_and_sync() {
    send_and_sync::<protobuf_edit::wire::groupless::RecordKind>();
    send_and_sync::<protobuf_edit::wire::groupless::TagClass>();
}

#[cfg(feature = "varint-carry")]
#[test]
fn the_carry_kernel_is_send_and_sync() {
    send_and_sync::<protobuf_edit::varint::carry::Carry>();
    send_and_sync::<protobuf_edit::varint::carry::Step<u64>>();
    send_and_sync::<protobuf_edit::varint::carry::Complete<'static, u64>>();
}

#[cfg(feature = "varint-slice")]
#[test]
fn the_slice_kernel_is_send_and_sync() {
    send_and_sync::<protobuf_edit::varint::slice::ReadFault>();
}

#[cfg(feature = "scalar")]
#[test]
fn the_scalar_matrix_is_send_and_sync() {
    send_and_sync::<protobuf_edit::scalar::OutOfDomain>();
}

// The stable-replay supply stratum rides the union of its
// consumers, exactly as its module gate does: the slice source and
// its walk are plain borrows of `&[u8]`, and the vocabulary — span
// coordinates, fault wrappers, the phase mark — is plain data. The
// supply trait itself carries no Send bound, so a caller's
// single-threaded provider is lawful; these pins hold the shipped
// types, not the trait.
#[cfg(any(
    feature = "replay-source",
    feature = "survey-grouped",
    feature = "survey-groupless",
    feature = "replay-rewrite-grouped",
    feature = "replay-rewrite-groupless",
    feature = "replay-splice-grouped",
    feature = "replay-splice-groupless",
    feature = "overhaul-grouped",
    feature = "overhaul-groupless"
))]
#[test]
fn the_replay_supply_is_send_and_sync() {
    send_and_sync::<protobuf_edit::replay_source::Chunk<'static>>();
    send_and_sync::<protobuf_edit::replay_source::SliceFault>();
    send_and_sync::<protobuf_edit::replay_source::SliceSource<'static>>();
    send_and_sync::<protobuf_edit::replay_source::SliceWalk<'static>>();
    send_and_sync::<
        protobuf_edit::replay_source::SupplyFault<protobuf_edit::replay_source::SliceFault>,
    >();
    send_and_sync::<protobuf_edit::replay_source::ReplayPhase>();
    send_and_sync::<protobuf_edit::replay_source::FaultAt>();
    send_and_sync::<protobuf_edit::replay_source::FaultZone>();
    send_and_sync::<
        protobuf_edit::replay_source::ReplayFault<protobuf_edit::replay_source::SliceFault>,
    >();
    send_and_sync::<protobuf_edit::replay_source::Handed<protobuf_edit::replay_source::SliceFault>>(
    );
    send_and_sync::<protobuf_edit::replay_source::SourceSpan>();
    // The writers' trail element is present exactly when a writer
    // cell that mints it is.
    #[cfg(any(
        feature = "replay-rewrite-grouped",
        feature = "replay-rewrite-groupless",
        feature = "replay-splice-grouped",
        feature = "replay-splice-groupless"
    ))]
    send_and_sync::<protobuf_edit::replay_source::SourceCrossing>();
}

/// The canonical replay cells' shared refusal carrier: plain data
/// (an opaque site–width coupling), no interior state.
#[cfg(any(
    feature = "refit-grouped",
    feature = "refit-groupless",
    feature = "commission-grouped",
    feature = "commission-groupless"
))]
#[test]
fn the_canonical_replay_refusal_carrier_is_send_and_sync() {
    send_and_sync::<protobuf_edit::replay_source::NonMinimal>();
    send_and_sync::<protobuf_edit::replay_source::NonMinimalSite>();
}

// The supply-boundary witness kit, shared by the two boundary
// rows below: a deliberately non-`Send` provider (`Rc` backing
// here; an FFI or mmap handle in practice) and an impl-ambiguity
// probe over it.
#[cfg(any(
    feature = "survey-grouped",
    feature = "survey-groupless",
    feature = "overhaul-grouped",
    feature = "overhaul-groupless",
    feature = "maintain-grouped",
    feature = "maintain-groupless",
    feature = "refit-grouped",
    feature = "refit-groupless",
    feature = "commission-grouped",
    feature = "commission-groupless"
))]
use protobuf_edit::replay_source::{Chunk, ReplayWalk, StableReplaySource, SupplyFault};

#[cfg(any(
    feature = "survey-grouped",
    feature = "survey-groupless",
    feature = "overhaul-grouped",
    feature = "overhaul-groupless",
    feature = "maintain-grouped",
    feature = "maintain-groupless",
    feature = "refit-grouped",
    feature = "refit-groupless",
    feature = "commission-grouped",
    feature = "commission-groupless"
))]
struct RcSource(std::rc::Rc<[u8]>);

#[cfg(any(
    feature = "survey-grouped",
    feature = "survey-groupless",
    feature = "overhaul-grouped",
    feature = "overhaul-groupless",
    feature = "maintain-grouped",
    feature = "maintain-groupless",
    feature = "refit-grouped",
    feature = "refit-groupless",
    feature = "commission-grouped",
    feature = "commission-groupless"
))]
struct RcWalk<'s>(&'s [u8]);

#[cfg(any(
    feature = "survey-grouped",
    feature = "survey-groupless",
    feature = "overhaul-grouped",
    feature = "overhaul-groupless",
    feature = "maintain-grouped",
    feature = "maintain-groupless",
    feature = "refit-grouped",
    feature = "refit-groupless",
    feature = "commission-grouped",
    feature = "commission-groupless"
))]
impl ReplayWalk for RcWalk<'_> {
    type Error = core::convert::Infallible;

    fn fill(&mut self) -> Result<Option<Chunk<'_>>, SupplyFault<Self::Error>> {
        Ok(Chunk::new(self.0))
    }

    fn consume(&mut self, n: usize) {
        self.0 = &self.0[n..];
    }

    fn skip(&mut self, n: u64) -> Result<u64, SupplyFault<Self::Error>> {
        let step = usize::try_from(n).map_or(self.0.len(), |w| w.min(self.0.len()));
        self.0 = &self.0[step..];
        Ok(step as u64)
    }
}

#[cfg(any(
    feature = "survey-grouped",
    feature = "survey-groupless",
    feature = "overhaul-grouped",
    feature = "overhaul-groupless",
    feature = "maintain-grouped",
    feature = "maintain-groupless",
    feature = "refit-grouped",
    feature = "refit-groupless",
    feature = "commission-grouped",
    feature = "commission-groupless"
))]
impl StableReplaySource for RcSource {
    type Error = core::convert::Infallible;
    type Walk<'s> = RcWalk<'s>;

    fn begin(&mut self) -> Result<Self::Walk<'_>, SupplyFault<Self::Error>> {
        Ok(RcWalk(&self.0))
    }
}

// The probe: a witness call resolves exactly while its subject is
// not `Send` — only the blanket impl applies; a `Send` subject
// would satisfy both impls and fail to compile as ambiguous.
#[cfg(any(
    feature = "survey-grouped",
    feature = "survey-groupless",
    feature = "overhaul-grouped",
    feature = "overhaul-groupless",
    feature = "maintain-grouped",
    feature = "maintain-groupless",
    feature = "refit-grouped",
    feature = "refit-groupless",
    feature = "commission-grouped",
    feature = "commission-groupless"
))]
trait NotSendWitness<Marker> {
    fn witness() {}
}
#[cfg(any(
    feature = "survey-grouped",
    feature = "survey-groupless",
    feature = "overhaul-grouped",
    feature = "overhaul-groupless",
    feature = "maintain-grouped",
    feature = "maintain-groupless",
    feature = "refit-grouped",
    feature = "refit-groupless",
    feature = "commission-grouped",
    feature = "commission-groupless"
))]
struct Blanket;
#[cfg(any(
    feature = "survey-grouped",
    feature = "survey-groupless",
    feature = "overhaul-grouped",
    feature = "overhaul-groupless",
    feature = "maintain-grouped",
    feature = "maintain-groupless",
    feature = "refit-grouped",
    feature = "refit-groupless",
    feature = "commission-grouped",
    feature = "commission-groupless"
))]
struct IfSend;
#[cfg(any(
    feature = "survey-grouped",
    feature = "survey-groupless",
    feature = "overhaul-grouped",
    feature = "overhaul-groupless",
    feature = "maintain-grouped",
    feature = "maintain-groupless",
    feature = "refit-grouped",
    feature = "refit-groupless",
    feature = "commission-grouped",
    feature = "commission-groupless"
))]
impl<T: ?Sized> NotSendWitness<Blanket> for T {}
#[cfg(any(
    feature = "survey-grouped",
    feature = "survey-groupless",
    feature = "overhaul-grouped",
    feature = "overhaul-groupless",
    feature = "maintain-grouped",
    feature = "maintain-groupless",
    feature = "refit-grouped",
    feature = "refit-groupless",
    feature = "commission-grouped",
    feature = "commission-groupless"
))]
impl<T: Send + ?Sized> NotSendWitness<IfSend> for T {}

/// The supply trait admits a deliberately non-`Send` provider:
/// neither [`StableReplaySource`] nor a machine over it carries a
/// `Send` bound of its own, so a single-threaded provider (the
/// `Rc`-backed `RcSource` above; an FFI or mmap handle in
/// practice) is lawful and the machine simply inherits the
/// provider's standing by composition (the sibling row below pins
/// that half). Compiling this instantiation is the pin, and the
/// row pins its own subject too: the witness call compiles
/// exactly while `RcSource` is `!Send`, so trading the `Rc`
/// backing for `Arc` turns this row into a compile error instead
/// of a silently weakened pin.
///
/// [`StableReplaySource`]: protobuf_edit::replay_source::StableReplaySource
#[cfg(feature = "survey-groupless")]
#[test]
fn the_supply_trait_admits_non_send_providers() {
    use protobuf_edit::DepthLimit;
    use protobuf_edit::survey::NoAdvice;
    use protobuf_edit::survey::groupless::Survey;
    use std::rc::Rc;

    // The negative half: the provider itself is not `Send`.
    <RcSource as NotSendWitness<_>>::witness();

    // Field 1, varint 0 — one record, walked through the machine.
    let source = RcSource(Rc::from(&[0x08, 0x00][..]));
    let tree = Survey::open(source, DepthLimit::REFERENCE, &mut NoAdvice)
        .unwrap_or_else(|_| unreachable!("a lawful document opens"));
    assert_eq!(tree.top().count(), 1);
}

/// The propagation half of the supply boundary: a machine that
/// *stores* its provider takes the provider's `Send` standing as
/// its own — composition decides, and nothing overrides it. Each
/// row resolves the witness exactly while the machine over the
/// non-`Send` `RcSource` is itself `!Send`, so an overreaching
/// `unsafe impl Send` on any machine turns its row into an
/// impl-ambiguity error. The roster is the census of public
/// source-storing machines — the two survey products and the six
/// forms each of overhaul, maintain, refit, and commission; the
/// replay rewrite/convert/splice faces are free functions over a
/// caller's source and store nothing.
#[cfg(any(
    feature = "survey-grouped",
    feature = "survey-groupless",
    feature = "overhaul-grouped",
    feature = "overhaul-groupless",
    feature = "maintain-grouped",
    feature = "maintain-groupless",
    feature = "refit-grouped",
    feature = "refit-groupless",
    feature = "commission-grouped",
    feature = "commission-groupless"
))]
#[test]
fn the_source_storing_machines_inherit_non_send() {
    // The premise, standing in every cell that pins a machine
    // (the admission row above is gated narrower): the provider
    // itself is not `Send`.
    <RcSource as NotSendWitness<_>>::witness();
    #[cfg(feature = "survey-grouped")]
    <protobuf_edit::survey::grouped::Survey<RcSource> as NotSendWitness<_>>::witness();
    #[cfg(feature = "survey-groupless")]
    <protobuf_edit::survey::groupless::Survey<RcSource> as NotSendWitness<_>>::witness();
    #[cfg(feature = "overhaul-grouped")]
    {
        <protobuf_edit::overhaul::grouped::Overhaul<'static, RcSource> as NotSendWitness<
            _,
        >>::witness();
        <protobuf_edit::overhaul::grouped::BorrowOverhaul<'static, RcSource> as NotSendWitness<
            _,
        >>::witness();
        <protobuf_edit::overhaul::grouped::CopyOverhaul<RcSource> as NotSendWitness<_>>::witness();
    }
    #[cfg(feature = "overhaul-groupless")]
    {
        <protobuf_edit::overhaul::groupless::Overhaul<'static, RcSource> as NotSendWitness<
            _,
        >>::witness();
        <protobuf_edit::overhaul::groupless::BorrowOverhaul<'static, RcSource> as NotSendWitness<
            _,
        >>::witness();
        <protobuf_edit::overhaul::groupless::CopyOverhaul<RcSource> as NotSendWitness<_>>::witness(
        );
    }
    #[cfg(feature = "refit-grouped")]
    {
        <protobuf_edit::refit::grouped::Refit<'static, RcSource> as NotSendWitness<_>>::witness();
        <protobuf_edit::refit::grouped::BorrowRefit<'static, RcSource> as NotSendWitness<
            _,
        >>::witness();
        <protobuf_edit::refit::grouped::CopyRefit<RcSource> as NotSendWitness<_>>::witness();
    }
    #[cfg(feature = "refit-groupless")]
    {
        <protobuf_edit::refit::groupless::Refit<'static, RcSource> as NotSendWitness<_>>::witness();
        <protobuf_edit::refit::groupless::BorrowRefit<'static, RcSource> as NotSendWitness<
            _,
        >>::witness();
        <protobuf_edit::refit::groupless::CopyRefit<RcSource> as NotSendWitness<_>>::witness();
    }
    #[cfg(feature = "commission-grouped")]
    {
        <protobuf_edit::commission::grouped::Commission<RcSource> as NotSendWitness<_>>::witness();
        <protobuf_edit::commission::grouped::BorrowCommission<'static, RcSource> as NotSendWitness<
            _,
        >>::witness();
        <protobuf_edit::commission::grouped::MixCommission<'static, RcSource> as NotSendWitness<
            _,
        >>::witness();
    }
    #[cfg(feature = "commission-groupless")]
    {
        <protobuf_edit::commission::groupless::Commission<RcSource> as NotSendWitness<_>>::witness(
        );
        <protobuf_edit::commission::groupless::BorrowCommission<'static, RcSource> as NotSendWitness<
            _,
        >>::witness();
        <protobuf_edit::commission::groupless::MixCommission<'static, RcSource> as NotSendWitness<
            _,
        >>::witness();
    }
    #[cfg(feature = "maintain-grouped")]
    {
        <protobuf_edit::maintain::grouped::Maintain<RcSource> as NotSendWitness<_>>::witness();
        <protobuf_edit::maintain::grouped::BorrowMaintain<'static, RcSource> as NotSendWitness<
            _,
        >>::witness();
        <protobuf_edit::maintain::grouped::MixMaintain<'static, RcSource> as NotSendWitness<
            _,
        >>::witness();
    }
    #[cfg(feature = "maintain-groupless")]
    {
        <protobuf_edit::maintain::groupless::Maintain<RcSource> as NotSendWitness<_>>::witness();
        <protobuf_edit::maintain::groupless::BorrowMaintain<'static, RcSource> as NotSendWitness<
            _,
        >>::witness();
        <protobuf_edit::maintain::groupless::MixMaintain<'static, RcSource> as NotSendWitness<
            _,
        >>::witness();
    }
}

#[cfg(any(feature = "select-grouped", feature = "select-groupless"))]
#[test]
fn the_select_family_is_send_and_sync() {
    send_and_sync::<protobuf_edit::select::Oversize>();
    #[cfg(feature = "select-grouped")]
    {
        send_and_sync::<protobuf_edit::select::grouped::Matches<'static, 'static>>();
        send_and_sync::<protobuf_edit::select::grouped::CanonicalMatches<'static, 'static>>();
        send_and_sync::<protobuf_edit::select::grouped::Match<'static>>();
        send_and_sync::<protobuf_edit::select::grouped::MatchKind<'static>>();
        send_and_sync::<protobuf_edit::select::grouped::Fault>();
        send_and_sync::<protobuf_edit::select::grouped::WireBreach>();
    }
    #[cfg(feature = "select-groupless")]
    {
        send_and_sync::<protobuf_edit::select::groupless::Matches<'static, 'static>>();
        send_and_sync::<protobuf_edit::select::groupless::CanonicalMatches<'static, 'static>>();
        send_and_sync::<protobuf_edit::select::groupless::Match<'static>>();
        send_and_sync::<protobuf_edit::select::groupless::MatchKind<'static>>();
        send_and_sync::<protobuf_edit::select::groupless::Fault>();
        send_and_sync::<protobuf_edit::select::groupless::WireBreach>();
    }
}

#[cfg(any(feature = "traverse-grouped", feature = "traverse-groupless"))]
#[test]
fn the_traverse_family_is_send_and_sync() {
    send_and_sync::<protobuf_edit::traverse::Oversize>();
    #[cfg(feature = "traverse-grouped")]
    {
        // GroupDepth is itself grouped-gated: the pin lives where
        // the type does, or the groupless cells cannot compile
        // this target.
        send_and_sync::<protobuf_edit::traverse::GroupDepth>();
        send_and_sync::<protobuf_edit::traverse::grouped::Cursor<'static>>();
        send_and_sync::<protobuf_edit::traverse::grouped::CanonicalCursor<'static>>();
        send_and_sync::<protobuf_edit::traverse::grouped::Entry<'static>>();
        send_and_sync::<protobuf_edit::traverse::grouped::EntryKind<'static>>();
        send_and_sync::<protobuf_edit::traverse::grouped::Fault>();
        send_and_sync::<protobuf_edit::traverse::grouped::FaultKind>();
    }
    #[cfg(feature = "traverse-groupless")]
    {
        send_and_sync::<protobuf_edit::traverse::groupless::Cursor<'static>>();
        send_and_sync::<protobuf_edit::traverse::groupless::CanonicalCursor<'static>>();
        send_and_sync::<protobuf_edit::traverse::groupless::Entry<'static>>();
        send_and_sync::<protobuf_edit::traverse::groupless::EntryKind<'static>>();
        send_and_sync::<protobuf_edit::traverse::groupless::Fault>();
        send_and_sync::<protobuf_edit::traverse::groupless::FaultKind>();
        send_and_sync::<protobuf_edit::traverse::packed::Varints<'static>>();
        send_and_sync::<protobuf_edit::traverse::packed::Fixed32s<'static>>();
        send_and_sync::<protobuf_edit::traverse::packed::Fixed64s<'static>>();
        send_and_sync::<protobuf_edit::traverse::packed::Cut>();
        send_and_sync::<protobuf_edit::traverse::packed::Fault>();
    }
}

#[cfg(any(feature = "inspect-grouped", feature = "inspect-groupless"))]
#[test]
fn the_inspect_family_is_send_and_sync() {
    send_and_sync::<protobuf_edit::inspect::Admitted<'static>>();
    send_and_sync::<protobuf_edit::inspect::Advice>();
    send_and_sync::<protobuf_edit::inspect::Ancestry>();
    send_and_sync::<protobuf_edit::inspect::NoAdvice>();
    send_and_sync::<protobuf_edit::inspect::NodeId>();
    #[cfg(feature = "inspect-grouped")]
    {
        send_and_sync::<protobuf_edit::inspect::grouped::Tree<'static>>();
        send_and_sync::<protobuf_edit::inspect::grouped::Nodes<'static>>();
        send_and_sync::<protobuf_edit::inspect::grouped::Children<'static>>();
        send_and_sync::<protobuf_edit::inspect::grouped::Ancestors<'static>>();
        send_and_sync::<protobuf_edit::inspect::grouped::RecordSpans>();
        send_and_sync::<protobuf_edit::inspect::grouped::Fault>();
        send_and_sync::<protobuf_edit::inspect::grouped::FaultKind>();
    }
    #[cfg(feature = "inspect-groupless")]
    {
        send_and_sync::<protobuf_edit::inspect::groupless::Tree<'static>>();
        send_and_sync::<protobuf_edit::inspect::groupless::Nodes<'static>>();
        send_and_sync::<protobuf_edit::inspect::groupless::Children<'static>>();
        send_and_sync::<protobuf_edit::inspect::groupless::Ancestors<'static>>();
        send_and_sync::<protobuf_edit::inspect::groupless::RecordSpans>();
        send_and_sync::<protobuf_edit::inspect::groupless::Fault>();
        send_and_sync::<protobuf_edit::inspect::groupless::FaultKind>();
    }
}

/// The fixed inspect twin is Send + Sync by composition: one shared
/// borrow of the input bytes plus one exclusive borrow of plain
/// `MaybeUninit` rows — no interior mutability anywhere, exactly
/// the fixed_patch argument.
#[cfg(any(feature = "fixed-inspect-grouped", feature = "fixed-inspect-groupless"))]
#[test]
fn the_fixed_inspect_family_is_send_and_sync() {
    send_and_sync::<protobuf_edit::fixed_inspect::OpenFault>();
    send_and_sync::<protobuf_edit::fixed_inspect::Gauge>();
    send_and_sync::<protobuf_edit::fixed_inspect::Budget>();
    #[cfg(feature = "fixed-inspect-grouped")]
    {
        send_and_sync::<protobuf_edit::fixed_inspect::grouped::Tree<'static, 'static>>();
        send_and_sync::<protobuf_edit::fixed_inspect::grouped::Plan>();
        send_and_sync::<protobuf_edit::fixed_inspect::grouped::Nodes<'static>>();
        send_and_sync::<protobuf_edit::fixed_inspect::grouped::Children<'static>>();
        send_and_sync::<protobuf_edit::fixed_inspect::grouped::Ancestors<'static>>();
        send_and_sync::<protobuf_edit::fixed_inspect::grouped::RecordSpans>();
        send_and_sync::<protobuf_edit::fixed_inspect::grouped::Fault>();
        send_and_sync::<protobuf_edit::fixed_inspect::grouped::FaultKind>();
    }
    #[cfg(feature = "fixed-inspect-groupless")]
    {
        send_and_sync::<protobuf_edit::fixed_inspect::groupless::Tree<'static, 'static>>();
        send_and_sync::<protobuf_edit::fixed_inspect::groupless::Plan>();
        send_and_sync::<protobuf_edit::fixed_inspect::groupless::Nodes<'static>>();
        send_and_sync::<protobuf_edit::fixed_inspect::groupless::Children<'static>>();
        send_and_sync::<protobuf_edit::fixed_inspect::groupless::Ancestors<'static>>();
        send_and_sync::<protobuf_edit::fixed_inspect::groupless::RecordSpans>();
        send_and_sync::<protobuf_edit::fixed_inspect::groupless::Fault>();
        send_and_sync::<protobuf_edit::fixed_inspect::groupless::FaultKind>();
    }
}

/// The source-designation vocabulary crosses threads: every ref is
/// a borrow plus proved metadata, and the fault enums are plain
/// data.
#[cfg(any(
    feature = "inspect-grouped",
    feature = "inspect-groupless",
    feature = "fixed-inspect-grouped",
    feature = "fixed-inspect-groupless",
    feature = "retain-grouped",
    feature = "retain-groupless",
    feature = "patch-grouped",
    feature = "patch-groupless",
    feature = "adopt-grouped",
    feature = "adopt-groupless",
    feature = "amend-grouped",
    feature = "amend-groupless",
    feature = "intake-grouped",
    feature = "intake-groupless",
    feature = "markup-grouped",
    feature = "markup-groupless",
    feature = "draft-grouped",
    feature = "draft-groupless",
    feature = "review-grouped",
    feature = "review-groupless",
    feature = "session-grouped",
    feature = "session-groupless",
    feature = "stream-adopt-grouped",
    feature = "stream-adopt-groupless",
    feature = "stream-draft-grouped",
    feature = "stream-draft-groupless",
    feature = "collect-grouped",
    feature = "collect-groupless",
    feature = "construct-grouped",
    feature = "construct-groupless"
))]
#[test]
fn the_source_family_is_send_and_sync() {
    send_and_sync::<protobuf_edit::source::PayloadRef<'static>>();
    #[cfg(any(
        feature = "inspect-grouped",
        feature = "fixed-inspect-grouped",
        feature = "retain-grouped",
        feature = "patch-grouped",
        feature = "adopt-grouped",
        feature = "amend-grouped",
        feature = "intake-grouped",
        feature = "markup-grouped",
        feature = "draft-grouped",
        feature = "review-grouped",
        feature = "session-grouped",
        feature = "stream-adopt-grouped",
        feature = "stream-draft-grouped",
        feature = "collect-grouped",
        feature = "construct-grouped"
    ))]
    {
        send_and_sync::<protobuf_edit::source::grouped::RecordRef<'static>>();
        send_and_sync::<protobuf_edit::source::grouped::CanonicalRecordRef<'static>>();
        send_and_sync::<protobuf_edit::source::grouped::Fault>();
    }
    #[cfg(any(
        feature = "inspect-groupless",
        feature = "fixed-inspect-groupless",
        feature = "retain-groupless",
        feature = "patch-groupless",
        feature = "adopt-groupless",
        feature = "amend-groupless",
        feature = "intake-groupless",
        feature = "markup-groupless",
        feature = "draft-groupless",
        feature = "review-groupless",
        feature = "session-groupless",
        feature = "stream-adopt-groupless",
        feature = "stream-draft-groupless",
        feature = "collect-groupless",
        feature = "construct-groupless"
    ))]
    {
        send_and_sync::<protobuf_edit::source::groupless::RecordRef<'static>>();
        send_and_sync::<protobuf_edit::source::groupless::CanonicalRecordRef<'static>>();
        send_and_sync::<protobuf_edit::source::groupless::Fault>();
    }
}

/// The retained inspector is the crate's first machine *product*
/// pinned positively: an immutable owned index (source + rows, no
/// share counter, no interior mutability), so the whole product —
/// not just its vocabulary — crosses threads.
#[cfg(any(feature = "retain-grouped", feature = "retain-groupless"))]
#[test]
fn the_retain_family_is_send_and_sync() {
    send_and_sync::<protobuf_edit::retain::Oversize>();
    send_and_sync::<protobuf_edit::retain::Advice>();
    send_and_sync::<protobuf_edit::retain::Ancestry>();
    send_and_sync::<protobuf_edit::retain::NoAdvice>();
    send_and_sync::<protobuf_edit::retain::NodeId>();
    #[cfg(feature = "retain-grouped")]
    {
        send_and_sync::<protobuf_edit::retain::grouped::Retained>();
        send_and_sync::<protobuf_edit::retain::grouped::Nodes<'static>>();
        send_and_sync::<protobuf_edit::retain::grouped::Children<'static>>();
        send_and_sync::<protobuf_edit::retain::grouped::Ancestors<'static>>();
        send_and_sync::<protobuf_edit::retain::grouped::RecordSpans>();
        send_and_sync::<protobuf_edit::retain::grouped::Fault>();
        send_and_sync::<protobuf_edit::retain::grouped::FaultKind>();
    }
    #[cfg(feature = "retain-groupless")]
    {
        send_and_sync::<protobuf_edit::retain::groupless::Retained>();
        send_and_sync::<protobuf_edit::retain::groupless::Nodes<'static>>();
        send_and_sync::<protobuf_edit::retain::groupless::Children<'static>>();
        send_and_sync::<protobuf_edit::retain::groupless::Ancestors<'static>>();
        send_and_sync::<protobuf_edit::retain::groupless::RecordSpans>();
        send_and_sync::<protobuf_edit::retain::groupless::Fault>();
        send_and_sync::<protobuf_edit::retain::groupless::FaultKind>();
    }
}

#[cfg(any(feature = "route-grouped", feature = "route-groupless"))]
#[test]
fn the_route_family_is_send_and_sync() {
    send_and_sync::<protobuf_edit::route::Flow>();
    send_and_sync::<protobuf_edit::route::ReadFault>();
    #[cfg(feature = "route-grouped")]
    {
        send_and_sync::<protobuf_edit::route::grouped::Router<'static>>();
        send_and_sync::<protobuf_edit::route::grouped::Fault>();
        send_and_sync::<protobuf_edit::route::grouped::FaultKind>();
    }
    #[cfg(feature = "route-groupless")]
    {
        send_and_sync::<protobuf_edit::route::groupless::Router<'static>>();
        send_and_sync::<protobuf_edit::route::groupless::Fault>();
        send_and_sync::<protobuf_edit::route::groupless::FaultKind>();
    }
}

#[cfg(any(feature = "scan-grouped", feature = "scan-groupless"))]
#[test]
fn the_scan_family_is_send_and_sync() {
    send_and_sync::<protobuf_edit::scan::Flow>();
    send_and_sync::<protobuf_edit::scan::LenDisposition>();
    send_and_sync::<protobuf_edit::scan::ReadFault>();
    #[cfg(feature = "scan-grouped")]
    {
        send_and_sync::<protobuf_edit::scan::grouped::Parser>();
        send_and_sync::<protobuf_edit::scan::grouped::Validator>();
        send_and_sync::<protobuf_edit::scan::grouped::Fault>();
        send_and_sync::<protobuf_edit::scan::grouped::FaultKind>();
    }
    #[cfg(feature = "scan-groupless")]
    {
        send_and_sync::<protobuf_edit::scan::groupless::Parser>();
        send_and_sync::<protobuf_edit::scan::groupless::Validator>();
        send_and_sync::<protobuf_edit::scan::groupless::Fault>();
        send_and_sync::<protobuf_edit::scan::groupless::FaultKind>();
    }
}

/// The stream collector crosses threads on both sides of the seal:
/// a live collector is plain data over its owned backing (its
/// advisor borrow forwards the advisor's own standing, and
/// `NoAdvice` is a unit), and the finished product is an immutable
/// owned index — source and rows, no share counter, no interior
/// mutability.
#[cfg(any(feature = "collect-grouped", feature = "collect-groupless"))]
#[test]
fn the_collect_family_is_send_and_sync() {
    send_and_sync::<protobuf_edit::collect::Advice>();
    send_and_sync::<protobuf_edit::collect::Ancestry>();
    send_and_sync::<protobuf_edit::collect::NoAdvice>();
    send_and_sync::<protobuf_edit::collect::NodeId>();
    send_and_sync::<protobuf_edit::collect::FeedOversize>();
    send_and_sync::<protobuf_edit::collect::CapacityOversize>();
    #[cfg(feature = "collect-grouped")]
    {
        send_and_sync::<
            protobuf_edit::collect::grouped::Collector<'static, protobuf_edit::collect::NoAdvice>,
        >();
        send_and_sync::<protobuf_edit::collect::grouped::Retained>();
        send_and_sync::<protobuf_edit::collect::grouped::Nodes<'static>>();
        send_and_sync::<protobuf_edit::collect::grouped::Children<'static>>();
        send_and_sync::<protobuf_edit::collect::grouped::Ancestors<'static>>();
        send_and_sync::<protobuf_edit::collect::grouped::RecordSpans>();
        send_and_sync::<protobuf_edit::collect::grouped::Fault>();
        send_and_sync::<protobuf_edit::collect::grouped::FaultKind>();
    }
    #[cfg(feature = "collect-groupless")]
    {
        send_and_sync::<
            protobuf_edit::collect::groupless::Collector<'static, protobuf_edit::collect::NoAdvice>,
        >();
        send_and_sync::<protobuf_edit::collect::groupless::Retained>();
        send_and_sync::<protobuf_edit::collect::groupless::Nodes<'static>>();
        send_and_sync::<protobuf_edit::collect::groupless::Children<'static>>();
        send_and_sync::<protobuf_edit::collect::groupless::Ancestors<'static>>();
        send_and_sync::<protobuf_edit::collect::groupless::RecordSpans>();
        send_and_sync::<protobuf_edit::collect::groupless::Fault>();
        send_and_sync::<protobuf_edit::collect::groupless::FaultKind>();
    }
}

/// The survey product crosses threads with its source: rows plus
/// the source handle, no share counter, no interior mutability —
/// the machine is generic over the supply, so its standing is the
/// source's own (pinned here over the shipped slice source).
#[cfg(any(feature = "survey-grouped", feature = "survey-groupless"))]
#[test]
fn the_survey_family_is_send_and_sync() {
    send_and_sync::<protobuf_edit::survey::NodeId>();
    send_and_sync::<protobuf_edit::survey::Advice>();
    send_and_sync::<protobuf_edit::survey::Ancestry<'static>>();
    send_and_sync::<protobuf_edit::survey::NoAdvice>();
    send_and_sync::<protobuf_edit::survey::OpenFault<protobuf_edit::replay_source::SliceFault>>();
    send_and_sync::<protobuf_edit::survey::FetchFault<protobuf_edit::replay_source::SliceFault>>();
    #[cfg(feature = "survey-grouped")]
    {
        send_and_sync::<
            protobuf_edit::survey::grouped::Survey<
                protobuf_edit::replay_source::SliceSource<'static>,
            >,
        >();
        send_and_sync::<protobuf_edit::survey::grouped::Nodes<'static>>();
        send_and_sync::<protobuf_edit::survey::grouped::Children<'static>>();
        send_and_sync::<protobuf_edit::survey::grouped::Ancestors<'static>>();
        send_and_sync::<protobuf_edit::survey::grouped::RecordSpans>();
        send_and_sync::<protobuf_edit::survey::grouped::ReadFault>();
        send_and_sync::<protobuf_edit::survey::grouped::Fault>();
        send_and_sync::<protobuf_edit::survey::grouped::FaultKind>();
    }
    #[cfg(feature = "survey-groupless")]
    {
        send_and_sync::<
            protobuf_edit::survey::groupless::Survey<
                protobuf_edit::replay_source::SliceSource<'static>,
            >,
        >();
        send_and_sync::<protobuf_edit::survey::groupless::Nodes<'static>>();
        send_and_sync::<protobuf_edit::survey::groupless::Children<'static>>();
        send_and_sync::<protobuf_edit::survey::groupless::Ancestors<'static>>();
        send_and_sync::<protobuf_edit::survey::groupless::RecordSpans>();
        send_and_sync::<protobuf_edit::survey::groupless::ReadFault>();
        send_and_sync::<protobuf_edit::survey::groupless::Fault>();
        send_and_sync::<protobuf_edit::survey::groupless::FaultKind>();
    }
}

#[cfg(any(feature = "rewrite-grouped", feature = "rewrite-groupless"))]
#[test]
fn the_rewrite_family_is_send_and_sync() {
    send_and_sync::<protobuf_edit::rewrite::Rule<'static>>();
    send_and_sync::<protobuf_edit::rewrite::RuleSet<'static>>();
    send_and_sync::<protobuf_edit::rewrite::InsertRuleSet<'static>>();
    send_and_sync::<protobuf_edit::rewrite::RuleError>();
    send_and_sync::<protobuf_edit::rewrite::Action<'static>>();
    send_and_sync::<protobuf_edit::rewrite::Gap>();
    send_and_sync::<protobuf_edit::rewrite::InsertRule<'static>>();
    send_and_sync::<protobuf_edit::rewrite::Value<'static>>();
    send_and_sync::<protobuf_edit::rewrite::Stats>();
    send_and_sync::<protobuf_edit::rewrite::InsertStats>();
    #[cfg(feature = "rewrite-grouped")]
    {
        send_and_sync::<protobuf_edit::rewrite::grouped::Fault>();
        send_and_sync::<protobuf_edit::rewrite::grouped::FaultKind>();
        send_and_sync::<protobuf_edit::rewrite::grouped::WireBreach>();
    }
    #[cfg(feature = "rewrite-groupless")]
    {
        send_and_sync::<protobuf_edit::rewrite::groupless::Fault>();
        send_and_sync::<protobuf_edit::rewrite::groupless::FaultKind>();
        send_and_sync::<protobuf_edit::rewrite::groupless::WireBreach>();
    }
}

#[cfg(any(feature = "inplace-grouped", feature = "inplace-groupless"))]
#[test]
fn the_inplace_family_is_send_and_sync() {
    send_and_sync::<protobuf_edit::inplace::Rule<'static>>();
    send_and_sync::<protobuf_edit::inplace::RuleSet<'static>>();
    send_and_sync::<protobuf_edit::inplace::RuleError>();
    send_and_sync::<protobuf_edit::inplace::Action<'static>>();
    send_and_sync::<protobuf_edit::inplace::Stats>();
    #[cfg(feature = "inplace-grouped")]
    {
        send_and_sync::<protobuf_edit::inplace::grouped::Fault>();
        send_and_sync::<protobuf_edit::inplace::grouped::FaultKind>();
        send_and_sync::<protobuf_edit::inplace::grouped::WireBreach>();
    }
    #[cfg(feature = "inplace-groupless")]
    {
        send_and_sync::<protobuf_edit::inplace::groupless::Fault>();
        send_and_sync::<protobuf_edit::inplace::groupless::FaultKind>();
        send_and_sync::<protobuf_edit::inplace::groupless::WireBreach>();
    }
}

/// The fixed-scratch in-place family is wholly positive: the faces
/// are free functions, and the vocabulary — plans, budgets, stats,
/// faults — is plain data (no machine type exists; the scratch
/// tenure is one call).
#[cfg(any(feature = "fixed-inplace-grouped", feature = "fixed-inplace-groupless"))]
#[test]
fn the_fixed_inplace_family_is_send_and_sync() {
    send_and_sync::<protobuf_edit::fixed_inplace::Stats>();
    send_and_sync::<protobuf_edit::fixed_inplace::Gauge>();
    #[cfg(feature = "fixed-inplace-grouped")]
    {
        send_and_sync::<protobuf_edit::fixed_inplace::grouped::Plan>();
        send_and_sync::<protobuf_edit::fixed_inplace::grouped::Budget>();
        send_and_sync::<protobuf_edit::fixed_inplace::grouped::Fault>();
        send_and_sync::<protobuf_edit::fixed_inplace::grouped::FaultKind>();
        send_and_sync::<protobuf_edit::fixed_inplace::grouped::WireBreach>();
    }
    #[cfg(feature = "fixed-inplace-groupless")]
    {
        send_and_sync::<protobuf_edit::fixed_inplace::groupless::Plan>();
        send_and_sync::<protobuf_edit::fixed_inplace::groupless::Budget>();
        send_and_sync::<protobuf_edit::fixed_inplace::groupless::Fault>();
        send_and_sync::<protobuf_edit::fixed_inplace::groupless::FaultKind>();
        send_and_sync::<protobuf_edit::fixed_inplace::groupless::WireBreach>();
    }
}

#[cfg(any(feature = "convert-grouped", feature = "convert-groupless"))]
#[test]
fn the_convert_family_is_send_and_sync() {
    #[cfg(feature = "convert-grouped")]
    {
        send_and_sync::<protobuf_edit::convert::grouped::Converter<'static>>();
        send_and_sync::<protobuf_edit::convert::grouped::Stats>();
        send_and_sync::<protobuf_edit::convert::grouped::Fault>();
        send_and_sync::<protobuf_edit::convert::grouped::FaultKind>();
        send_and_sync::<protobuf_edit::convert::grouped::WireBreach>();
    }
    #[cfg(feature = "convert-groupless")]
    {
        send_and_sync::<protobuf_edit::convert::groupless::Converter>();
        send_and_sync::<protobuf_edit::convert::groupless::Stats>();
        send_and_sync::<protobuf_edit::convert::groupless::Fault>();
        send_and_sync::<protobuf_edit::convert::groupless::FaultKind>();
        send_and_sync::<protobuf_edit::convert::groupless::WireBreach>();
    }
}

#[cfg(any(feature = "splice-grouped", feature = "splice-groupless"))]
#[test]
fn the_splice_family_is_send_and_sync() {
    send_and_sync::<protobuf_edit::splice::Scalar<'static, u64>>();
    send_and_sync::<protobuf_edit::splice::Len<'static>>();
    #[cfg(feature = "splice-grouped")]
    {
        send_and_sync::<protobuf_edit::splice::grouped::Group<'static>>();
        send_and_sync::<protobuf_edit::splice::grouped::Fault>();
        send_and_sync::<protobuf_edit::splice::grouped::FaultKind>();
        send_and_sync::<protobuf_edit::splice::grouped::WireBreach>();
    }
    #[cfg(feature = "splice-groupless")]
    {
        send_and_sync::<protobuf_edit::splice::groupless::Fault>();
        send_and_sync::<protobuf_edit::splice::groupless::FaultKind>();
        send_and_sync::<protobuf_edit::splice::groupless::WireBreach>();
    }
}

#[cfg(any(feature = "patch-grouped", feature = "patch-groupless"))]
#[test]
fn the_patch_family_is_send_and_sync() {
    send_and_sync::<protobuf_edit::patch::Handle>();
    send_and_sync::<protobuf_edit::patch::InsertAt>();
    send_and_sync::<protobuf_edit::patch::EditStatus>();
    #[cfg(feature = "patch-grouped")]
    {
        send_and_sync::<protobuf_edit::patch::grouped::Patch<'static, 'static>>();
        send_and_sync::<protobuf_edit::patch::grouped::PayloadWrite<'static, 'static, 'static>>();
        send_and_sync::<protobuf_edit::patch::grouped::SizedPayloadWrite<'static, 'static, 'static>>(
        );
        send_and_sync::<protobuf_edit::patch::grouped::Children<'static>>();
        send_and_sync::<protobuf_edit::patch::grouped::Ancestors<'static>>();
        send_and_sync::<protobuf_edit::patch::grouped::RecordSpans>();
        send_and_sync::<protobuf_edit::patch::grouped::SaveSpans>();
        send_and_sync::<protobuf_edit::patch::grouped::BorrowPatch<'static, 'static>>();
        send_and_sync::<protobuf_edit::patch::grouped::CopyPatch<'static>>();
        send_and_sync::<protobuf_edit::patch::grouped::CopyPayloadWrite<'static, 'static>>();
        send_and_sync::<protobuf_edit::patch::grouped::SizedCopyPayloadWrite<'static, 'static>>();
        send_and_sync::<protobuf_edit::patch::grouped::Descent>();
        send_and_sync::<protobuf_edit::patch::grouped::OpenFault>();
        send_and_sync::<protobuf_edit::patch::grouped::Fault>();
        send_and_sync::<protobuf_edit::patch::grouped::FaultKind>();
        send_and_sync::<protobuf_edit::patch::grouped::EditFault>();
        send_and_sync::<protobuf_edit::patch::grouped::FrameFault>();
        send_and_sync::<protobuf_edit::patch::grouped::SaveFault>();
        send_and_sync::<protobuf_edit::patch::grouped::Refusal>();
    }
    #[cfg(feature = "patch-groupless")]
    {
        send_and_sync::<protobuf_edit::patch::groupless::Patch<'static, 'static>>();
        send_and_sync::<protobuf_edit::patch::groupless::PayloadWrite<'static, 'static, 'static>>();
        send_and_sync::<
            protobuf_edit::patch::groupless::SizedPayloadWrite<'static, 'static, 'static>,
        >();
        send_and_sync::<protobuf_edit::patch::groupless::Children<'static>>();
        send_and_sync::<protobuf_edit::patch::groupless::Ancestors<'static>>();
        send_and_sync::<protobuf_edit::patch::groupless::RecordSpans>();
        send_and_sync::<protobuf_edit::patch::groupless::SaveSpans>();
        send_and_sync::<protobuf_edit::patch::groupless::BorrowPatch<'static, 'static>>();
        send_and_sync::<protobuf_edit::patch::groupless::CopyPatch<'static>>();
        send_and_sync::<protobuf_edit::patch::groupless::CopyPayloadWrite<'static, 'static>>();
        send_and_sync::<protobuf_edit::patch::groupless::SizedCopyPayloadWrite<'static, 'static>>();
        send_and_sync::<protobuf_edit::patch::groupless::Descent>();
        send_and_sync::<protobuf_edit::patch::groupless::OpenFault>();
        send_and_sync::<protobuf_edit::patch::groupless::Fault>();
        send_and_sync::<protobuf_edit::patch::groupless::FaultKind>();
        send_and_sync::<protobuf_edit::patch::groupless::EditFault>();
        send_and_sync::<protobuf_edit::patch::groupless::FrameFault>();
        send_and_sync::<protobuf_edit::patch::groupless::SaveFault>();
        send_and_sync::<protobuf_edit::patch::groupless::Refusal>();
    }
    #[cfg(feature = "transfer-patch-grouped")]
    {
        send_and_sync::<protobuf_edit::patch::grouped::transfer::TransferPatch<'static, 'static>>();
        send_and_sync::<protobuf_edit::patch::grouped::transfer::PayloadTarget>();
        send_and_sync::<
            protobuf_edit::patch::grouped::transfer::PayloadWrite<'static, 'static, 'static>,
        >();
        send_and_sync::<
            protobuf_edit::patch::grouped::transfer::SizedPayloadWrite<'static, 'static, 'static>,
        >();
        send_and_sync::<protobuf_edit::patch::grouped::transfer::Children<'static>>();
        send_and_sync::<protobuf_edit::patch::grouped::transfer::Ancestors<'static>>();
        send_and_sync::<protobuf_edit::patch::grouped::transfer::RecordSpans>();
        send_and_sync::<protobuf_edit::patch::grouped::transfer::SaveSpans>();
        send_and_sync::<protobuf_edit::patch::grouped::transfer::Descent>();
        send_and_sync::<protobuf_edit::patch::grouped::transfer::OpenFault>();
        send_and_sync::<protobuf_edit::patch::grouped::transfer::Fault>();
        send_and_sync::<protobuf_edit::patch::grouped::transfer::FaultKind>();
        send_and_sync::<protobuf_edit::patch::grouped::transfer::EditFault>();
        send_and_sync::<protobuf_edit::patch::grouped::transfer::FrameFault>();
        send_and_sync::<protobuf_edit::patch::grouped::transfer::SaveFault>();
        send_and_sync::<protobuf_edit::patch::grouped::transfer::Refusal>();
    }
    #[cfg(feature = "transfer-patch-groupless")]
    {
        send_and_sync::<protobuf_edit::patch::groupless::transfer::TransferPatch<'static, 'static>>(
        );
        send_and_sync::<protobuf_edit::patch::groupless::transfer::PayloadTarget>();
        send_and_sync::<
            protobuf_edit::patch::groupless::transfer::PayloadWrite<'static, 'static, 'static>,
        >();
        send_and_sync::<
            protobuf_edit::patch::groupless::transfer::SizedPayloadWrite<'static, 'static, 'static>,
        >();
        send_and_sync::<protobuf_edit::patch::groupless::transfer::Children<'static>>();
        send_and_sync::<protobuf_edit::patch::groupless::transfer::Ancestors<'static>>();
        send_and_sync::<protobuf_edit::patch::groupless::transfer::RecordSpans>();
        send_and_sync::<protobuf_edit::patch::groupless::transfer::SaveSpans>();
        send_and_sync::<protobuf_edit::patch::groupless::transfer::Descent>();
        send_and_sync::<protobuf_edit::patch::groupless::transfer::OpenFault>();
        send_and_sync::<protobuf_edit::patch::groupless::transfer::Fault>();
        send_and_sync::<protobuf_edit::patch::groupless::transfer::FaultKind>();
        send_and_sync::<protobuf_edit::patch::groupless::transfer::EditFault>();
        send_and_sync::<protobuf_edit::patch::groupless::transfer::FrameFault>();
        send_and_sync::<protobuf_edit::patch::groupless::transfer::SaveFault>();
        send_and_sync::<protobuf_edit::patch::groupless::transfer::Refusal>();
    }
}

/// The fixed-scratch patch family mirrors the patch's pins and
/// stays wholly positive: the machines hold shared borrows (source,
/// payloads) plus one exclusive slab borrow of plain bytes — no
/// share counter, no interior mutability — so a mid-edit machine
/// crosses threads with its slab, and the plans, budgets, and
/// faults are plain data.
#[cfg(any(feature = "fixed-patch-grouped", feature = "fixed-patch-groupless"))]
#[test]
fn the_fixed_patch_family_is_send_and_sync() {
    send_and_sync::<protobuf_edit::fixed_patch::Handle>();
    send_and_sync::<protobuf_edit::fixed_patch::InsertAt>();
    send_and_sync::<protobuf_edit::fixed_patch::EditStatus>();
    send_and_sync::<protobuf_edit::fixed_patch::ScratchRole>();
    send_and_sync::<protobuf_edit::fixed_patch::Gauge>();
    send_and_sync::<protobuf_edit::fixed_patch::Budget>();
    send_and_sync::<protobuf_edit::fixed_patch::BorrowBudget>();
    #[cfg(feature = "fixed-patch-grouped")]
    {
        send_and_sync::<protobuf_edit::fixed_patch::grouped::Patch<'static, 'static, 'static>>();
        send_and_sync::<
            protobuf_edit::fixed_patch::grouped::PayloadWrite<'static, 'static, 'static, 'static>,
        >();
        send_and_sync::<
            protobuf_edit::fixed_patch::grouped::SizedPayloadWrite<
                'static,
                'static,
                'static,
                'static,
            >,
        >();
        send_and_sync::<protobuf_edit::fixed_patch::grouped::BorrowPatch<'static, 'static, 'static>>(
        );
        send_and_sync::<protobuf_edit::fixed_patch::grouped::CopyPatch<'static, 'static>>();
        send_and_sync::<
            protobuf_edit::fixed_patch::grouped::CopyPayloadWrite<'static, 'static, 'static>,
        >();
        send_and_sync::<
            protobuf_edit::fixed_patch::grouped::SizedCopyPayloadWrite<'static, 'static, 'static>,
        >();
        send_and_sync::<protobuf_edit::fixed_patch::grouped::Plan>();
        send_and_sync::<protobuf_edit::fixed_patch::grouped::BorrowPlan>();
        send_and_sync::<protobuf_edit::fixed_patch::grouped::CopyPlan>();
        send_and_sync::<protobuf_edit::fixed_patch::grouped::Children<'static>>();
        send_and_sync::<protobuf_edit::fixed_patch::grouped::Ancestors<'static>>();
        send_and_sync::<protobuf_edit::fixed_patch::grouped::RecordSpans>();
        send_and_sync::<protobuf_edit::fixed_patch::grouped::Descent<'static>>();
        send_and_sync::<protobuf_edit::fixed_patch::grouped::OpenFault>();
        send_and_sync::<protobuf_edit::fixed_patch::grouped::Fault>();
        send_and_sync::<protobuf_edit::fixed_patch::grouped::FaultKind>();
        send_and_sync::<protobuf_edit::fixed_patch::grouped::EditFault>();
        send_and_sync::<protobuf_edit::fixed_patch::grouped::FrameFault>();
        send_and_sync::<protobuf_edit::fixed_patch::grouped::SaveFault>();
        send_and_sync::<protobuf_edit::fixed_patch::grouped::Refusal>();
    }
    #[cfg(feature = "fixed-patch-groupless")]
    {
        send_and_sync::<protobuf_edit::fixed_patch::groupless::Patch<'static, 'static, 'static>>();
        send_and_sync::<
            protobuf_edit::fixed_patch::groupless::PayloadWrite<'static, 'static, 'static, 'static>,
        >();
        send_and_sync::<
            protobuf_edit::fixed_patch::groupless::SizedPayloadWrite<
                'static,
                'static,
                'static,
                'static,
            >,
        >();
        send_and_sync::<
            protobuf_edit::fixed_patch::groupless::BorrowPatch<'static, 'static, 'static>,
        >();
        send_and_sync::<protobuf_edit::fixed_patch::groupless::CopyPatch<'static, 'static>>();
        send_and_sync::<
            protobuf_edit::fixed_patch::groupless::CopyPayloadWrite<'static, 'static, 'static>,
        >();
        send_and_sync::<
            protobuf_edit::fixed_patch::groupless::SizedCopyPayloadWrite<'static, 'static, 'static>,
        >();
        send_and_sync::<protobuf_edit::fixed_patch::groupless::Plan>();
        send_and_sync::<protobuf_edit::fixed_patch::groupless::BorrowPlan>();
        send_and_sync::<protobuf_edit::fixed_patch::groupless::CopyPlan>();
        send_and_sync::<protobuf_edit::fixed_patch::groupless::Children<'static>>();
        send_and_sync::<protobuf_edit::fixed_patch::groupless::Ancestors<'static>>();
        send_and_sync::<protobuf_edit::fixed_patch::groupless::RecordSpans>();
        send_and_sync::<protobuf_edit::fixed_patch::groupless::Descent<'static>>();
        send_and_sync::<protobuf_edit::fixed_patch::groupless::OpenFault>();
        send_and_sync::<protobuf_edit::fixed_patch::groupless::Fault>();
        send_and_sync::<protobuf_edit::fixed_patch::groupless::FaultKind>();
        send_and_sync::<protobuf_edit::fixed_patch::groupless::EditFault>();
        send_and_sync::<protobuf_edit::fixed_patch::groupless::FrameFault>();
        send_and_sync::<protobuf_edit::fixed_patch::groupless::SaveFault>();
        send_and_sync::<protobuf_edit::fixed_patch::groupless::Refusal>();
    }
}

/// The markup family is wholly positive: the machine holds a plain
/// `&[u8]` — no share counting, no interior mutability — so the
/// markup, its payload frames, and its whole vocabulary are
/// `Send + Sync`, the borrowed revisable editor's identity within
/// the borrow's extent.
#[cfg(any(feature = "markup-grouped", feature = "markup-groupless"))]
#[test]
fn the_markup_family_is_send_and_sync() {
    send_and_sync::<protobuf_edit::markup::Handle>();
    #[cfg(feature = "markup-grouped")]
    {
        send_and_sync::<protobuf_edit::markup::grouped::Markup<'static>>();
        send_and_sync::<protobuf_edit::markup::grouped::PayloadFrame<'static, 'static>>();
        send_and_sync::<protobuf_edit::markup::grouped::SizedPayloadFrame<'static, 'static>>();
        send_and_sync::<protobuf_edit::markup::grouped::EditStatus>();
        send_and_sync::<protobuf_edit::markup::grouped::InsertAt>();
        send_and_sync::<protobuf_edit::markup::grouped::OpenFault>();
        send_and_sync::<protobuf_edit::markup::grouped::Fault>();
        send_and_sync::<protobuf_edit::markup::grouped::FaultKind>();
        send_and_sync::<protobuf_edit::markup::grouped::EditFault>();
        send_and_sync::<protobuf_edit::markup::grouped::BorrowMarkup<'static, 'static>>();
        send_and_sync::<protobuf_edit::markup::grouped::MixMarkup<'static, 'static>>();
        send_and_sync::<protobuf_edit::markup::grouped::MixPayloadFrame<'static, 'static, 'static>>(
        );
        send_and_sync::<
            protobuf_edit::markup::grouped::MixSizedPayloadFrame<'static, 'static, 'static>,
        >();
        send_and_sync::<protobuf_edit::markup::grouped::FrameFault>();
        send_and_sync::<protobuf_edit::markup::grouped::SaveFault>();
        send_and_sync::<protobuf_edit::markup::grouped::Children<'static>>();
        send_and_sync::<protobuf_edit::markup::grouped::Ancestors<'static>>();
        send_and_sync::<protobuf_edit::markup::grouped::Descent<'static>>();
        send_and_sync::<protobuf_edit::markup::grouped::RecordSpans>();
        send_and_sync::<protobuf_edit::markup::grouped::SaveSpans>();
    }
    #[cfg(feature = "markup-groupless")]
    {
        send_and_sync::<protobuf_edit::markup::groupless::Markup<'static>>();
        send_and_sync::<protobuf_edit::markup::groupless::PayloadFrame<'static, 'static>>();
        send_and_sync::<protobuf_edit::markup::groupless::SizedPayloadFrame<'static, 'static>>();
        send_and_sync::<protobuf_edit::markup::groupless::EditStatus>();
        send_and_sync::<protobuf_edit::markup::groupless::InsertAt>();
        send_and_sync::<protobuf_edit::markup::groupless::OpenFault>();
        send_and_sync::<protobuf_edit::markup::groupless::Fault>();
        send_and_sync::<protobuf_edit::markup::groupless::FaultKind>();
        send_and_sync::<protobuf_edit::markup::groupless::EditFault>();
        send_and_sync::<protobuf_edit::markup::groupless::BorrowMarkup<'static, 'static>>();
        send_and_sync::<protobuf_edit::markup::groupless::MixMarkup<'static, 'static>>();
        send_and_sync::<protobuf_edit::markup::groupless::MixPayloadFrame<'static, 'static, 'static>>(
        );
        send_and_sync::<
            protobuf_edit::markup::groupless::MixSizedPayloadFrame<'static, 'static, 'static>,
        >();
        send_and_sync::<protobuf_edit::markup::groupless::FrameFault>();
        send_and_sync::<protobuf_edit::markup::groupless::SaveFault>();
        send_and_sync::<protobuf_edit::markup::groupless::Refusal>();
        send_and_sync::<protobuf_edit::markup::groupless::Children<'static>>();
        send_and_sync::<protobuf_edit::markup::groupless::Ancestors<'static>>();
        send_and_sync::<protobuf_edit::markup::groupless::Descent<'static>>();
        send_and_sync::<protobuf_edit::markup::groupless::RecordSpans>();
        send_and_sync::<protobuf_edit::markup::groupless::SaveSpans>();
    }
    #[cfg(feature = "transfer-markup-grouped")]
    {
        send_and_sync::<protobuf_edit::markup::grouped::transfer::TransferMarkup<'static>>();
        send_and_sync::<
            protobuf_edit::markup::grouped::transfer::TransferBorrowMarkup<'static, 'static>,
        >();
        send_and_sync::<protobuf_edit::markup::grouped::transfer::PayloadFrame<'static, 'static>>();
        send_and_sync::<
            protobuf_edit::markup::grouped::transfer::SizedPayloadFrame<'static, 'static>,
        >();
        send_and_sync::<protobuf_edit::markup::grouped::transfer::EditStatus>();
        send_and_sync::<protobuf_edit::markup::grouped::transfer::PayloadTarget>();
        send_and_sync::<protobuf_edit::markup::grouped::transfer::OpenFault>();
        send_and_sync::<protobuf_edit::markup::grouped::transfer::Fault>();
        send_and_sync::<protobuf_edit::markup::grouped::transfer::FaultKind>();
        send_and_sync::<protobuf_edit::markup::grouped::transfer::EditFault>();
        send_and_sync::<protobuf_edit::markup::grouped::transfer::FrameFault>();
        send_and_sync::<protobuf_edit::markup::grouped::transfer::SaveFault>();
        send_and_sync::<protobuf_edit::markup::grouped::transfer::Children<'static>>();
        send_and_sync::<protobuf_edit::markup::grouped::transfer::Ancestors<'static>>();
        send_and_sync::<protobuf_edit::markup::grouped::transfer::Descent<'static>>();
        send_and_sync::<protobuf_edit::markup::grouped::transfer::RecordSpans>();
        send_and_sync::<protobuf_edit::markup::grouped::transfer::SaveSpans>();
    }
    #[cfg(feature = "transfer-markup-groupless")]
    {
        send_and_sync::<protobuf_edit::markup::groupless::transfer::TransferMarkup<'static>>();
        send_and_sync::<
            protobuf_edit::markup::groupless::transfer::TransferBorrowMarkup<'static, 'static>,
        >();
        send_and_sync::<protobuf_edit::markup::groupless::transfer::PayloadFrame<'static, 'static>>(
        );
        send_and_sync::<
            protobuf_edit::markup::groupless::transfer::SizedPayloadFrame<'static, 'static>,
        >();
        send_and_sync::<protobuf_edit::markup::groupless::transfer::EditStatus>();
        send_and_sync::<protobuf_edit::markup::groupless::transfer::PayloadTarget>();
        send_and_sync::<protobuf_edit::markup::groupless::transfer::OpenFault>();
        send_and_sync::<protobuf_edit::markup::groupless::transfer::Fault>();
        send_and_sync::<protobuf_edit::markup::groupless::transfer::FaultKind>();
        send_and_sync::<protobuf_edit::markup::groupless::transfer::EditFault>();
        send_and_sync::<protobuf_edit::markup::groupless::transfer::FrameFault>();
        send_and_sync::<protobuf_edit::markup::groupless::transfer::SaveFault>();
        send_and_sync::<protobuf_edit::markup::groupless::transfer::Children<'static>>();
        send_and_sync::<protobuf_edit::markup::groupless::transfer::Ancestors<'static>>();
        send_and_sync::<protobuf_edit::markup::groupless::transfer::Descent<'static>>();
        send_and_sync::<protobuf_edit::markup::groupless::transfer::RecordSpans>();
        send_and_sync::<protobuf_edit::markup::groupless::transfer::SaveSpans>();
        send_and_sync::<protobuf_edit::markup::groupless::transfer::Refusal>();
    }
}

/// The adopt family mirrors the patch's pins exactly: plain data
/// over an owned `Vec<u8>` — no share counter, no interior
/// mutability — so the machine itself stays on the positive side,
/// mid-edit thread crossing included.
#[cfg(any(feature = "adopt-grouped", feature = "adopt-groupless"))]
#[test]
fn the_adopt_family_is_send_and_sync() {
    send_and_sync::<protobuf_edit::adopt::Handle>();
    send_and_sync::<protobuf_edit::adopt::InsertAt>();
    send_and_sync::<protobuf_edit::adopt::EditStatus>();
    #[cfg(feature = "adopt-grouped")]
    {
        send_and_sync::<protobuf_edit::adopt::grouped::Adopt<'static>>();
        send_and_sync::<protobuf_edit::adopt::grouped::PayloadWrite<'static, 'static>>();
        send_and_sync::<protobuf_edit::adopt::grouped::SizedPayloadWrite<'static, 'static>>();
        send_and_sync::<protobuf_edit::adopt::grouped::Children<'static>>();
        send_and_sync::<protobuf_edit::adopt::grouped::Ancestors<'static>>();
        send_and_sync::<protobuf_edit::adopt::grouped::RecordSpans>();
        send_and_sync::<protobuf_edit::adopt::grouped::SaveSpans>();
        send_and_sync::<protobuf_edit::adopt::grouped::BorrowAdopt<'static>>();
        send_and_sync::<protobuf_edit::adopt::grouped::CopyAdopt>();
        send_and_sync::<protobuf_edit::adopt::grouped::CopyPayloadWrite<'static>>();
        send_and_sync::<protobuf_edit::adopt::grouped::SizedCopyPayloadWrite<'static>>();
        send_and_sync::<protobuf_edit::adopt::grouped::Descent>();
        send_and_sync::<protobuf_edit::adopt::grouped::OpenFault>();
        send_and_sync::<protobuf_edit::adopt::grouped::Fault>();
        send_and_sync::<protobuf_edit::adopt::grouped::FaultKind>();
        send_and_sync::<protobuf_edit::adopt::grouped::EditFault>();
        send_and_sync::<protobuf_edit::adopt::grouped::FrameFault>();
        send_and_sync::<protobuf_edit::adopt::grouped::SaveFault>();
        send_and_sync::<protobuf_edit::adopt::grouped::Refusal>();
    }
    #[cfg(feature = "adopt-groupless")]
    {
        send_and_sync::<protobuf_edit::adopt::groupless::Adopt<'static>>();
        send_and_sync::<protobuf_edit::adopt::groupless::PayloadWrite<'static, 'static>>();
        send_and_sync::<protobuf_edit::adopt::groupless::SizedPayloadWrite<'static, 'static>>();
        send_and_sync::<protobuf_edit::adopt::groupless::Children<'static>>();
        send_and_sync::<protobuf_edit::adopt::groupless::Ancestors<'static>>();
        send_and_sync::<protobuf_edit::adopt::groupless::RecordSpans>();
        send_and_sync::<protobuf_edit::adopt::groupless::SaveSpans>();
        send_and_sync::<protobuf_edit::adopt::groupless::BorrowAdopt<'static>>();
        send_and_sync::<protobuf_edit::adopt::groupless::CopyAdopt>();
        send_and_sync::<protobuf_edit::adopt::groupless::CopyPayloadWrite<'static>>();
        send_and_sync::<protobuf_edit::adopt::groupless::SizedCopyPayloadWrite<'static>>();
        send_and_sync::<protobuf_edit::adopt::groupless::Descent>();
        send_and_sync::<protobuf_edit::adopt::groupless::OpenFault>();
        send_and_sync::<protobuf_edit::adopt::groupless::Fault>();
        send_and_sync::<protobuf_edit::adopt::groupless::FaultKind>();
        send_and_sync::<protobuf_edit::adopt::groupless::EditFault>();
        send_and_sync::<protobuf_edit::adopt::groupless::FrameFault>();
        send_and_sync::<protobuf_edit::adopt::groupless::SaveFault>();
        send_and_sync::<protobuf_edit::adopt::groupless::Refusal>();
    }
    #[cfg(feature = "transfer-adopt-grouped")]
    {
        send_and_sync::<protobuf_edit::adopt::grouped::transfer::TransferAdopt<'static>>();
        send_and_sync::<protobuf_edit::adopt::grouped::transfer::PayloadTarget>();
        send_and_sync::<protobuf_edit::adopt::grouped::transfer::PayloadWrite<'static, 'static>>();
        send_and_sync::<protobuf_edit::adopt::grouped::transfer::SizedPayloadWrite<'static, 'static>>(
        );
        send_and_sync::<protobuf_edit::adopt::grouped::transfer::Children<'static>>();
        send_and_sync::<protobuf_edit::adopt::grouped::transfer::Ancestors<'static>>();
        send_and_sync::<protobuf_edit::adopt::grouped::transfer::RecordSpans>();
        send_and_sync::<protobuf_edit::adopt::grouped::transfer::SaveSpans>();
        send_and_sync::<protobuf_edit::adopt::grouped::transfer::Descent>();
        send_and_sync::<protobuf_edit::adopt::grouped::transfer::OpenFault>();
        send_and_sync::<protobuf_edit::adopt::grouped::transfer::Fault>();
        send_and_sync::<protobuf_edit::adopt::grouped::transfer::FaultKind>();
        send_and_sync::<protobuf_edit::adopt::grouped::transfer::EditFault>();
        send_and_sync::<protobuf_edit::adopt::grouped::transfer::FrameFault>();
        send_and_sync::<protobuf_edit::adopt::grouped::transfer::SaveFault>();
        send_and_sync::<protobuf_edit::adopt::grouped::transfer::Refusal>();
    }
    #[cfg(feature = "transfer-adopt-groupless")]
    {
        send_and_sync::<protobuf_edit::adopt::groupless::transfer::TransferAdopt<'static>>();
        send_and_sync::<protobuf_edit::adopt::groupless::transfer::PayloadTarget>();
        send_and_sync::<protobuf_edit::adopt::groupless::transfer::PayloadWrite<'static, 'static>>(
        );
        send_and_sync::<
            protobuf_edit::adopt::groupless::transfer::SizedPayloadWrite<'static, 'static>,
        >();
        send_and_sync::<protobuf_edit::adopt::groupless::transfer::Children<'static>>();
        send_and_sync::<protobuf_edit::adopt::groupless::transfer::Ancestors<'static>>();
        send_and_sync::<protobuf_edit::adopt::groupless::transfer::RecordSpans>();
        send_and_sync::<protobuf_edit::adopt::groupless::transfer::SaveSpans>();
        send_and_sync::<protobuf_edit::adopt::groupless::transfer::Descent>();
        send_and_sync::<protobuf_edit::adopt::groupless::transfer::OpenFault>();
        send_and_sync::<protobuf_edit::adopt::groupless::transfer::Fault>();
        send_and_sync::<protobuf_edit::adopt::groupless::transfer::FaultKind>();
        send_and_sync::<protobuf_edit::adopt::groupless::transfer::EditFault>();
        send_and_sync::<protobuf_edit::adopt::groupless::transfer::FrameFault>();
        send_and_sync::<protobuf_edit::adopt::groupless::transfer::SaveFault>();
        send_and_sync::<protobuf_edit::adopt::groupless::transfer::Refusal>();
    }
}

/// The stream-ingest adopt family mirrors the buffered adopt's
/// pins, and the ingest phase itself joins them: plain data over
/// owned `Vec`s — no share counter, no interior mutability — so a
/// mid-stream job crosses threads like a mid-edit machine.
#[cfg(any(feature = "stream-adopt-grouped", feature = "stream-adopt-groupless"))]
#[test]
fn the_stream_adopt_family_is_send_and_sync() {
    send_and_sync::<protobuf_edit::stream_adopt::Handle>();
    send_and_sync::<protobuf_edit::stream_adopt::InsertAt>();
    send_and_sync::<protobuf_edit::stream_adopt::EditStatus>();
    #[cfg(feature = "stream-adopt-grouped")]
    {
        send_and_sync::<protobuf_edit::stream_adopt::grouped::Ingest>();
        send_and_sync::<protobuf_edit::stream_adopt::grouped::Failure>();
        send_and_sync::<protobuf_edit::stream_adopt::grouped::IngestFault>();
        send_and_sync::<protobuf_edit::stream_adopt::grouped::IngestFaultKind>();
        send_and_sync::<protobuf_edit::stream_adopt::grouped::ChunkDisposition>();
        send_and_sync::<protobuf_edit::stream_adopt::grouped::StartFault>();
        send_and_sync::<protobuf_edit::stream_adopt::grouped::Adopt<'static>>();
        send_and_sync::<protobuf_edit::stream_adopt::grouped::PayloadWrite<'static, 'static>>();
        send_and_sync::<protobuf_edit::stream_adopt::grouped::SizedPayloadWrite<'static, 'static>>(
        );
        send_and_sync::<protobuf_edit::stream_adopt::grouped::Children<'static>>();
        send_and_sync::<protobuf_edit::stream_adopt::grouped::Ancestors<'static>>();
        send_and_sync::<protobuf_edit::stream_adopt::grouped::RecordSpans>();
        send_and_sync::<protobuf_edit::stream_adopt::grouped::SaveSpans>();
        send_and_sync::<protobuf_edit::stream_adopt::grouped::BorrowAdopt<'static>>();
        send_and_sync::<protobuf_edit::stream_adopt::grouped::CopyAdopt>();
        send_and_sync::<protobuf_edit::stream_adopt::grouped::CopyPayloadWrite<'static>>();
        send_and_sync::<protobuf_edit::stream_adopt::grouped::SizedCopyPayloadWrite<'static>>();
        send_and_sync::<protobuf_edit::stream_adopt::grouped::Descent>();
        send_and_sync::<protobuf_edit::stream_adopt::grouped::Fault>();
        send_and_sync::<protobuf_edit::stream_adopt::grouped::FaultKind>();
        send_and_sync::<protobuf_edit::stream_adopt::grouped::EditFault>();
        send_and_sync::<protobuf_edit::stream_adopt::grouped::FrameFault>();
        send_and_sync::<protobuf_edit::stream_adopt::grouped::SaveFault>();
        send_and_sync::<protobuf_edit::stream_adopt::grouped::Refusal>();
    }
    #[cfg(feature = "stream-adopt-groupless")]
    {
        send_and_sync::<protobuf_edit::stream_adopt::groupless::Ingest>();
        send_and_sync::<protobuf_edit::stream_adopt::groupless::Failure>();
        send_and_sync::<protobuf_edit::stream_adopt::groupless::IngestFault>();
        send_and_sync::<protobuf_edit::stream_adopt::groupless::IngestFaultKind>();
        send_and_sync::<protobuf_edit::stream_adopt::groupless::ChunkDisposition>();
        send_and_sync::<protobuf_edit::stream_adopt::groupless::StartFault>();
        send_and_sync::<protobuf_edit::stream_adopt::groupless::Adopt<'static>>();
        send_and_sync::<protobuf_edit::stream_adopt::groupless::PayloadWrite<'static, 'static>>();
        send_and_sync::<protobuf_edit::stream_adopt::groupless::SizedPayloadWrite<'static, 'static>>(
        );
        send_and_sync::<protobuf_edit::stream_adopt::groupless::Children<'static>>();
        send_and_sync::<protobuf_edit::stream_adopt::groupless::Ancestors<'static>>();
        send_and_sync::<protobuf_edit::stream_adopt::groupless::RecordSpans>();
        send_and_sync::<protobuf_edit::stream_adopt::groupless::SaveSpans>();
        send_and_sync::<protobuf_edit::stream_adopt::groupless::BorrowAdopt<'static>>();
        send_and_sync::<protobuf_edit::stream_adopt::groupless::CopyAdopt>();
        send_and_sync::<protobuf_edit::stream_adopt::groupless::CopyPayloadWrite<'static>>();
        send_and_sync::<protobuf_edit::stream_adopt::groupless::SizedCopyPayloadWrite<'static>>();
        send_and_sync::<protobuf_edit::stream_adopt::groupless::Descent>();
        send_and_sync::<protobuf_edit::stream_adopt::groupless::Fault>();
        send_and_sync::<protobuf_edit::stream_adopt::groupless::FaultKind>();
        send_and_sync::<protobuf_edit::stream_adopt::groupless::EditFault>();
        send_and_sync::<protobuf_edit::stream_adopt::groupless::FrameFault>();
        send_and_sync::<protobuf_edit::stream_adopt::groupless::SaveFault>();
        send_and_sync::<protobuf_edit::stream_adopt::groupless::Refusal>();
    }
    #[cfg(feature = "transfer-stream-adopt-grouped")]
    {
        send_and_sync::<protobuf_edit::stream_adopt::grouped::transfer::TransferAdopt<'static>>();
        send_and_sync::<protobuf_edit::stream_adopt::grouped::transfer::PayloadTarget>();
        send_and_sync::<
            protobuf_edit::stream_adopt::grouped::transfer::PayloadWrite<'static, 'static>,
        >();
        send_and_sync::<
            protobuf_edit::stream_adopt::grouped::transfer::SizedPayloadWrite<'static, 'static>,
        >();
        send_and_sync::<protobuf_edit::stream_adopt::grouped::transfer::Children<'static>>();
        send_and_sync::<protobuf_edit::stream_adopt::grouped::transfer::Ancestors<'static>>();
        send_and_sync::<protobuf_edit::stream_adopt::grouped::transfer::RecordSpans>();
        send_and_sync::<protobuf_edit::stream_adopt::grouped::transfer::SaveSpans>();
        send_and_sync::<protobuf_edit::stream_adopt::grouped::transfer::Descent>();
        send_and_sync::<protobuf_edit::stream_adopt::grouped::transfer::Fault>();
        send_and_sync::<protobuf_edit::stream_adopt::grouped::transfer::FaultKind>();
        send_and_sync::<protobuf_edit::stream_adopt::grouped::transfer::EditFault>();
        send_and_sync::<protobuf_edit::stream_adopt::grouped::transfer::FrameFault>();
        send_and_sync::<protobuf_edit::stream_adopt::grouped::transfer::SaveFault>();
        send_and_sync::<protobuf_edit::stream_adopt::grouped::transfer::Refusal>();
    }
    #[cfg(feature = "transfer-stream-adopt-groupless")]
    {
        send_and_sync::<protobuf_edit::stream_adopt::groupless::transfer::TransferAdopt<'static>>();
        send_and_sync::<protobuf_edit::stream_adopt::groupless::transfer::PayloadTarget>();
        send_and_sync::<
            protobuf_edit::stream_adopt::groupless::transfer::PayloadWrite<'static, 'static>,
        >();
        send_and_sync::<
            protobuf_edit::stream_adopt::groupless::transfer::SizedPayloadWrite<'static, 'static>,
        >();
        send_and_sync::<protobuf_edit::stream_adopt::groupless::transfer::Children<'static>>();
        send_and_sync::<protobuf_edit::stream_adopt::groupless::transfer::Ancestors<'static>>();
        send_and_sync::<protobuf_edit::stream_adopt::groupless::transfer::RecordSpans>();
        send_and_sync::<protobuf_edit::stream_adopt::groupless::transfer::SaveSpans>();
        send_and_sync::<protobuf_edit::stream_adopt::groupless::transfer::Descent>();
        send_and_sync::<protobuf_edit::stream_adopt::groupless::transfer::Fault>();
        send_and_sync::<protobuf_edit::stream_adopt::groupless::transfer::FaultKind>();
        send_and_sync::<protobuf_edit::stream_adopt::groupless::transfer::EditFault>();
        send_and_sync::<protobuf_edit::stream_adopt::groupless::transfer::FrameFault>();
        send_and_sync::<protobuf_edit::stream_adopt::groupless::transfer::SaveFault>();
        send_and_sync::<protobuf_edit::stream_adopt::groupless::transfer::Refusal>();
    }
}

/// The stream-ingest draft family mirrors the buffered draft's
/// pins, and the ingest phase itself joins them: plain data over
/// owned `Vec`s — no share counter, no interior mutability.
#[cfg(any(feature = "stream-draft-grouped", feature = "stream-draft-groupless"))]
#[test]
fn the_stream_draft_family_is_send_and_sync() {
    send_and_sync::<protobuf_edit::stream_draft::Handle>();
    #[cfg(feature = "stream-draft-grouped")]
    {
        send_and_sync::<protobuf_edit::stream_draft::grouped::Ingest>();
        send_and_sync::<protobuf_edit::stream_draft::grouped::Failure>();
        send_and_sync::<protobuf_edit::stream_draft::grouped::IngestFault>();
        send_and_sync::<protobuf_edit::stream_draft::grouped::IngestFaultKind>();
        send_and_sync::<protobuf_edit::stream_draft::grouped::ChunkDisposition>();
        send_and_sync::<protobuf_edit::stream_draft::grouped::ResourceSite>();
        send_and_sync::<protobuf_edit::stream_draft::grouped::StartFault>();
        send_and_sync::<protobuf_edit::stream_draft::grouped::Draft>();
        send_and_sync::<protobuf_edit::stream_draft::grouped::BorrowDraft<'static>>();
        send_and_sync::<protobuf_edit::stream_draft::grouped::PayloadFrame<'static>>();
        send_and_sync::<protobuf_edit::stream_draft::grouped::SizedPayloadFrame<'static>>();
        send_and_sync::<protobuf_edit::stream_draft::grouped::EditStatus>();
        send_and_sync::<protobuf_edit::stream_draft::grouped::InsertAt>();
        send_and_sync::<protobuf_edit::stream_draft::grouped::Fault>();
        send_and_sync::<protobuf_edit::stream_draft::grouped::FaultKind>();
        send_and_sync::<protobuf_edit::stream_draft::grouped::EditFault>();
        send_and_sync::<protobuf_edit::stream_draft::grouped::FrameFault>();
        send_and_sync::<protobuf_edit::stream_draft::grouped::SaveFault>();
        send_and_sync::<protobuf_edit::stream_draft::grouped::Children<'static>>();
        send_and_sync::<protobuf_edit::stream_draft::grouped::Ancestors<'static>>();
        send_and_sync::<protobuf_edit::stream_draft::grouped::Descent<'static>>();
        send_and_sync::<protobuf_edit::stream_draft::grouped::RecordSpans>();
        send_and_sync::<protobuf_edit::stream_draft::grouped::SaveSpans>();
    }
    #[cfg(feature = "stream-draft-groupless")]
    {
        send_and_sync::<protobuf_edit::stream_draft::groupless::Ingest>();
        send_and_sync::<protobuf_edit::stream_draft::groupless::Failure>();
        send_and_sync::<protobuf_edit::stream_draft::groupless::IngestFault>();
        send_and_sync::<protobuf_edit::stream_draft::groupless::IngestFaultKind>();
        send_and_sync::<protobuf_edit::stream_draft::groupless::ChunkDisposition>();
        send_and_sync::<protobuf_edit::stream_draft::groupless::ResourceSite>();
        send_and_sync::<protobuf_edit::stream_draft::groupless::StartFault>();
        send_and_sync::<protobuf_edit::stream_draft::groupless::Draft>();
        send_and_sync::<protobuf_edit::stream_draft::groupless::BorrowDraft<'static>>();
        send_and_sync::<protobuf_edit::stream_draft::groupless::PayloadFrame<'static>>();
        send_and_sync::<protobuf_edit::stream_draft::groupless::SizedPayloadFrame<'static>>();
        send_and_sync::<protobuf_edit::stream_draft::groupless::EditStatus>();
        send_and_sync::<protobuf_edit::stream_draft::groupless::InsertAt>();
        send_and_sync::<protobuf_edit::stream_draft::groupless::Fault>();
        send_and_sync::<protobuf_edit::stream_draft::groupless::FaultKind>();
        send_and_sync::<protobuf_edit::stream_draft::groupless::EditFault>();
        send_and_sync::<protobuf_edit::stream_draft::groupless::FrameFault>();
        send_and_sync::<protobuf_edit::stream_draft::groupless::SaveFault>();
        send_and_sync::<protobuf_edit::stream_draft::groupless::Refusal>();
        send_and_sync::<protobuf_edit::stream_draft::groupless::Children<'static>>();
        send_and_sync::<protobuf_edit::stream_draft::groupless::Ancestors<'static>>();
        send_and_sync::<protobuf_edit::stream_draft::groupless::Descent<'static>>();
        send_and_sync::<protobuf_edit::stream_draft::groupless::RecordSpans>();
        send_and_sync::<protobuf_edit::stream_draft::groupless::SaveSpans>();
    }
    #[cfg(feature = "transfer-stream-draft-grouped")]
    {
        send_and_sync::<protobuf_edit::stream_draft::grouped::transfer::TransferDraft>();
        send_and_sync::<protobuf_edit::stream_draft::grouped::transfer::TransferBorrowDraft<'static>>(
        );
        send_and_sync::<protobuf_edit::stream_draft::grouped::transfer::PayloadFrame<'static>>();
        send_and_sync::<protobuf_edit::stream_draft::grouped::transfer::SizedPayloadFrame<'static>>(
        );
        send_and_sync::<protobuf_edit::stream_draft::grouped::transfer::EditStatus>();
        send_and_sync::<protobuf_edit::stream_draft::grouped::transfer::PayloadTarget>();
        send_and_sync::<protobuf_edit::stream_draft::grouped::transfer::Fault>();
        send_and_sync::<protobuf_edit::stream_draft::grouped::transfer::FaultKind>();
        send_and_sync::<protobuf_edit::stream_draft::grouped::transfer::EditFault>();
        send_and_sync::<protobuf_edit::stream_draft::grouped::transfer::FrameFault>();
        send_and_sync::<protobuf_edit::stream_draft::grouped::transfer::SaveFault>();
        send_and_sync::<protobuf_edit::stream_draft::grouped::transfer::Children<'static>>();
        send_and_sync::<protobuf_edit::stream_draft::grouped::transfer::Ancestors<'static>>();
        send_and_sync::<protobuf_edit::stream_draft::grouped::transfer::Descent<'static>>();
        send_and_sync::<protobuf_edit::stream_draft::grouped::transfer::RecordSpans>();
        send_and_sync::<protobuf_edit::stream_draft::grouped::transfer::SaveSpans>();
    }
    #[cfg(feature = "transfer-stream-draft-groupless")]
    {
        send_and_sync::<protobuf_edit::stream_draft::groupless::transfer::TransferDraft>();
        send_and_sync::<
            protobuf_edit::stream_draft::groupless::transfer::TransferBorrowDraft<'static>,
        >();
        send_and_sync::<protobuf_edit::stream_draft::groupless::transfer::PayloadFrame<'static>>();
        send_and_sync::<protobuf_edit::stream_draft::groupless::transfer::SizedPayloadFrame<'static>>(
        );
        send_and_sync::<protobuf_edit::stream_draft::groupless::transfer::EditStatus>();
        send_and_sync::<protobuf_edit::stream_draft::groupless::transfer::PayloadTarget>();
        send_and_sync::<protobuf_edit::stream_draft::groupless::transfer::Fault>();
        send_and_sync::<protobuf_edit::stream_draft::groupless::transfer::FaultKind>();
        send_and_sync::<protobuf_edit::stream_draft::groupless::transfer::EditFault>();
        send_and_sync::<protobuf_edit::stream_draft::groupless::transfer::FrameFault>();
        send_and_sync::<protobuf_edit::stream_draft::groupless::transfer::SaveFault>();
        send_and_sync::<protobuf_edit::stream_draft::groupless::transfer::Refusal>();
        send_and_sync::<protobuf_edit::stream_draft::groupless::transfer::Children<'static>>();
        send_and_sync::<protobuf_edit::stream_draft::groupless::transfer::Ancestors<'static>>();
        send_and_sync::<protobuf_edit::stream_draft::groupless::transfer::Descent<'static>>();
        send_and_sync::<protobuf_edit::stream_draft::groupless::transfer::RecordSpans>();
        send_and_sync::<protobuf_edit::stream_draft::groupless::transfer::SaveSpans>();
    }
}

/// The stream-ingest intake family mirrors the buffered intake's
/// pins, and the ingest phase itself joins them: plain data over
/// owned `Vec`s — no share counter, no interior mutability — so a
/// mid-stream job crosses threads like a mid-edit machine.
#[cfg(any(feature = "stream-intake-grouped", feature = "stream-intake-groupless"))]
#[test]
fn the_stream_intake_family_is_send_and_sync() {
    send_and_sync::<protobuf_edit::stream_intake::Handle>();
    send_and_sync::<protobuf_edit::stream_intake::InsertAt>();
    send_and_sync::<protobuf_edit::stream_intake::EditStatus>();
    #[cfg(feature = "stream-intake-grouped")]
    {
        send_and_sync::<protobuf_edit::stream_intake::grouped::Ingest>();
        send_and_sync::<protobuf_edit::stream_intake::grouped::Failure>();
        send_and_sync::<protobuf_edit::stream_intake::grouped::IngestFault>();
        send_and_sync::<protobuf_edit::stream_intake::grouped::IngestFaultKind>();
        send_and_sync::<protobuf_edit::stream_intake::grouped::ChunkDisposition>();
        send_and_sync::<protobuf_edit::stream_intake::grouped::StartFault>();
        send_and_sync::<protobuf_edit::stream_intake::grouped::Intake<'static>>();
        send_and_sync::<protobuf_edit::stream_intake::grouped::PayloadWrite<'static, 'static>>();
        send_and_sync::<protobuf_edit::stream_intake::grouped::SizedPayloadWrite<'static, 'static>>(
        );
        send_and_sync::<protobuf_edit::stream_intake::grouped::Children<'static>>();
        send_and_sync::<protobuf_edit::stream_intake::grouped::Ancestors<'static>>();
        send_and_sync::<protobuf_edit::stream_intake::grouped::RecordSpans>();
        send_and_sync::<protobuf_edit::stream_intake::grouped::SaveSpans>();
        send_and_sync::<protobuf_edit::stream_intake::grouped::BorrowIntake<'static>>();
        send_and_sync::<protobuf_edit::stream_intake::grouped::CopyIntake>();
        send_and_sync::<protobuf_edit::stream_intake::grouped::CopyPayloadWrite<'static>>();
        send_and_sync::<protobuf_edit::stream_intake::grouped::SizedCopyPayloadWrite<'static>>();
        send_and_sync::<protobuf_edit::stream_intake::grouped::Descent>();
        send_and_sync::<protobuf_edit::stream_intake::grouped::Fault>();
        send_and_sync::<protobuf_edit::stream_intake::grouped::FaultKind>();
        send_and_sync::<protobuf_edit::stream_intake::grouped::EditFault>();
        send_and_sync::<protobuf_edit::stream_intake::grouped::FrameFault>();
        send_and_sync::<protobuf_edit::stream_intake::grouped::SaveFault>();
        send_and_sync::<protobuf_edit::stream_intake::grouped::Refusal>();
    }
    #[cfg(feature = "stream-intake-groupless")]
    {
        send_and_sync::<protobuf_edit::stream_intake::groupless::Ingest>();
        send_and_sync::<protobuf_edit::stream_intake::groupless::Failure>();
        send_and_sync::<protobuf_edit::stream_intake::groupless::IngestFault>();
        send_and_sync::<protobuf_edit::stream_intake::groupless::IngestFaultKind>();
        send_and_sync::<protobuf_edit::stream_intake::groupless::ChunkDisposition>();
        send_and_sync::<protobuf_edit::stream_intake::groupless::StartFault>();
        send_and_sync::<protobuf_edit::stream_intake::groupless::Intake<'static>>();
        send_and_sync::<protobuf_edit::stream_intake::groupless::PayloadWrite<'static, 'static>>();
        send_and_sync::<protobuf_edit::stream_intake::groupless::SizedPayloadWrite<'static, 'static>>(
        );
        send_and_sync::<protobuf_edit::stream_intake::groupless::Children<'static>>();
        send_and_sync::<protobuf_edit::stream_intake::groupless::Ancestors<'static>>();
        send_and_sync::<protobuf_edit::stream_intake::groupless::RecordSpans>();
        send_and_sync::<protobuf_edit::stream_intake::groupless::SaveSpans>();
        send_and_sync::<protobuf_edit::stream_intake::groupless::BorrowIntake<'static>>();
        send_and_sync::<protobuf_edit::stream_intake::groupless::CopyIntake>();
        send_and_sync::<protobuf_edit::stream_intake::groupless::CopyPayloadWrite<'static>>();
        send_and_sync::<protobuf_edit::stream_intake::groupless::SizedCopyPayloadWrite<'static>>();
        send_and_sync::<protobuf_edit::stream_intake::groupless::Descent>();
        send_and_sync::<protobuf_edit::stream_intake::groupless::Fault>();
        send_and_sync::<protobuf_edit::stream_intake::groupless::FaultKind>();
        send_and_sync::<protobuf_edit::stream_intake::groupless::EditFault>();
        send_and_sync::<protobuf_edit::stream_intake::groupless::FrameFault>();
        send_and_sync::<protobuf_edit::stream_intake::groupless::SaveFault>();
        send_and_sync::<protobuf_edit::stream_intake::groupless::Refusal>();
    }
    #[cfg(feature = "transfer-stream-intake-grouped")]
    {
        send_and_sync::<protobuf_edit::stream_intake::grouped::transfer::TransferIntake<'static>>();
        send_and_sync::<protobuf_edit::stream_intake::grouped::transfer::PayloadTarget>();
        send_and_sync::<
            protobuf_edit::stream_intake::grouped::transfer::PayloadWrite<'static, 'static>,
        >();
        send_and_sync::<
            protobuf_edit::stream_intake::grouped::transfer::SizedPayloadWrite<'static, 'static>,
        >();
        send_and_sync::<protobuf_edit::stream_intake::grouped::transfer::Children<'static>>();
        send_and_sync::<protobuf_edit::stream_intake::grouped::transfer::Ancestors<'static>>();
        send_and_sync::<protobuf_edit::stream_intake::grouped::transfer::RecordSpans>();
        send_and_sync::<protobuf_edit::stream_intake::grouped::transfer::SaveSpans>();
        send_and_sync::<protobuf_edit::stream_intake::grouped::transfer::Descent>();
        send_and_sync::<protobuf_edit::stream_intake::grouped::transfer::Fault>();
        send_and_sync::<protobuf_edit::stream_intake::grouped::transfer::FaultKind>();
        send_and_sync::<protobuf_edit::stream_intake::grouped::transfer::EditFault>();
        send_and_sync::<protobuf_edit::stream_intake::grouped::transfer::FrameFault>();
        send_and_sync::<protobuf_edit::stream_intake::grouped::transfer::SaveFault>();
        send_and_sync::<protobuf_edit::stream_intake::grouped::transfer::Refusal>();
    }
    #[cfg(feature = "transfer-stream-intake-groupless")]
    {
        send_and_sync::<protobuf_edit::stream_intake::groupless::transfer::TransferIntake<'static>>(
        );
        send_and_sync::<protobuf_edit::stream_intake::groupless::transfer::PayloadTarget>();
        send_and_sync::<
            protobuf_edit::stream_intake::groupless::transfer::PayloadWrite<'static, 'static>,
        >();
        send_and_sync::<
            protobuf_edit::stream_intake::groupless::transfer::SizedPayloadWrite<'static, 'static>,
        >();
        send_and_sync::<protobuf_edit::stream_intake::groupless::transfer::Children<'static>>();
        send_and_sync::<protobuf_edit::stream_intake::groupless::transfer::Ancestors<'static>>();
        send_and_sync::<protobuf_edit::stream_intake::groupless::transfer::RecordSpans>();
        send_and_sync::<protobuf_edit::stream_intake::groupless::transfer::SaveSpans>();
        send_and_sync::<protobuf_edit::stream_intake::groupless::transfer::Descent>();
        send_and_sync::<protobuf_edit::stream_intake::groupless::transfer::Fault>();
        send_and_sync::<protobuf_edit::stream_intake::groupless::transfer::FaultKind>();
        send_and_sync::<protobuf_edit::stream_intake::groupless::transfer::EditFault>();
        send_and_sync::<protobuf_edit::stream_intake::groupless::transfer::FrameFault>();
        send_and_sync::<protobuf_edit::stream_intake::groupless::transfer::SaveFault>();
        send_and_sync::<protobuf_edit::stream_intake::groupless::transfer::Refusal>();
    }
}

/// The amend family carries the patch's pins under the canonical
/// door: plain data over `&[u8]` — no share counter, no interior
/// mutability — so the machine itself stays on the positive side.
#[cfg(any(feature = "amend-grouped", feature = "amend-groupless"))]
#[test]
fn the_amend_family_is_send_and_sync() {
    send_and_sync::<protobuf_edit::amend::Handle>();
    send_and_sync::<protobuf_edit::amend::InsertAt>();
    send_and_sync::<protobuf_edit::amend::EditStatus>();
    #[cfg(feature = "amend-grouped")]
    {
        send_and_sync::<protobuf_edit::amend::grouped::Amend<'static, 'static>>();
        send_and_sync::<protobuf_edit::amend::grouped::PayloadWrite<'static, 'static, 'static>>();
        send_and_sync::<protobuf_edit::amend::grouped::SizedPayloadWrite<'static, 'static, 'static>>(
        );
        send_and_sync::<protobuf_edit::amend::grouped::Children<'static>>();
        send_and_sync::<protobuf_edit::amend::grouped::Ancestors<'static>>();
        send_and_sync::<protobuf_edit::amend::grouped::RecordSpans>();
        send_and_sync::<protobuf_edit::amend::grouped::SaveSpans>();
        send_and_sync::<protobuf_edit::amend::grouped::BorrowAmend<'static, 'static>>();
        send_and_sync::<protobuf_edit::amend::grouped::CopyAmend<'static>>();
        send_and_sync::<protobuf_edit::amend::grouped::CopyPayloadWrite<'static, 'static>>();
        send_and_sync::<protobuf_edit::amend::grouped::SizedCopyPayloadWrite<'static, 'static>>();
        send_and_sync::<protobuf_edit::amend::grouped::Descent>();
        send_and_sync::<protobuf_edit::amend::grouped::OpenFault>();
        send_and_sync::<protobuf_edit::amend::grouped::Fault>();
        send_and_sync::<protobuf_edit::amend::grouped::FaultKind>();
        send_and_sync::<protobuf_edit::amend::grouped::EditFault>();
        send_and_sync::<protobuf_edit::amend::grouped::FrameFault>();
        send_and_sync::<protobuf_edit::amend::grouped::SaveFault>();
        send_and_sync::<protobuf_edit::amend::grouped::Refusal>();
    }
    #[cfg(feature = "amend-groupless")]
    {
        send_and_sync::<protobuf_edit::amend::groupless::Amend<'static, 'static>>();
        send_and_sync::<protobuf_edit::amend::groupless::PayloadWrite<'static, 'static, 'static>>();
        send_and_sync::<
            protobuf_edit::amend::groupless::SizedPayloadWrite<'static, 'static, 'static>,
        >();
        send_and_sync::<protobuf_edit::amend::groupless::Children<'static>>();
        send_and_sync::<protobuf_edit::amend::groupless::Ancestors<'static>>();
        send_and_sync::<protobuf_edit::amend::groupless::RecordSpans>();
        send_and_sync::<protobuf_edit::amend::groupless::SaveSpans>();
        send_and_sync::<protobuf_edit::amend::groupless::BorrowAmend<'static, 'static>>();
        send_and_sync::<protobuf_edit::amend::groupless::CopyAmend<'static>>();
        send_and_sync::<protobuf_edit::amend::groupless::CopyPayloadWrite<'static, 'static>>();
        send_and_sync::<protobuf_edit::amend::groupless::SizedCopyPayloadWrite<'static, 'static>>();
        send_and_sync::<protobuf_edit::amend::groupless::Descent>();
        send_and_sync::<protobuf_edit::amend::groupless::OpenFault>();
        send_and_sync::<protobuf_edit::amend::groupless::Fault>();
        send_and_sync::<protobuf_edit::amend::groupless::FaultKind>();
        send_and_sync::<protobuf_edit::amend::groupless::EditFault>();
        send_and_sync::<protobuf_edit::amend::groupless::FrameFault>();
        send_and_sync::<protobuf_edit::amend::groupless::SaveFault>();
        send_and_sync::<protobuf_edit::amend::groupless::Refusal>();
    }
    #[cfg(feature = "transfer-amend-grouped")]
    {
        send_and_sync::<protobuf_edit::amend::grouped::transfer::TransferAmend<'static, 'static>>();
        send_and_sync::<protobuf_edit::amend::grouped::transfer::PayloadTarget>();
        send_and_sync::<
            protobuf_edit::amend::grouped::transfer::PayloadWrite<'static, 'static, 'static>,
        >();
        send_and_sync::<
            protobuf_edit::amend::grouped::transfer::SizedPayloadWrite<'static, 'static, 'static>,
        >();
        send_and_sync::<protobuf_edit::amend::grouped::transfer::Children<'static>>();
        send_and_sync::<protobuf_edit::amend::grouped::transfer::Ancestors<'static>>();
        send_and_sync::<protobuf_edit::amend::grouped::transfer::RecordSpans>();
        send_and_sync::<protobuf_edit::amend::grouped::transfer::SaveSpans>();
        send_and_sync::<protobuf_edit::amend::grouped::transfer::Descent>();
        send_and_sync::<protobuf_edit::amend::grouped::transfer::OpenFault>();
        send_and_sync::<protobuf_edit::amend::grouped::transfer::Fault>();
        send_and_sync::<protobuf_edit::amend::grouped::transfer::FaultKind>();
        send_and_sync::<protobuf_edit::amend::grouped::transfer::EditFault>();
        send_and_sync::<protobuf_edit::amend::grouped::transfer::FrameFault>();
        send_and_sync::<protobuf_edit::amend::grouped::transfer::SaveFault>();
        send_and_sync::<protobuf_edit::amend::grouped::transfer::Refusal>();
    }
    #[cfg(feature = "transfer-amend-groupless")]
    {
        send_and_sync::<protobuf_edit::amend::groupless::transfer::TransferAmend<'static, 'static>>(
        );
        send_and_sync::<protobuf_edit::amend::groupless::transfer::PayloadTarget>();
        send_and_sync::<
            protobuf_edit::amend::groupless::transfer::PayloadWrite<'static, 'static, 'static>,
        >();
        send_and_sync::<
            protobuf_edit::amend::groupless::transfer::SizedPayloadWrite<'static, 'static, 'static>,
        >();
        send_and_sync::<protobuf_edit::amend::groupless::transfer::Children<'static>>();
        send_and_sync::<protobuf_edit::amend::groupless::transfer::Ancestors<'static>>();
        send_and_sync::<protobuf_edit::amend::groupless::transfer::RecordSpans>();
        send_and_sync::<protobuf_edit::amend::groupless::transfer::SaveSpans>();
        send_and_sync::<protobuf_edit::amend::groupless::transfer::Descent>();
        send_and_sync::<protobuf_edit::amend::groupless::transfer::OpenFault>();
        send_and_sync::<protobuf_edit::amend::groupless::transfer::Fault>();
        send_and_sync::<protobuf_edit::amend::groupless::transfer::FaultKind>();
        send_and_sync::<protobuf_edit::amend::groupless::transfer::EditFault>();
        send_and_sync::<protobuf_edit::amend::groupless::transfer::FrameFault>();
        send_and_sync::<protobuf_edit::amend::groupless::transfer::SaveFault>();
        send_and_sync::<protobuf_edit::amend::groupless::transfer::Refusal>();
    }
}

/// The review family carries the markup's pins under the canonical
/// door: the machine holds a plain `&[u8]` — no share counting, no
/// interior mutability — so the review, its payload frames, and its
/// whole vocabulary are `Send + Sync` within the borrow's extent.
#[cfg(any(feature = "review-grouped", feature = "review-groupless"))]
#[test]
fn the_review_family_is_send_and_sync() {
    send_and_sync::<protobuf_edit::review::Handle>();
    #[cfg(feature = "review-grouped")]
    {
        send_and_sync::<protobuf_edit::review::grouped::Review<'static>>();
        send_and_sync::<protobuf_edit::review::grouped::PayloadFrame<'static, 'static>>();
        send_and_sync::<protobuf_edit::review::grouped::SizedPayloadFrame<'static, 'static>>();
        send_and_sync::<protobuf_edit::review::grouped::EditStatus>();
        send_and_sync::<protobuf_edit::review::grouped::InsertAt>();
        send_and_sync::<protobuf_edit::review::grouped::OpenFault>();
        send_and_sync::<protobuf_edit::review::grouped::Fault>();
        send_and_sync::<protobuf_edit::review::grouped::FaultKind>();
        send_and_sync::<protobuf_edit::review::grouped::EditFault>();
        send_and_sync::<protobuf_edit::review::grouped::BorrowReview<'static, 'static>>();
        send_and_sync::<protobuf_edit::review::grouped::MixReview<'static, 'static>>();
        send_and_sync::<protobuf_edit::review::grouped::MixPayloadFrame<'static, 'static, 'static>>(
        );
        send_and_sync::<
            protobuf_edit::review::grouped::MixSizedPayloadFrame<'static, 'static, 'static>,
        >();
        send_and_sync::<protobuf_edit::review::grouped::FrameFault>();
        send_and_sync::<protobuf_edit::review::grouped::SaveFault>();
        send_and_sync::<protobuf_edit::review::grouped::Refusal>();
        send_and_sync::<protobuf_edit::review::grouped::Children<'static>>();
        send_and_sync::<protobuf_edit::review::grouped::Ancestors<'static>>();
        send_and_sync::<protobuf_edit::review::grouped::Descent<'static>>();
        send_and_sync::<protobuf_edit::review::grouped::RecordSpans>();
        send_and_sync::<protobuf_edit::review::grouped::SaveSpans>();
    }
    #[cfg(feature = "review-groupless")]
    {
        send_and_sync::<protobuf_edit::review::groupless::Review<'static>>();
        send_and_sync::<protobuf_edit::review::groupless::PayloadFrame<'static, 'static>>();
        send_and_sync::<protobuf_edit::review::groupless::SizedPayloadFrame<'static, 'static>>();
        send_and_sync::<protobuf_edit::review::groupless::EditStatus>();
        send_and_sync::<protobuf_edit::review::groupless::InsertAt>();
        send_and_sync::<protobuf_edit::review::groupless::OpenFault>();
        send_and_sync::<protobuf_edit::review::groupless::Fault>();
        send_and_sync::<protobuf_edit::review::groupless::FaultKind>();
        send_and_sync::<protobuf_edit::review::groupless::EditFault>();
        send_and_sync::<protobuf_edit::review::groupless::BorrowReview<'static, 'static>>();
        send_and_sync::<protobuf_edit::review::groupless::MixReview<'static, 'static>>();
        send_and_sync::<protobuf_edit::review::groupless::MixPayloadFrame<'static, 'static, 'static>>(
        );
        send_and_sync::<
            protobuf_edit::review::groupless::MixSizedPayloadFrame<'static, 'static, 'static>,
        >();
        send_and_sync::<protobuf_edit::review::groupless::FrameFault>();
        send_and_sync::<protobuf_edit::review::groupless::SaveFault>();
        send_and_sync::<protobuf_edit::review::groupless::Refusal>();
        send_and_sync::<protobuf_edit::review::groupless::Children<'static>>();
        send_and_sync::<protobuf_edit::review::groupless::Ancestors<'static>>();
        send_and_sync::<protobuf_edit::review::groupless::Descent<'static>>();
        send_and_sync::<protobuf_edit::review::groupless::RecordSpans>();
        send_and_sync::<protobuf_edit::review::groupless::SaveSpans>();
    }
    #[cfg(feature = "transfer-review-grouped")]
    {
        send_and_sync::<protobuf_edit::review::grouped::transfer::TransferReview<'static>>();
        send_and_sync::<
            protobuf_edit::review::grouped::transfer::TransferBorrowReview<'static, 'static>,
        >();
        send_and_sync::<protobuf_edit::review::grouped::transfer::PayloadFrame<'static, 'static>>();
        send_and_sync::<
            protobuf_edit::review::grouped::transfer::SizedPayloadFrame<'static, 'static>,
        >();
        send_and_sync::<protobuf_edit::review::grouped::transfer::EditStatus>();
        send_and_sync::<protobuf_edit::review::grouped::transfer::PayloadTarget>();
        send_and_sync::<protobuf_edit::review::grouped::transfer::OpenFault>();
        send_and_sync::<protobuf_edit::review::grouped::transfer::Fault>();
        send_and_sync::<protobuf_edit::review::grouped::transfer::FaultKind>();
        send_and_sync::<protobuf_edit::review::grouped::transfer::EditFault>();
        send_and_sync::<protobuf_edit::review::grouped::transfer::FrameFault>();
        send_and_sync::<protobuf_edit::review::grouped::transfer::SaveFault>();
        send_and_sync::<protobuf_edit::review::grouped::transfer::Refusal>();
        send_and_sync::<protobuf_edit::review::grouped::transfer::Children<'static>>();
        send_and_sync::<protobuf_edit::review::grouped::transfer::Ancestors<'static>>();
        send_and_sync::<protobuf_edit::review::grouped::transfer::Descent<'static>>();
        send_and_sync::<protobuf_edit::review::grouped::transfer::RecordSpans>();
        send_and_sync::<protobuf_edit::review::grouped::transfer::SaveSpans>();
    }
    #[cfg(feature = "transfer-review-groupless")]
    {
        send_and_sync::<protobuf_edit::review::groupless::transfer::TransferReview<'static>>();
        send_and_sync::<
            protobuf_edit::review::groupless::transfer::TransferBorrowReview<'static, 'static>,
        >();
        send_and_sync::<protobuf_edit::review::groupless::transfer::PayloadFrame<'static, 'static>>(
        );
        send_and_sync::<
            protobuf_edit::review::groupless::transfer::SizedPayloadFrame<'static, 'static>,
        >();
        send_and_sync::<protobuf_edit::review::groupless::transfer::EditStatus>();
        send_and_sync::<protobuf_edit::review::groupless::transfer::PayloadTarget>();
        send_and_sync::<protobuf_edit::review::groupless::transfer::OpenFault>();
        send_and_sync::<protobuf_edit::review::groupless::transfer::Fault>();
        send_and_sync::<protobuf_edit::review::groupless::transfer::FaultKind>();
        send_and_sync::<protobuf_edit::review::groupless::transfer::EditFault>();
        send_and_sync::<protobuf_edit::review::groupless::transfer::FrameFault>();
        send_and_sync::<protobuf_edit::review::groupless::transfer::SaveFault>();
        send_and_sync::<protobuf_edit::review::groupless::transfer::Children<'static>>();
        send_and_sync::<protobuf_edit::review::groupless::transfer::Ancestors<'static>>();
        send_and_sync::<protobuf_edit::review::groupless::transfer::Descent<'static>>();
        send_and_sync::<protobuf_edit::review::groupless::transfer::RecordSpans>();
        send_and_sync::<protobuf_edit::review::groupless::transfer::SaveSpans>();
        send_and_sync::<protobuf_edit::review::groupless::transfer::Refusal>();
    }
}

/// The intake family carries the adopt's pins under the canonical
/// door: plain data over an owned `Vec<u8>` — no share counter, no
/// interior mutability — so the machine itself stays on the
/// positive side, mid-edit thread crossing included.
#[cfg(any(feature = "intake-grouped", feature = "intake-groupless"))]
#[test]
fn the_intake_family_is_send_and_sync() {
    send_and_sync::<protobuf_edit::intake::Handle>();
    send_and_sync::<protobuf_edit::intake::InsertAt>();
    send_and_sync::<protobuf_edit::intake::EditStatus>();
    #[cfg(feature = "intake-grouped")]
    {
        send_and_sync::<protobuf_edit::intake::grouped::Intake<'static>>();
        send_and_sync::<protobuf_edit::intake::grouped::PayloadWrite<'static, 'static>>();
        send_and_sync::<protobuf_edit::intake::grouped::SizedPayloadWrite<'static, 'static>>();
        send_and_sync::<protobuf_edit::intake::grouped::Children<'static>>();
        send_and_sync::<protobuf_edit::intake::grouped::Ancestors<'static>>();
        send_and_sync::<protobuf_edit::intake::grouped::RecordSpans>();
        send_and_sync::<protobuf_edit::intake::grouped::SaveSpans>();
        send_and_sync::<protobuf_edit::intake::grouped::BorrowIntake<'static>>();
        send_and_sync::<protobuf_edit::intake::grouped::CopyIntake>();
        send_and_sync::<protobuf_edit::intake::grouped::CopyPayloadWrite<'static>>();
        send_and_sync::<protobuf_edit::intake::grouped::SizedCopyPayloadWrite<'static>>();
        send_and_sync::<protobuf_edit::intake::grouped::Descent>();
        send_and_sync::<protobuf_edit::intake::grouped::OpenFault>();
        send_and_sync::<protobuf_edit::intake::grouped::Fault>();
        send_and_sync::<protobuf_edit::intake::grouped::FaultKind>();
        send_and_sync::<protobuf_edit::intake::grouped::EditFault>();
        send_and_sync::<protobuf_edit::intake::grouped::FrameFault>();
        send_and_sync::<protobuf_edit::intake::grouped::SaveFault>();
        send_and_sync::<protobuf_edit::intake::grouped::Refusal>();
    }
    #[cfg(feature = "intake-groupless")]
    {
        send_and_sync::<protobuf_edit::intake::groupless::Intake<'static>>();
        send_and_sync::<protobuf_edit::intake::groupless::PayloadWrite<'static, 'static>>();
        send_and_sync::<protobuf_edit::intake::groupless::SizedPayloadWrite<'static, 'static>>();
        send_and_sync::<protobuf_edit::intake::groupless::Children<'static>>();
        send_and_sync::<protobuf_edit::intake::groupless::Ancestors<'static>>();
        send_and_sync::<protobuf_edit::intake::groupless::RecordSpans>();
        send_and_sync::<protobuf_edit::intake::groupless::SaveSpans>();
        send_and_sync::<protobuf_edit::intake::groupless::BorrowIntake<'static>>();
        send_and_sync::<protobuf_edit::intake::groupless::CopyIntake>();
        send_and_sync::<protobuf_edit::intake::groupless::CopyPayloadWrite<'static>>();
        send_and_sync::<protobuf_edit::intake::groupless::SizedCopyPayloadWrite<'static>>();
        send_and_sync::<protobuf_edit::intake::groupless::Descent>();
        send_and_sync::<protobuf_edit::intake::groupless::OpenFault>();
        send_and_sync::<protobuf_edit::intake::groupless::Fault>();
        send_and_sync::<protobuf_edit::intake::groupless::FaultKind>();
        send_and_sync::<protobuf_edit::intake::groupless::EditFault>();
        send_and_sync::<protobuf_edit::intake::groupless::FrameFault>();
        send_and_sync::<protobuf_edit::intake::groupless::SaveFault>();
        send_and_sync::<protobuf_edit::intake::groupless::Refusal>();
    }
    #[cfg(feature = "transfer-intake-grouped")]
    {
        send_and_sync::<protobuf_edit::intake::grouped::transfer::TransferIntake<'static>>();
        send_and_sync::<protobuf_edit::intake::grouped::transfer::PayloadTarget>();
        send_and_sync::<protobuf_edit::intake::grouped::transfer::PayloadWrite<'static, 'static>>();
        send_and_sync::<
            protobuf_edit::intake::grouped::transfer::SizedPayloadWrite<'static, 'static>,
        >();
        send_and_sync::<protobuf_edit::intake::grouped::transfer::Children<'static>>();
        send_and_sync::<protobuf_edit::intake::grouped::transfer::Ancestors<'static>>();
        send_and_sync::<protobuf_edit::intake::grouped::transfer::RecordSpans>();
        send_and_sync::<protobuf_edit::intake::grouped::transfer::SaveSpans>();
        send_and_sync::<protobuf_edit::intake::grouped::transfer::Descent>();
        send_and_sync::<protobuf_edit::intake::grouped::transfer::OpenFault>();
        send_and_sync::<protobuf_edit::intake::grouped::transfer::Fault>();
        send_and_sync::<protobuf_edit::intake::grouped::transfer::FaultKind>();
        send_and_sync::<protobuf_edit::intake::grouped::transfer::EditFault>();
        send_and_sync::<protobuf_edit::intake::grouped::transfer::FrameFault>();
        send_and_sync::<protobuf_edit::intake::grouped::transfer::SaveFault>();
        send_and_sync::<protobuf_edit::intake::grouped::transfer::Refusal>();
    }
    #[cfg(feature = "transfer-intake-groupless")]
    {
        send_and_sync::<protobuf_edit::intake::groupless::transfer::TransferIntake<'static>>();
        send_and_sync::<protobuf_edit::intake::groupless::transfer::PayloadTarget>();
        send_and_sync::<protobuf_edit::intake::groupless::transfer::PayloadWrite<'static, 'static>>(
        );
        send_and_sync::<
            protobuf_edit::intake::groupless::transfer::SizedPayloadWrite<'static, 'static>,
        >();
        send_and_sync::<protobuf_edit::intake::groupless::transfer::Children<'static>>();
        send_and_sync::<protobuf_edit::intake::groupless::transfer::Ancestors<'static>>();
        send_and_sync::<protobuf_edit::intake::groupless::transfer::RecordSpans>();
        send_and_sync::<protobuf_edit::intake::groupless::transfer::SaveSpans>();
        send_and_sync::<protobuf_edit::intake::groupless::transfer::Descent>();
        send_and_sync::<protobuf_edit::intake::groupless::transfer::OpenFault>();
        send_and_sync::<protobuf_edit::intake::groupless::transfer::Fault>();
        send_and_sync::<protobuf_edit::intake::groupless::transfer::FaultKind>();
        send_and_sync::<protobuf_edit::intake::groupless::transfer::EditFault>();
        send_and_sync::<protobuf_edit::intake::groupless::transfer::FrameFault>();
        send_and_sync::<protobuf_edit::intake::groupless::transfer::SaveFault>();
        send_and_sync::<protobuf_edit::intake::groupless::transfer::Refusal>();
    }
}

/// The draft family is wholly positive: the machine owns a plain
/// `Vec<u8>` — no share counting, no interior mutability — so the
/// draft, its borrowed-payload sibling (shared `&[u8]` slots are
/// `Sync` pointees), its payload frames, and its whole vocabulary
/// are `Send + Sync`, the tolerant revisable editor's movable
/// identity (the session's `!Send` is its carrier's, not
/// revision's).
#[cfg(any(feature = "draft-grouped", feature = "draft-groupless"))]
#[test]
fn the_draft_family_is_send_and_sync() {
    send_and_sync::<protobuf_edit::draft::Handle>();
    #[cfg(feature = "draft-grouped")]
    {
        send_and_sync::<protobuf_edit::draft::grouped::Draft>();
        send_and_sync::<protobuf_edit::draft::grouped::BorrowDraft<'static>>();
        send_and_sync::<protobuf_edit::draft::grouped::MixDraft<'static>>();
        send_and_sync::<protobuf_edit::draft::grouped::MixPayloadFrame<'static, 'static>>();
        send_and_sync::<protobuf_edit::draft::grouped::MixSizedPayloadFrame<'static, 'static>>();
        send_and_sync::<protobuf_edit::draft::grouped::PayloadFrame<'static>>();
        send_and_sync::<protobuf_edit::draft::grouped::SizedPayloadFrame<'static>>();
        send_and_sync::<protobuf_edit::draft::grouped::EditStatus>();
        send_and_sync::<protobuf_edit::draft::grouped::InsertAt>();
        send_and_sync::<protobuf_edit::draft::grouped::OpenFault>();
        send_and_sync::<protobuf_edit::draft::grouped::Fault>();
        send_and_sync::<protobuf_edit::draft::grouped::FaultKind>();
        send_and_sync::<protobuf_edit::draft::grouped::EditFault>();
        send_and_sync::<protobuf_edit::draft::grouped::FrameFault>();
        send_and_sync::<protobuf_edit::draft::grouped::SaveFault>();
        send_and_sync::<protobuf_edit::draft::grouped::Children<'static>>();
        send_and_sync::<protobuf_edit::draft::grouped::Ancestors<'static>>();
        send_and_sync::<protobuf_edit::draft::grouped::Descent<'static>>();
        send_and_sync::<protobuf_edit::draft::grouped::RecordSpans>();
        send_and_sync::<protobuf_edit::draft::grouped::SaveSpans>();
    }
    #[cfg(feature = "draft-groupless")]
    {
        send_and_sync::<protobuf_edit::draft::groupless::Draft>();
        send_and_sync::<protobuf_edit::draft::groupless::BorrowDraft<'static>>();
        send_and_sync::<protobuf_edit::draft::groupless::MixDraft<'static>>();
        send_and_sync::<protobuf_edit::draft::groupless::MixPayloadFrame<'static, 'static>>();
        send_and_sync::<protobuf_edit::draft::groupless::MixSizedPayloadFrame<'static, 'static>>();
        send_and_sync::<protobuf_edit::draft::groupless::PayloadFrame<'static>>();
        send_and_sync::<protobuf_edit::draft::groupless::SizedPayloadFrame<'static>>();
        send_and_sync::<protobuf_edit::draft::groupless::EditStatus>();
        send_and_sync::<protobuf_edit::draft::groupless::InsertAt>();
        send_and_sync::<protobuf_edit::draft::groupless::OpenFault>();
        send_and_sync::<protobuf_edit::draft::groupless::Fault>();
        send_and_sync::<protobuf_edit::draft::groupless::FaultKind>();
        send_and_sync::<protobuf_edit::draft::groupless::EditFault>();
        send_and_sync::<protobuf_edit::draft::groupless::FrameFault>();
        send_and_sync::<protobuf_edit::draft::groupless::SaveFault>();
        send_and_sync::<protobuf_edit::draft::groupless::Refusal>();
        send_and_sync::<protobuf_edit::draft::groupless::Children<'static>>();
        send_and_sync::<protobuf_edit::draft::groupless::Ancestors<'static>>();
        send_and_sync::<protobuf_edit::draft::groupless::Descent<'static>>();
        send_and_sync::<protobuf_edit::draft::groupless::RecordSpans>();
        send_and_sync::<protobuf_edit::draft::groupless::SaveSpans>();
    }
    #[cfg(feature = "transfer-draft-grouped")]
    {
        send_and_sync::<protobuf_edit::draft::grouped::transfer::TransferDraft>();
        send_and_sync::<protobuf_edit::draft::grouped::transfer::TransferBorrowDraft<'static>>();
        send_and_sync::<protobuf_edit::draft::grouped::transfer::PayloadFrame<'static>>();
        send_and_sync::<protobuf_edit::draft::grouped::transfer::SizedPayloadFrame<'static>>();
        send_and_sync::<protobuf_edit::draft::grouped::transfer::EditStatus>();
        send_and_sync::<protobuf_edit::draft::grouped::transfer::PayloadTarget>();
        send_and_sync::<protobuf_edit::draft::grouped::transfer::OpenFault>();
        send_and_sync::<protobuf_edit::draft::grouped::transfer::Fault>();
        send_and_sync::<protobuf_edit::draft::grouped::transfer::FaultKind>();
        send_and_sync::<protobuf_edit::draft::grouped::transfer::EditFault>();
        send_and_sync::<protobuf_edit::draft::grouped::transfer::FrameFault>();
        send_and_sync::<protobuf_edit::draft::grouped::transfer::SaveFault>();
        send_and_sync::<protobuf_edit::draft::grouped::transfer::Children<'static>>();
        send_and_sync::<protobuf_edit::draft::grouped::transfer::Ancestors<'static>>();
        send_and_sync::<protobuf_edit::draft::grouped::transfer::Descent<'static>>();
        send_and_sync::<protobuf_edit::draft::grouped::transfer::RecordSpans>();
        send_and_sync::<protobuf_edit::draft::grouped::transfer::SaveSpans>();
    }
    #[cfg(feature = "transfer-draft-groupless")]
    {
        send_and_sync::<protobuf_edit::draft::groupless::transfer::TransferDraft>();
        send_and_sync::<protobuf_edit::draft::groupless::transfer::TransferBorrowDraft<'static>>();
        send_and_sync::<protobuf_edit::draft::groupless::transfer::PayloadFrame<'static>>();
        send_and_sync::<protobuf_edit::draft::groupless::transfer::SizedPayloadFrame<'static>>();
        send_and_sync::<protobuf_edit::draft::groupless::transfer::EditStatus>();
        send_and_sync::<protobuf_edit::draft::groupless::transfer::PayloadTarget>();
        send_and_sync::<protobuf_edit::draft::groupless::transfer::OpenFault>();
        send_and_sync::<protobuf_edit::draft::groupless::transfer::Fault>();
        send_and_sync::<protobuf_edit::draft::groupless::transfer::FaultKind>();
        send_and_sync::<protobuf_edit::draft::groupless::transfer::EditFault>();
        send_and_sync::<protobuf_edit::draft::groupless::transfer::FrameFault>();
        send_and_sync::<protobuf_edit::draft::groupless::transfer::SaveFault>();
        send_and_sync::<protobuf_edit::draft::groupless::transfer::Refusal>();
        send_and_sync::<protobuf_edit::draft::groupless::transfer::Children<'static>>();
        send_and_sync::<protobuf_edit::draft::groupless::transfer::Ancestors<'static>>();
        send_and_sync::<protobuf_edit::draft::groupless::transfer::Descent<'static>>();
        send_and_sync::<protobuf_edit::draft::groupless::transfer::RecordSpans>();
        send_and_sync::<protobuf_edit::draft::groupless::transfer::SaveSpans>();
    }
}

/// The session family's plain vocabulary stays `Send + Sync`; the
/// machine itself and its backing are deliberately not (the
/// `compile_fail` pins live on their docs).
#[cfg(any(feature = "session-grouped", feature = "session-groupless"))]
#[test]
fn the_session_vocabulary_is_send_and_sync_around_the_owned_core() {
    send_and_sync::<protobuf_edit::session::Handle>();
    send_and_sync::<protobuf_edit::session::LoadFault>();
    #[cfg(feature = "session-grouped")]
    {
        // The command vocabulary is declared once in the session's
        // private module and re-exported per dialect; each cfg block
        // pins the path its own feature makes visible.
        send_and_sync::<protobuf_edit::session::grouped::EditStatus>();
        send_and_sync::<protobuf_edit::session::grouped::InsertAt>();
        send_and_sync::<protobuf_edit::session::grouped::OpenFault>();
        send_and_sync::<protobuf_edit::session::grouped::Fault>();
        send_and_sync::<protobuf_edit::session::grouped::FaultKind>();
        send_and_sync::<protobuf_edit::session::grouped::EditFault>();
        send_and_sync::<protobuf_edit::session::grouped::FrameFault>();
        #[cfg(feature = "transfer-session-grouped")]
        send_and_sync::<protobuf_edit::session::grouped::transfer::FrameFault>();
        send_and_sync::<protobuf_edit::session::grouped::SaveFault>();
        send_and_sync::<protobuf_edit::session::grouped::Refusal>();
        // The views borrow the row table, not the shared carrier —
        // and the span table is plain data, like the saved bytes.
        send_and_sync::<protobuf_edit::session::grouped::Children<'static>>();
        send_and_sync::<protobuf_edit::session::grouped::Ancestors<'static>>();
        send_and_sync::<protobuf_edit::session::grouped::Descent<'static>>();
        send_and_sync::<protobuf_edit::session::grouped::RecordSpans>();
        send_and_sync::<protobuf_edit::session::grouped::SaveSpans>();
        // The priced typestate's fault vocabulary is plain data; the
        // wrapper itself (`session::grouped::PricedSession`) and its
        // frames (`session::grouped::PricedPayloadFrame`,
        // `session::grouped::PricedSizedPayloadFrame`) carry the
        // owned core and sit on the negative side with it.
        #[cfg(feature = "priced-session-grouped")]
        send_and_sync::<protobuf_edit::session::grouped::PriceFault>();
    }
    #[cfg(feature = "session-groupless")]
    {
        send_and_sync::<protobuf_edit::session::groupless::EditStatus>();
        send_and_sync::<protobuf_edit::session::groupless::InsertAt>();
        send_and_sync::<protobuf_edit::session::groupless::OpenFault>();
        send_and_sync::<protobuf_edit::session::groupless::Fault>();
        send_and_sync::<protobuf_edit::session::groupless::FaultKind>();
        send_and_sync::<protobuf_edit::session::groupless::EditFault>();
        send_and_sync::<protobuf_edit::session::groupless::FrameFault>();
        #[cfg(feature = "transfer-session-groupless")]
        send_and_sync::<protobuf_edit::session::groupless::transfer::FrameFault>();
        send_and_sync::<protobuf_edit::session::groupless::SaveFault>();
        send_and_sync::<protobuf_edit::session::groupless::Refusal>();
        // The views borrow the row table, not the shared carrier —
        // and the span table is plain data, like the saved bytes.
        send_and_sync::<protobuf_edit::session::groupless::Children<'static>>();
        send_and_sync::<protobuf_edit::session::groupless::Ancestors<'static>>();
        send_and_sync::<protobuf_edit::session::groupless::Descent<'static>>();
        send_and_sync::<protobuf_edit::session::groupless::RecordSpans>();
        send_and_sync::<protobuf_edit::session::groupless::SaveSpans>();
        // The priced typestate's fault vocabulary is plain data; the
        // wrapper itself (`session::groupless::PricedSession`) and its
        // frames (`session::groupless::PricedPayloadFrame`,
        // `session::groupless::PricedSizedPayloadFrame`) carry the
        // owned core and sit on the negative side with it.
        #[cfg(feature = "priced-session-groupless")]
        send_and_sync::<protobuf_edit::session::groupless::PriceFault>();
    }
    // The transfer twin's vocabulary is the same plain data; its
    // machines (`session::grouped::transfer::TransferSession`,
    // `TransferBorrowSession`, `PricedTransferSession`) and frames
    // carry the owned core and sit on the negative side with it.
    #[cfg(feature = "transfer-session-grouped")]
    {
        send_and_sync::<protobuf_edit::session::grouped::transfer::EditStatus>();
        send_and_sync::<protobuf_edit::session::grouped::transfer::PayloadTarget>();
        send_and_sync::<protobuf_edit::session::grouped::transfer::OpenFault>();
        send_and_sync::<protobuf_edit::session::grouped::transfer::Fault>();
        send_and_sync::<protobuf_edit::session::grouped::transfer::FaultKind>();
        send_and_sync::<protobuf_edit::session::grouped::transfer::EditFault>();
        send_and_sync::<protobuf_edit::session::grouped::transfer::SaveFault>();
        send_and_sync::<protobuf_edit::session::grouped::transfer::Refusal>();
        send_and_sync::<protobuf_edit::session::grouped::transfer::Children<'static>>();
        send_and_sync::<protobuf_edit::session::grouped::transfer::Ancestors<'static>>();
        send_and_sync::<protobuf_edit::session::grouped::transfer::Descent<'static>>();
        send_and_sync::<protobuf_edit::session::grouped::transfer::RecordSpans>();
        send_and_sync::<protobuf_edit::session::grouped::transfer::SaveSpans>();
        #[cfg(feature = "priced-transfer-session-grouped")]
        send_and_sync::<protobuf_edit::session::grouped::transfer::PriceFault>();
    }
    #[cfg(feature = "transfer-session-groupless")]
    {
        send_and_sync::<protobuf_edit::session::groupless::transfer::EditStatus>();
        send_and_sync::<protobuf_edit::session::groupless::transfer::PayloadTarget>();
        send_and_sync::<protobuf_edit::session::groupless::transfer::OpenFault>();
        send_and_sync::<protobuf_edit::session::groupless::transfer::Fault>();
        send_and_sync::<protobuf_edit::session::groupless::transfer::FaultKind>();
        send_and_sync::<protobuf_edit::session::groupless::transfer::EditFault>();
        send_and_sync::<protobuf_edit::session::groupless::transfer::SaveFault>();
        send_and_sync::<protobuf_edit::session::groupless::transfer::Refusal>();
        send_and_sync::<protobuf_edit::session::groupless::transfer::Children<'static>>();
        send_and_sync::<protobuf_edit::session::groupless::transfer::Ancestors<'static>>();
        send_and_sync::<protobuf_edit::session::groupless::transfer::Descent<'static>>();
        send_and_sync::<protobuf_edit::session::groupless::transfer::RecordSpans>();
        send_and_sync::<protobuf_edit::session::groupless::transfer::SaveSpans>();
        #[cfg(feature = "priced-transfer-session-groupless")]
        send_and_sync::<protobuf_edit::session::groupless::transfer::PriceFault>();
    }
}

#[cfg(any(feature = "rewire-grouped", feature = "rewire-groupless"))]
#[test]
fn the_rewire_family_is_send_and_sync() {
    send_and_sync::<protobuf_edit::rewire::Action<'static>>();
    send_and_sync::<protobuf_edit::rewire::Value<'static>>();
    send_and_sync::<protobuf_edit::rewire::ActionError>();
    #[cfg(feature = "rewire-grouped")]
    {
        send_and_sync::<protobuf_edit::rewire::grouped::Actions<'static>>();
        send_and_sync::<protobuf_edit::rewire::grouped::Fault>();
        send_and_sync::<protobuf_edit::rewire::grouped::WireBreach>();
        send_and_sync::<protobuf_edit::rewire::grouped::RuleFault>();
        send_and_sync::<protobuf_edit::rewire::grouped::RuleFaultKind>();
        send_and_sync::<protobuf_edit::rewire::grouped::Rewirer<'static>>();
    }
    #[cfg(feature = "rewire-groupless")]
    {
        send_and_sync::<protobuf_edit::rewire::groupless::Actions<'static>>();
        send_and_sync::<protobuf_edit::rewire::groupless::Fault>();
        send_and_sync::<protobuf_edit::rewire::groupless::WireBreach>();
        send_and_sync::<protobuf_edit::rewire::groupless::RuleFault>();
        send_and_sync::<protobuf_edit::rewire::groupless::RuleFaultKind>();
        send_and_sync::<protobuf_edit::rewire::groupless::Rewirer<'static>>();
    }
}

#[cfg(any(feature = "transcode-grouped", feature = "transcode-groupless"))]
#[test]
fn the_transcode_family_is_send_and_sync() {
    send_and_sync::<protobuf_edit::transcode::FreeScalar<u64>>();
    send_and_sync::<protobuf_edit::transcode::FreeLen<'static>>();
    send_and_sync::<protobuf_edit::transcode::LockedScalar<u64>>();
    send_and_sync::<protobuf_edit::transcode::LockedLen>();
    #[cfg(feature = "transcode-grouped")]
    {
        send_and_sync::<protobuf_edit::transcode::grouped::Transcoder>();
        send_and_sync::<protobuf_edit::transcode::grouped::Fault>();
        send_and_sync::<protobuf_edit::transcode::grouped::WireBreach>();
        send_and_sync::<protobuf_edit::transcode::grouped::RuleFault>();
        send_and_sync::<protobuf_edit::transcode::grouped::RuleFaultKind>();
        send_and_sync::<protobuf_edit::transcode::grouped::FreeGroup>();
    }
    #[cfg(feature = "transcode-groupless")]
    {
        send_and_sync::<protobuf_edit::transcode::groupless::Transcoder>();
        send_and_sync::<protobuf_edit::transcode::groupless::Fault>();
        send_and_sync::<protobuf_edit::transcode::groupless::WireBreach>();
        send_and_sync::<protobuf_edit::transcode::groupless::RuleFault>();
        send_and_sync::<protobuf_edit::transcode::groupless::RuleFaultKind>();
    }
}

#[cfg(any(feature = "replay-rewrite-grouped", feature = "replay-rewrite-groupless"))]
#[test]
fn the_replay_rewrite_family_is_send_and_sync() {
    send_and_sync::<protobuf_edit::replay_rewrite::Action<'static>>();
    send_and_sync::<protobuf_edit::replay_rewrite::Value<'static>>();
    send_and_sync::<protobuf_edit::replay_rewrite::Rule<'static>>();
    send_and_sync::<protobuf_edit::replay_rewrite::RuleError>();
    send_and_sync::<protobuf_edit::replay_rewrite::RuleSet<'static>>();
    send_and_sync::<protobuf_edit::replay_rewrite::Stats>();
    #[cfg(feature = "replay-rewrite-grouped")]
    {
        send_and_sync::<protobuf_edit::replay_rewrite::grouped::Fault>();
        send_and_sync::<protobuf_edit::replay_rewrite::grouped::FaultKind>();
        send_and_sync::<protobuf_edit::replay_rewrite::grouped::WireBreach>();
        send_and_sync::<
            protobuf_edit::replay_rewrite::grouped::JobFault<
                protobuf_edit::replay_source::SliceFault,
            >,
        >();
    }
    #[cfg(feature = "replay-rewrite-groupless")]
    {
        send_and_sync::<protobuf_edit::replay_rewrite::groupless::Fault>();
        send_and_sync::<protobuf_edit::replay_rewrite::groupless::FaultKind>();
        send_and_sync::<protobuf_edit::replay_rewrite::groupless::WireBreach>();
        send_and_sync::<
            protobuf_edit::replay_rewrite::groupless::JobFault<
                protobuf_edit::replay_source::SliceFault,
            >,
        >();
    }
}

#[cfg(any(feature = "replay-convert-grouped", feature = "replay-convert-groupless"))]
#[test]
fn the_replay_convert_family_is_send_and_sync() {
    #[cfg(feature = "replay-convert-grouped")]
    {
        send_and_sync::<protobuf_edit::replay_convert::grouped::Stats>();
        send_and_sync::<protobuf_edit::replay_convert::grouped::Fault>();
        send_and_sync::<protobuf_edit::replay_convert::grouped::FaultKind>();
        send_and_sync::<protobuf_edit::replay_convert::grouped::WireBreach>();
        send_and_sync::<
            protobuf_edit::replay_convert::grouped::JobFault<
                protobuf_edit::replay_source::SliceFault,
            >,
        >();
    }
    #[cfg(feature = "replay-convert-groupless")]
    {
        send_and_sync::<protobuf_edit::replay_convert::groupless::Stats>();
        send_and_sync::<protobuf_edit::replay_convert::groupless::Fault>();
        send_and_sync::<protobuf_edit::replay_convert::groupless::FaultKind>();
        send_and_sync::<protobuf_edit::replay_convert::groupless::WireBreach>();
        send_and_sync::<
            protobuf_edit::replay_convert::groupless::JobFault<
                protobuf_edit::replay_source::SliceFault,
            >,
        >();
    }
}

#[cfg(any(feature = "replay-splice-grouped", feature = "replay-splice-groupless"))]
#[test]
fn the_replay_splice_family_is_send_and_sync() {
    send_and_sync::<protobuf_edit::replay_splice::Scalar<'static, u64>>();
    send_and_sync::<protobuf_edit::replay_splice::Head<'static>>();
    send_and_sync::<protobuf_edit::replay_splice::Close<'static>>();
    #[cfg(feature = "replay-splice-grouped")]
    {
        send_and_sync::<protobuf_edit::replay_splice::grouped::Group<'static>>();
        send_and_sync::<protobuf_edit::replay_splice::grouped::Fault>();
        send_and_sync::<protobuf_edit::replay_splice::grouped::FaultKind>();
        send_and_sync::<protobuf_edit::replay_splice::grouped::WireBreach>();
        send_and_sync::<
            protobuf_edit::replay_splice::grouped::JobFault<
                protobuf_edit::replay_source::SliceFault,
            >,
        >();
    }
    #[cfg(feature = "replay-splice-groupless")]
    {
        send_and_sync::<protobuf_edit::replay_splice::groupless::Fault>();
        send_and_sync::<protobuf_edit::replay_splice::groupless::FaultKind>();
        send_and_sync::<protobuf_edit::replay_splice::groupless::WireBreach>();
        send_and_sync::<
            protobuf_edit::replay_splice::groupless::JobFault<
                protobuf_edit::replay_source::SliceFault,
            >,
        >();
    }
}

/// The one-shot replay editor crosses threads mid-edit: rows,
/// authored stores (borrowed payload slots are `&[u8]`), and the
/// source handle — no share counter, no interior mutability — so
/// its standing, like the survey product's, is the source's own.
#[cfg(any(feature = "overhaul-grouped", feature = "overhaul-groupless"))]
#[test]
fn the_overhaul_family_is_send_and_sync() {
    send_and_sync::<protobuf_edit::overhaul::Handle>();
    send_and_sync::<protobuf_edit::overhaul::EditStatus>();
    send_and_sync::<protobuf_edit::overhaul::InsertAt>();
    send_and_sync::<protobuf_edit::overhaul::SaveFault<protobuf_edit::replay_source::SliceFault>>();
    #[cfg(feature = "overhaul-grouped")]
    {
        send_and_sync::<
            protobuf_edit::overhaul::grouped::Overhaul<
                'static,
                protobuf_edit::replay_source::SliceSource<'static>,
            >,
        >();
        send_and_sync::<
            protobuf_edit::overhaul::grouped::BorrowOverhaul<
                'static,
                protobuf_edit::replay_source::SliceSource<'static>,
            >,
        >();
        send_and_sync::<
            protobuf_edit::overhaul::grouped::CopyOverhaul<
                protobuf_edit::replay_source::SliceSource<'static>,
            >,
        >();
        send_and_sync::<protobuf_edit::overhaul::grouped::Children<'static>>();
        send_and_sync::<protobuf_edit::overhaul::grouped::Descent<'static>>();
        send_and_sync::<protobuf_edit::overhaul::grouped::RecordSpans>();
        send_and_sync::<protobuf_edit::overhaul::grouped::ReadFault>();
        send_and_sync::<protobuf_edit::overhaul::grouped::Fault>();
        send_and_sync::<protobuf_edit::overhaul::grouped::FaultKind>();
        send_and_sync::<protobuf_edit::overhaul::grouped::EditFault>();
        send_and_sync::<
            protobuf_edit::overhaul::grouped::OpenFault<protobuf_edit::replay_source::SliceFault>,
        >();
        send_and_sync::<
            protobuf_edit::overhaul::grouped::DescendFault<
                protobuf_edit::replay_source::SliceFault,
            >,
        >();
        send_and_sync::<
            protobuf_edit::overhaul::grouped::FetchFault<protobuf_edit::replay_source::SliceFault>,
        >();
    }
    #[cfg(feature = "overhaul-groupless")]
    {
        send_and_sync::<
            protobuf_edit::overhaul::groupless::Overhaul<
                'static,
                protobuf_edit::replay_source::SliceSource<'static>,
            >,
        >();
        send_and_sync::<
            protobuf_edit::overhaul::groupless::BorrowOverhaul<
                'static,
                protobuf_edit::replay_source::SliceSource<'static>,
            >,
        >();
        send_and_sync::<
            protobuf_edit::overhaul::groupless::CopyOverhaul<
                protobuf_edit::replay_source::SliceSource<'static>,
            >,
        >();
        send_and_sync::<protobuf_edit::overhaul::groupless::Children<'static>>();
        send_and_sync::<protobuf_edit::overhaul::groupless::Descent<'static>>();
        send_and_sync::<protobuf_edit::overhaul::groupless::RecordSpans>();
        send_and_sync::<protobuf_edit::overhaul::groupless::ReadFault>();
        send_and_sync::<protobuf_edit::overhaul::groupless::Fault>();
        send_and_sync::<protobuf_edit::overhaul::groupless::FaultKind>();
        send_and_sync::<protobuf_edit::overhaul::groupless::EditFault>();
        send_and_sync::<
            protobuf_edit::overhaul::groupless::OpenFault<protobuf_edit::replay_source::SliceFault>,
        >();
        send_and_sync::<
            protobuf_edit::overhaul::groupless::DescendFault<
                protobuf_edit::replay_source::SliceFault,
            >,
        >();
        send_and_sync::<
            protobuf_edit::overhaul::groupless::FetchFault<
                protobuf_edit::replay_source::SliceFault,
            >,
        >();
    }
}

/// The revisable replay editor crosses threads mid-edit: rows,
/// layers, the revision log, authored stores (borrowed payload
/// slots are `&[u8]`), and the source handle — no share counter,
/// no interior mutability — so every form's standing is the
/// source's (and, for the borrowed and mixed forms, the payload
/// borrows') own.
#[cfg(any(feature = "maintain-grouped", feature = "maintain-groupless"))]
#[test]
fn the_maintain_family_is_send_and_sync() {
    send_and_sync::<protobuf_edit::maintain::Handle>();
    send_and_sync::<protobuf_edit::maintain::EditStatus>();
    send_and_sync::<protobuf_edit::maintain::InsertAt>();
    #[cfg(feature = "maintain-grouped")]
    {
        type Slice = protobuf_edit::replay_source::SliceSource<'static>;
        send_and_sync::<protobuf_edit::maintain::grouped::Maintain<Slice>>();
        send_and_sync::<protobuf_edit::maintain::grouped::BorrowMaintain<'static, Slice>>();
        send_and_sync::<protobuf_edit::maintain::grouped::MixMaintain<'static, Slice>>();
        send_and_sync::<protobuf_edit::maintain::grouped::Children<'static>>();
        send_and_sync::<protobuf_edit::maintain::grouped::Ancestors<'static>>();
        send_and_sync::<protobuf_edit::maintain::grouped::Descent<'static>>();
        send_and_sync::<protobuf_edit::maintain::grouped::RecordSpans>();
        send_and_sync::<protobuf_edit::maintain::grouped::SaveSpans>();
        send_and_sync::<protobuf_edit::maintain::grouped::ReadFault>();
        send_and_sync::<protobuf_edit::maintain::grouped::Fault>();
        send_and_sync::<protobuf_edit::maintain::grouped::FaultKind>();
        send_and_sync::<protobuf_edit::maintain::grouped::EditFault>();
        send_and_sync::<protobuf_edit::maintain::grouped::FrameFault>();
        send_and_sync::<
            protobuf_edit::maintain::grouped::OpenFault<protobuf_edit::replay_source::SliceFault>,
        >();
        send_and_sync::<
            protobuf_edit::maintain::grouped::DescendFault<
                protobuf_edit::replay_source::SliceFault,
            >,
        >();
        send_and_sync::<
            protobuf_edit::maintain::grouped::FetchFault<protobuf_edit::replay_source::SliceFault>,
        >();
        send_and_sync::<
            protobuf_edit::maintain::grouped::SaveFault<protobuf_edit::replay_source::SliceFault>,
        >();
        send_and_sync::<protobuf_edit::maintain::grouped::PayloadFrame<'static, Slice>>();
        send_and_sync::<protobuf_edit::maintain::grouped::SizedPayloadFrame<'static, Slice>>();
        send_and_sync::<protobuf_edit::maintain::grouped::MixPayloadFrame<'static, 'static, Slice>>(
        );
        send_and_sync::<
            protobuf_edit::maintain::grouped::MixSizedPayloadFrame<'static, 'static, Slice>,
        >();
    }
    #[cfg(feature = "maintain-groupless")]
    {
        type Slice = protobuf_edit::replay_source::SliceSource<'static>;
        send_and_sync::<protobuf_edit::maintain::groupless::Maintain<Slice>>();
        send_and_sync::<protobuf_edit::maintain::groupless::BorrowMaintain<'static, Slice>>();
        send_and_sync::<protobuf_edit::maintain::groupless::MixMaintain<'static, Slice>>();
        send_and_sync::<protobuf_edit::maintain::groupless::Children<'static>>();
        send_and_sync::<protobuf_edit::maintain::groupless::Ancestors<'static>>();
        send_and_sync::<protobuf_edit::maintain::groupless::Descent<'static>>();
        send_and_sync::<protobuf_edit::maintain::groupless::RecordSpans>();
        send_and_sync::<protobuf_edit::maintain::groupless::SaveSpans>();
        send_and_sync::<protobuf_edit::maintain::groupless::ReadFault>();
        send_and_sync::<protobuf_edit::maintain::groupless::Fault>();
        send_and_sync::<protobuf_edit::maintain::groupless::FaultKind>();
        send_and_sync::<protobuf_edit::maintain::groupless::EditFault>();
        send_and_sync::<protobuf_edit::maintain::groupless::FrameFault>();
        send_and_sync::<
            protobuf_edit::maintain::groupless::OpenFault<protobuf_edit::replay_source::SliceFault>,
        >();
        send_and_sync::<
            protobuf_edit::maintain::groupless::DescendFault<
                protobuf_edit::replay_source::SliceFault,
            >,
        >();
        send_and_sync::<
            protobuf_edit::maintain::groupless::FetchFault<
                protobuf_edit::replay_source::SliceFault,
            >,
        >();
        send_and_sync::<
            protobuf_edit::maintain::groupless::SaveFault<protobuf_edit::replay_source::SliceFault>,
        >();
        send_and_sync::<protobuf_edit::maintain::groupless::PayloadFrame<'static, Slice>>();
        send_and_sync::<protobuf_edit::maintain::groupless::SizedPayloadFrame<'static, Slice>>();
        send_and_sync::<protobuf_edit::maintain::groupless::MixPayloadFrame<'static, 'static, Slice>>(
        );
        send_and_sync::<
            protobuf_edit::maintain::groupless::MixSizedPayloadFrame<'static, 'static, Slice>,
        >();
    }
}

/// The canonical one-shot replay editor crosses threads mid-edit
/// exactly like its tolerant twin: rows, authored stores
/// (borrowed payload slots are `&[u8]`), and the source handle —
/// so every form's standing is the source's (and the payload
/// borrows') own.
#[cfg(any(feature = "refit-grouped", feature = "refit-groupless"))]
#[test]
fn the_refit_family_is_send_and_sync() {
    send_and_sync::<protobuf_edit::refit::Handle>();
    send_and_sync::<protobuf_edit::refit::EditStatus>();
    send_and_sync::<protobuf_edit::refit::InsertAt>();
    send_and_sync::<protobuf_edit::refit::SaveFault<protobuf_edit::replay_source::SliceFault>>();
    #[cfg(feature = "refit-grouped")]
    {
        type Slice = protobuf_edit::replay_source::SliceSource<'static>;
        send_and_sync::<protobuf_edit::refit::grouped::Refit<'static, Slice>>();
        send_and_sync::<protobuf_edit::refit::grouped::BorrowRefit<'static, Slice>>();
        send_and_sync::<protobuf_edit::refit::grouped::CopyRefit<Slice>>();
        send_and_sync::<protobuf_edit::refit::grouped::Children<'static>>();
        send_and_sync::<protobuf_edit::refit::grouped::Descent<'static>>();
        send_and_sync::<protobuf_edit::refit::grouped::RecordSpans>();
        send_and_sync::<protobuf_edit::refit::grouped::SaveSpans>();
        send_and_sync::<protobuf_edit::refit::grouped::ReadFault>();
        send_and_sync::<protobuf_edit::refit::grouped::Fault>();
        send_and_sync::<protobuf_edit::refit::grouped::FaultKind>();
        send_and_sync::<protobuf_edit::refit::grouped::EditFault>();
        send_and_sync::<protobuf_edit::refit::grouped::FrameFault>();
        send_and_sync::<
            protobuf_edit::refit::grouped::OpenFault<protobuf_edit::replay_source::SliceFault>,
        >();
        send_and_sync::<
            protobuf_edit::refit::grouped::DescendFault<protobuf_edit::replay_source::SliceFault>,
        >();
        send_and_sync::<
            protobuf_edit::refit::grouped::FetchFault<protobuf_edit::replay_source::SliceFault>,
        >();
        send_and_sync::<protobuf_edit::refit::grouped::PayloadWrite<'static, 'static, Slice>>();
        send_and_sync::<protobuf_edit::refit::grouped::SizedPayloadWrite<'static, 'static, Slice>>(
        );
        send_and_sync::<protobuf_edit::refit::grouped::CopyPayloadWrite<'static, Slice>>();
        send_and_sync::<protobuf_edit::refit::grouped::SizedCopyPayloadWrite<'static, Slice>>();
    }
    #[cfg(feature = "refit-groupless")]
    {
        type Slice = protobuf_edit::replay_source::SliceSource<'static>;
        send_and_sync::<protobuf_edit::refit::groupless::Refit<'static, Slice>>();
        send_and_sync::<protobuf_edit::refit::groupless::BorrowRefit<'static, Slice>>();
        send_and_sync::<protobuf_edit::refit::groupless::CopyRefit<Slice>>();
        send_and_sync::<protobuf_edit::refit::groupless::Children<'static>>();
        send_and_sync::<protobuf_edit::refit::groupless::Descent<'static>>();
        send_and_sync::<protobuf_edit::refit::groupless::RecordSpans>();
        send_and_sync::<protobuf_edit::refit::groupless::SaveSpans>();
        send_and_sync::<protobuf_edit::refit::groupless::ReadFault>();
        send_and_sync::<protobuf_edit::refit::groupless::Fault>();
        send_and_sync::<protobuf_edit::refit::groupless::FaultKind>();
        send_and_sync::<protobuf_edit::refit::groupless::EditFault>();
        send_and_sync::<protobuf_edit::refit::groupless::FrameFault>();
        send_and_sync::<
            protobuf_edit::refit::groupless::OpenFault<protobuf_edit::replay_source::SliceFault>,
        >();
        send_and_sync::<
            protobuf_edit::refit::groupless::DescendFault<protobuf_edit::replay_source::SliceFault>,
        >();
        send_and_sync::<
            protobuf_edit::refit::groupless::FetchFault<protobuf_edit::replay_source::SliceFault>,
        >();
        send_and_sync::<protobuf_edit::refit::groupless::PayloadWrite<'static, 'static, Slice>>();
        send_and_sync::<protobuf_edit::refit::groupless::SizedPayloadWrite<'static, 'static, Slice>>(
        );
        send_and_sync::<protobuf_edit::refit::groupless::CopyPayloadWrite<'static, Slice>>();
        send_and_sync::<protobuf_edit::refit::groupless::SizedCopyPayloadWrite<'static, Slice>>();
    }
}

/// The canonical revisable replay editor crosses threads mid-edit
/// exactly like its tolerant twin: rows, layers, the revision
/// log, authored stores (borrowed payload slots are `&[u8]`), and
/// the source handle — so every form's standing is the source's
/// (and, for the borrowed and mixed forms, the payload borrows')
/// own.
#[cfg(any(feature = "commission-grouped", feature = "commission-groupless"))]
#[test]
fn the_commission_family_is_send_and_sync() {
    send_and_sync::<protobuf_edit::commission::Handle>();
    send_and_sync::<protobuf_edit::commission::EditStatus>();
    send_and_sync::<protobuf_edit::commission::InsertAt>();
    #[cfg(feature = "commission-grouped")]
    {
        type Slice = protobuf_edit::replay_source::SliceSource<'static>;
        send_and_sync::<protobuf_edit::commission::grouped::Commission<Slice>>();
        send_and_sync::<protobuf_edit::commission::grouped::BorrowCommission<'static, Slice>>();
        send_and_sync::<protobuf_edit::commission::grouped::MixCommission<'static, Slice>>();
        send_and_sync::<protobuf_edit::commission::grouped::Children<'static>>();
        send_and_sync::<protobuf_edit::commission::grouped::Ancestors<'static>>();
        send_and_sync::<protobuf_edit::commission::grouped::Descent<'static>>();
        send_and_sync::<protobuf_edit::commission::grouped::RecordSpans>();
        send_and_sync::<protobuf_edit::commission::grouped::SaveSpans>();
        send_and_sync::<protobuf_edit::commission::grouped::ReadFault>();
        send_and_sync::<protobuf_edit::commission::grouped::Fault>();
        send_and_sync::<protobuf_edit::commission::grouped::FaultKind>();
        send_and_sync::<protobuf_edit::commission::grouped::EditFault>();
        send_and_sync::<protobuf_edit::commission::grouped::FrameFault>();
        send_and_sync::<
            protobuf_edit::commission::grouped::OpenFault<protobuf_edit::replay_source::SliceFault>,
        >();
        send_and_sync::<
            protobuf_edit::commission::grouped::DescendFault<
                protobuf_edit::replay_source::SliceFault,
            >,
        >();
        send_and_sync::<
            protobuf_edit::commission::grouped::FetchFault<
                protobuf_edit::replay_source::SliceFault,
            >,
        >();
        send_and_sync::<
            protobuf_edit::commission::grouped::SaveFault<protobuf_edit::replay_source::SliceFault>,
        >();
        send_and_sync::<protobuf_edit::commission::grouped::PayloadFrame<'static, Slice>>();
        send_and_sync::<protobuf_edit::commission::grouped::SizedPayloadFrame<'static, Slice>>();
        send_and_sync::<protobuf_edit::commission::grouped::MixPayloadFrame<'static, 'static, Slice>>(
        );
        send_and_sync::<
            protobuf_edit::commission::grouped::MixSizedPayloadFrame<'static, 'static, Slice>,
        >();
    }
    #[cfg(feature = "commission-groupless")]
    {
        type Slice = protobuf_edit::replay_source::SliceSource<'static>;
        send_and_sync::<protobuf_edit::commission::groupless::Commission<Slice>>();
        send_and_sync::<protobuf_edit::commission::groupless::BorrowCommission<'static, Slice>>();
        send_and_sync::<protobuf_edit::commission::groupless::MixCommission<'static, Slice>>();
        send_and_sync::<protobuf_edit::commission::groupless::Children<'static>>();
        send_and_sync::<protobuf_edit::commission::groupless::Ancestors<'static>>();
        send_and_sync::<protobuf_edit::commission::groupless::Descent<'static>>();
        send_and_sync::<protobuf_edit::commission::groupless::RecordSpans>();
        send_and_sync::<protobuf_edit::commission::groupless::SaveSpans>();
        send_and_sync::<protobuf_edit::commission::groupless::ReadFault>();
        send_and_sync::<protobuf_edit::commission::groupless::Fault>();
        send_and_sync::<protobuf_edit::commission::groupless::FaultKind>();
        send_and_sync::<protobuf_edit::commission::groupless::EditFault>();
        send_and_sync::<protobuf_edit::commission::groupless::FrameFault>();
        send_and_sync::<
            protobuf_edit::commission::groupless::OpenFault<
                protobuf_edit::replay_source::SliceFault,
            >,
        >();
        send_and_sync::<
            protobuf_edit::commission::groupless::DescendFault<
                protobuf_edit::replay_source::SliceFault,
            >,
        >();
        send_and_sync::<
            protobuf_edit::commission::groupless::FetchFault<
                protobuf_edit::replay_source::SliceFault,
            >,
        >();
        send_and_sync::<
            protobuf_edit::commission::groupless::SaveFault<
                protobuf_edit::replay_source::SliceFault,
            >,
        >();
        send_and_sync::<protobuf_edit::commission::groupless::PayloadFrame<'static, Slice>>();
        send_and_sync::<protobuf_edit::commission::groupless::SizedPayloadFrame<'static, Slice>>();
        send_and_sync::<
            protobuf_edit::commission::groupless::MixPayloadFrame<'static, 'static, Slice>,
        >();
        send_and_sync::<
            protobuf_edit::commission::groupless::MixSizedPayloadFrame<'static, 'static, Slice>,
        >();
    }
}

#[cfg(any(feature = "construct-grouped", feature = "construct-groupless"))]
#[test]
fn the_construct_family_is_send_and_sync() {
    send_and_sync::<protobuf_edit::construct::OverCap>();
    send_and_sync::<protobuf_edit::construct::Bytes<'static, 'static>>();
    send_and_sync::<protobuf_edit::construct::CopyBytes<'static>>();
    #[cfg(feature = "construct-grouped")]
    {
        send_and_sync::<protobuf_edit::construct::grouped::Builder<'static>>();
        send_and_sync::<protobuf_edit::construct::grouped::BodyBuilder<'static, 'static>>();
        send_and_sync::<protobuf_edit::construct::grouped::CopyBuilder>();
        send_and_sync::<protobuf_edit::construct::grouped::CopyBodyBuilder<'static>>();
    }
    #[cfg(feature = "construct-groupless")]
    {
        send_and_sync::<protobuf_edit::construct::groupless::Builder<'static>>();
        send_and_sync::<protobuf_edit::construct::groupless::BodyBuilder<'static, 'static>>();
        send_and_sync::<protobuf_edit::construct::groupless::CopyBuilder>();
        send_and_sync::<protobuf_edit::construct::groupless::CopyBodyBuilder<'static>>();
    }
}

#[cfg(any(feature = "transfer-rewrite-grouped", feature = "transfer-rewrite-groupless"))]
#[test]
fn the_rewrite_transfer_vocabulary_is_send_and_sync() {
    send_and_sync::<protobuf_edit::rewrite::transfer::Claim>();
    send_and_sync::<protobuf_edit::rewrite::transfer::CopyPairing>();
    send_and_sync::<protobuf_edit::rewrite::transfer::PathBreach>();
    send_and_sync::<protobuf_edit::rewrite::transfer::PathRole>();
    send_and_sync::<protobuf_edit::rewrite::transfer::PayloadCopyRule<'static>>();
    send_and_sync::<protobuf_edit::rewrite::transfer::PayloadCopyTarget<'static>>();
    send_and_sync::<protobuf_edit::rewrite::transfer::PayloadMoveRule<'static>>();
    send_and_sync::<protobuf_edit::rewrite::transfer::RecordTransfer>();
    send_and_sync::<protobuf_edit::rewrite::transfer::RecordTransferRule<'static>>();
    send_and_sync::<protobuf_edit::rewrite::transfer::TransferBreach>();
    send_and_sync::<protobuf_edit::rewrite::transfer::TransferRuleError>();
    send_and_sync::<protobuf_edit::rewrite::transfer::TransferRuleSet<'static>>();
    send_and_sync::<protobuf_edit::rewrite::transfer::TransferStats>();
    send_and_sync::<protobuf_edit::rewrite::transfer::TransferTable>();
}

#[cfg(feature = "transfer-rewrite-grouped")]
#[test]
fn the_grouped_rewrite_transfer_faults_are_send_and_sync() {
    send_and_sync::<protobuf_edit::rewrite::grouped::transfer::TransferFault>();
    send_and_sync::<protobuf_edit::rewrite::grouped::transfer::TransferFaultKind>();
}

#[cfg(feature = "transfer-rewrite-groupless")]
#[test]
fn the_groupless_rewrite_transfer_faults_are_send_and_sync() {
    send_and_sync::<protobuf_edit::rewrite::groupless::transfer::TransferFault>();
    send_and_sync::<protobuf_edit::rewrite::groupless::transfer::TransferFaultKind>();
}

#[cfg(any(feature = "transfer-splice-grouped", feature = "transfer-splice-groupless"))]
#[test]
fn the_splice_transfer_vocabulary_is_send_and_sync() {
    send_and_sync::<protobuf_edit::splice::transfer::OnlineGap>();
    send_and_sync::<protobuf_edit::splice::transfer::SourceLen<'static>>();
    send_and_sync::<protobuf_edit::splice::transfer::SourceScalar<'static, u64>>();
}

#[cfg(feature = "transfer-splice-grouped")]
#[test]
fn the_grouped_splice_transfer_vocabulary_is_send_and_sync() {
    send_and_sync::<protobuf_edit::splice::grouped::transfer::SourceGroup<'static>>();
    send_and_sync::<protobuf_edit::splice::grouped::transfer::TransferFault>();
    send_and_sync::<protobuf_edit::splice::grouped::transfer::TransferFaultKind>();
}

#[cfg(feature = "transfer-splice-groupless")]
#[test]
fn the_groupless_splice_transfer_faults_are_send_and_sync() {
    send_and_sync::<protobuf_edit::splice::groupless::transfer::TransferFault>();
    send_and_sync::<protobuf_edit::splice::groupless::transfer::TransferFaultKind>();
}
