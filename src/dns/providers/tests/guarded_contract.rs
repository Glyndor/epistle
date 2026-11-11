//! What a provider that writes by id must do under a precondition, the same
//! cases for every one of them (see [`crate::dns::providers::guarded`]).
//!
//! A provider's test module supplies a [`Rig`], its mock zone with the
//! requests it saw written, and [`guarded_contract!`] runs every case
//! against it. The zone holds A records at `mail.example.org`.

use crate::dns::provider::{DnsProvider, DnsRecord, RecordKind};
use crate::dns::publish::provider::{Change, Guard, Precondition, Receipt};

/// A mock zone of one provider.
pub(crate) trait Rig: Sized {
	/// A provider over a zone that holds these `(id, address)` records.
	async fn start(records: &[(&str, &str)]) -> Self;
	/// The provider under test.
	fn provider(&self) -> &dyn DnsProvider;
	/// What the zone holds now, as another account may have left it.
	fn set(&self, records: &[(&str, &str)]);
	/// The writes the provider received, in order: `create`, `update <id>`
	/// or `delete <id>`.
	fn writes(&self) -> Vec<String>;
	/// The address each write carried, in order.
	fn written_addresses(&self) -> Vec<String>;
}

const ZONE: &str = "example.org";
const NAME: &str = "mail.example.org";

pub(crate) fn a(value: &str) -> DnsRecord {
	DnsRecord::new(NAME, RecordKind::A, value, 300)
}

/// A change at the name, planned against what the provider lists now. `plan`
/// builds the set to write from the records listed, which carry over exactly
/// as they were read.
async fn change(rig: &impl Rig, plan: impl FnOnce(&[DnsRecord]) -> Vec<DnsRecord>) -> Change {
	let snapshot = rig.provider().publish_snapshot(ZONE).await.unwrap();
	// The set at the name and type, which is all a change carries.
	let before: Vec<_> = snapshot
		.records
		.into_iter()
		.filter(|o| o.record.name == NAME && o.record.kind == RecordKind::A)
		.collect();
	let listed: Vec<DnsRecord> = before.iter().map(|o| o.record.clone()).collect();
	Change {
		name: NAME.into(),
		kind: RecordKind::A,
		before,
		after: plan(&listed),
		precondition: Precondition::Identity,
		operation_id: "epistle-publish-test".into(),
	}
}

fn applied(receipt: &Receipt) -> bool {
	matches!(receipt, Receipt::Applied { .. })
}

pub(crate) async fn snapshot_carries_ids_and_says_it_checks<R: Rig>() {
	let rig = R::start(&[("101", "203.0.113.10")]).await;
	let snapshot = rig.provider().publish_snapshot(ZONE).await.unwrap();
	assert_eq!(snapshot.guard, Guard::Checked);
	assert_eq!(snapshot.revision, None);
	let own = snapshot
		.records
		.iter()
		.find(|o| o.identity.as_deref() == Some("101"))
		.expect("the record is listed with its id");
	assert_eq!(own.record, a("203.0.113.10"));
}

pub(crate) async fn record_added_after_the_listing_stops_the_write<R: Rig>() {
	let rig = R::start(&[("101", "203.0.113.10")]).await;
	let change = change(&rig, |_| vec![a("203.0.113.11")]).await;
	rig.set(&[("101", "203.0.113.10"), ("999", "203.0.113.99")]);
	let receipt = rig.provider().apply_guarded(ZONE, change).await;
	assert_eq!(receipt, Receipt::PreconditionFailed);
	assert_eq!(rig.writes(), Vec::<String>::new());
}

pub(crate) async fn record_replaced_after_the_listing_stops_the_write<R: Rig>() {
	let rig = R::start(&[("101", "203.0.113.10")]).await;
	let change = change(&rig, |_| vec![a("203.0.113.11")]).await;
	// The same id now holds another value.
	rig.set(&[("101", "203.0.113.50")]);
	let receipt = rig.provider().apply_guarded(ZONE, change).await;
	assert_eq!(receipt, Receipt::PreconditionFailed);
	assert_eq!(rig.writes(), Vec::<String>::new());
}

pub(crate) async fn record_swapped_for_another_id_stops_the_write<R: Rig>() {
	let rig = R::start(&[("101", "203.0.113.10")]).await;
	let change = change(&rig, |_| vec![a("203.0.113.11")]).await;
	// Same value, but somebody deleted ours and created theirs.
	rig.set(&[("999", "203.0.113.10")]);
	let receipt = rig.provider().apply_guarded(ZONE, change).await;
	assert_eq!(receipt, Receipt::PreconditionFailed);
	assert_eq!(rig.writes(), Vec::<String>::new());
}

pub(crate) async fn record_removed_after_the_listing_stops_the_write<R: Rig>() {
	let rig = R::start(&[("100", "203.0.113.20"), ("101", "203.0.113.10")]).await;
	let change = change(&rig, |held| vec![held[0].clone(), a("203.0.113.11")]).await;
	rig.set(&[("100", "203.0.113.20")]);
	let receipt = rig.provider().apply_guarded(ZONE, change).await;
	assert_eq!(receipt, Receipt::PreconditionFailed);
	assert_eq!(rig.writes(), Vec::<String>::new());
}

pub(crate) async fn update_touches_only_the_record_that_changes<R: Rig>() {
	let rig = R::start(&[("100", "203.0.113.20"), ("101", "203.0.113.10")]).await;
	let change = change(&rig, |held| vec![held[0].clone(), a("203.0.113.11")]).await;
	let receipt = rig.provider().apply_guarded(ZONE, change).await;
	assert!(applied(&receipt), "{receipt:?}");
	assert_eq!(rig.writes(), vec!["update 101"]);
	assert_eq!(rig.written_addresses(), vec!["203.0.113.11"]);
}

pub(crate) async fn new_record_is_created_and_nothing_else_is_written<R: Rig>() {
	let rig = R::start(&[("100", "203.0.113.20")]).await;
	let change = change(&rig, |held| vec![held[0].clone(), a("203.0.113.11")]).await;
	let receipt = rig.provider().apply_guarded(ZONE, change).await;
	assert!(applied(&receipt), "{receipt:?}");
	assert_eq!(rig.writes(), vec!["create"]);
	assert_eq!(rig.written_addresses(), vec!["203.0.113.11"]);
}

pub(crate) async fn removal_deletes_only_its_own_id<R: Rig>() {
	let rig = R::start(&[("100", "203.0.113.20"), ("101", "203.0.113.10")]).await;
	let change = change(&rig, |held| vec![held[0].clone()]).await;
	let receipt = rig.provider().apply_guarded(ZONE, change).await;
	assert!(applied(&receipt), "{receipt:?}");
	assert_eq!(rig.writes(), vec!["delete 101"]);
}

pub(crate) async fn replacing_one_with_two_updates_one_and_creates_one<R: Rig>() {
	let rig = R::start(&[("100", "203.0.113.20"), ("101", "203.0.113.10")]).await;
	let change = change(&rig, |held| {
		vec![held[0].clone(), a("203.0.113.11"), a("203.0.113.12")]
	})
	.await;
	let receipt = rig.provider().apply_guarded(ZONE, change).await;
	assert!(applied(&receipt), "{receipt:?}");
	assert_eq!(rig.writes(), vec!["update 101", "create"]);
}

pub(crate) async fn replacing_two_with_one_updates_one_and_deletes_the_other<R: Rig>() {
	let rig = R::start(&[
		("100", "203.0.113.20"),
		("201", "203.0.113.10"),
		("202", "203.0.113.11"),
	])
	.await;
	let change = change(&rig, |held| vec![held[0].clone(), a("203.0.113.12")]).await;
	let receipt = rig.provider().apply_guarded(ZONE, change).await;
	assert!(applied(&receipt), "{receipt:?}");
	assert_eq!(rig.writes(), vec!["update 201", "delete 202"]);
}

pub(crate) async fn change_that_alters_nothing_writes_nothing<R: Rig>() {
	let rig = R::start(&[("101", "203.0.113.10")]).await;
	let held = change(&rig, |held| held.to_vec()).await;
	let receipt = rig.provider().apply_guarded(ZONE, held).await;
	assert!(applied(&receipt), "{receipt:?}");
	assert_eq!(rig.writes(), Vec::<String>::new());
}

pub(crate) async fn change_outside_its_name_is_refused_before_any_write<R: Rig>() {
	let rig = R::start(&[("101", "203.0.113.10")]).await;
	let other = DnsRecord::new("other.example.org", RecordKind::A, "203.0.113.11", 300);
	let change = change(&rig, |_| vec![other]).await;
	let receipt = rig.provider().apply_guarded(ZONE, change).await;
	assert!(matches!(receipt, Receipt::Rejected(_)), "{receipt:?}");
	assert_eq!(rig.writes(), Vec::<String>::new());
}

/// Every case of the contract, as tests of the module it is invoked in.
macro_rules! guarded_contract {
	($rig:ty) => {
		$crate::dns::providers::tests::guarded_contract::cases!($rig;
			snapshot_carries_ids_and_says_it_checks,
			record_added_after_the_listing_stops_the_write,
			record_replaced_after_the_listing_stops_the_write,
			record_swapped_for_another_id_stops_the_write,
			record_removed_after_the_listing_stops_the_write,
			update_touches_only_the_record_that_changes,
			new_record_is_created_and_nothing_else_is_written,
			removal_deletes_only_its_own_id,
			replacing_one_with_two_updates_one_and_creates_one,
			replacing_two_with_one_updates_one_and_deletes_the_other,
			change_that_alters_nothing_writes_nothing,
			change_outside_its_name_is_refused_before_any_write,
		);
	};
}
macro_rules! cases {
	($rig:ty; $($case:ident,)*) => {
		$(
			#[tokio::test]
			async fn $case() {
				$crate::dns::providers::tests::guarded_contract::$case::<$rig>().await;
			}
		)*
	};
}
pub(crate) use cases;
pub(crate) use guarded_contract;
