//! The rules of an operation, against the in-memory store: what each caller
//! may name, the caps, and that a refusal writes nothing.

use super::fake::FakeAdmin;
use crate::antispam::bans::operator::*;
use crate::antispam::bans::{BanTarget, UnbanTarget};
use crate::cidr::Cidr;

const NOW: u64 = 1_000_000;

fn target(spec: &str) -> BanTarget {
	BanTarget::parse(spec).expect("a ban target")
}

fn cidr(spec: &str) -> Cidr {
	Cidr::parse(spec).expect("a block")
}

#[tokio::test]
async fn a_ban_lasts_a_day_unless_told_and_ends_at_that_instant() {
	let store = FakeAdmin::default();
	let banned = ban(&store, target("203.0.113.9"), None, NOW, Limits::operator())
		.await
		.expect("banned");
	assert_eq!(banned.until, NOW + DEFAULT_BAN_SECS);
	assert_eq!(banned.target, "203.0.113.9");
	let banned = ban(
		&store,
		target("203.0.113.9"),
		Some(60),
		NOW,
		Limits::operator(),
	)
	.await
	.expect("banned again");
	assert_eq!(banned.until, NOW + 60);
	assert_eq!(
		store.ban_until("ip:203.0.113.9"),
		Some(NOW + 60),
		"the row moved"
	);
}

#[tokio::test]
async fn an_allow_listed_address_is_not_banned_and_nothing_is_written() {
	let store = FakeAdmin::default();
	store.allow_entries(["203.0.113.0/24".to_string()]);
	let refusal = ban(&store, target("203.0.113.9"), None, NOW, Limits::operator())
		.await
		.expect_err("allow-listed");
	assert!(matches!(refusal, Refusal::AllowListed(_)), "{refusal}");
	assert!(store.writes().is_empty());
}

#[tokio::test]
async fn a_key_may_not_ban_or_allow_a_block_wider_than_its_limit() {
	let store = FakeAdmin::default();
	let api = Limits::api();
	for wide in ["10.0.0.0/8", "10.0.0.0/15", "2001:db8::/31", "2000::/3"] {
		let refusal = ban(&store, target(wide), None, NOW, api)
			.await
			.expect_err(wide);
		assert!(matches!(refusal, Refusal::TooWide(_)), "{wide}: {refusal}");
		let refusal = allow(&store, cidr(wide), api).await.expect_err(wide);
		assert!(matches!(refusal, Refusal::TooWide(_)), "{wide}: {refusal}");
	}
	assert!(store.writes().is_empty(), "{:?}", store.writes());
	let narrow = ["10.1.0.0/16", "10.1.2.3", "2001:db8::/32", "2001:db8::1"];
	for spec in narrow {
		ban(&store, target(spec), None, NOW, api).await.expect(spec);
	}
	for spec in narrow {
		allow(&store, cidr(spec), api).await.expect(spec);
	}
}

/// The operator at a terminal is not held to the narrower limit.
#[tokio::test]
async fn the_operator_may_name_a_wide_block() {
	let store = FakeAdmin::default();
	ban(&store, target("10.0.0.0/8"), None, NOW, Limits::operator())
		.await
		.expect("a /8 ban");
	allow(&store, cidr("0.0.0.0/0"), Limits::operator())
		.await
		.expect("the whole internet allowed");
}

fn nets(prefix: &str, count: usize) -> Vec<String> {
	(0..count)
		.map(|n| format!("{prefix}{}.{}.0/24", n / 250, n % 250))
		.collect()
}

#[tokio::test]
async fn the_bans_the_listeners_raise_do_not_use_up_a_keys_room() {
	let store = FakeAdmin::default();
	for n in 0..API_MAX_MANUAL_BANS + 50 {
		store.preload_ban(&format!("account:user{n}@example.org"), NOW + 1_000);
	}
	ban(&store, target("203.0.113.9"), None, NOW, Limits::api())
		.await
		.expect("automatic bans never block a manual one");
}

#[tokio::test]
async fn the_manual_cap_stops_a_new_ban_and_not_a_renewal_and_not_the_operator() {
	let store = FakeAdmin::default();
	for n in 0..API_MAX_MANUAL_BANS {
		let target = target(&format!("2001:db8:{:x}:{:x}::1", n / 250, n % 250));
		store.preload_manual(&target.subject(), NOW + 1_000);
	}
	let refusal = ban(&store, target("203.0.113.9"), None, NOW, Limits::api())
		.await
		.expect_err("full");
	assert!(matches!(refusal, Refusal::Full("manual bans")), "{refusal}");
	ban(
		&store,
		target("2001:db8:0:0::1"),
		Some(5),
		NOW,
		Limits::api(),
	)
	.await
	.expect("a ban that is already there moves");
	assert_eq!(
		store.ban_until(&target("2001:db8:0:0::1").subject()),
		Some(NOW + 5)
	);
	ban(&store, target("203.0.113.9"), None, NOW, Limits::operator())
		.await
		.expect("the operator has no count");
}

/// Many networks of a middling size would cover more than any one entry
/// does: a key has a few of them.
#[tokio::test]
async fn a_key_keeps_few_banned_networks_and_the_operator_any_number() {
	let store = FakeAdmin::default();
	for net in nets("10.", API_MAX_BAN_NETWORKS) {
		store.preload_manual(&format!("cidr:{net}"), NOW + 1_000);
	}
	let refusal = ban(&store, target("192.0.2.0/24"), None, NOW, Limits::api())
		.await
		.expect_err("full");
	assert!(
		matches!(refusal, Refusal::Full("banned networks")),
		"{refusal}"
	);
	ban(&store, target("192.0.2.9"), None, NOW, Limits::api())
		.await
		.expect("an address is not a network");
	ban(&store, target("10.0.0.0/24"), Some(5), NOW, Limits::api())
		.await
		.expect("a network that is there moves");
	ban(
		&store,
		target("192.0.2.0/24"),
		None,
		NOW,
		Limits::operator(),
	)
	.await
	.expect("the operator has no count");
}

#[tokio::test]
async fn the_allow_caps_stop_a_new_entry_and_a_new_network_and_not_one_already_there() {
	let store = FakeAdmin::default();
	store.allow_entries(nets("10.", API_MAX_ALLOW_NETWORKS));
	let refusal = allow(&store, cidr("192.0.2.0/24"), Limits::api())
		.await
		.expect_err("full of networks");
	assert!(
		matches!(refusal, Refusal::Full("allowed networks")),
		"{refusal}"
	);
	allow(&store, cidr("192.0.2.9"), Limits::api())
		.await
		.expect("an address is not a network");
	let held = store
		.allowed()
		.into_iter()
		.find(|e| e.starts_with("10."))
		.expect("held");
	assert!(
		!allow(&store, cidr(&held), Limits::api())
			.await
			.expect("held")
	);
	allow(&store, cidr("192.0.2.0/24"), Limits::operator())
		.await
		.expect("the operator has no count");
	let full = FakeAdmin::default();
	full.allow_entries((0..API_MAX_ALLOW_ENTRIES).map(|n| format!("2001:db8:{n:x}::1")));
	let refusal = allow(&full, cidr("192.0.2.9"), Limits::api())
		.await
		.expect_err("full");
	assert!(
		matches!(refusal, Refusal::Full("allow-list entries")),
		"{refusal}"
	);
}

/// A key cannot lift a block wider than it could have made, which an
/// operator may have.
#[tokio::test]
async fn a_key_cannot_lift_or_remove_a_block_wider_than_it_may_name() {
	let store = FakeAdmin::default();
	store.preload_manual("cidr:10.0.0.0/8", NOW + 1_000);
	store.allow_entries(["172.16.0.0/12".to_string()]);
	let wide = UnbanTarget::parse("10.0.0.0/8").expect("target");
	let refusal = unban(&store, wide.clone(), Limits::api())
		.await
		.expect_err("wide");
	assert!(matches!(refusal, Refusal::TooWide(_)), "{refusal}");
	let refusal = disallow(&store, cidr("172.16.0.0/12"), Limits::api())
		.await
		.expect_err("wide");
	assert!(matches!(refusal, Refusal::TooWide(_)), "{refusal}");
	assert_eq!(store.ban_subjects(), ["cidr:10.0.0.0/8"]);
	assert_eq!(store.allowed(), ["172.16.0.0/12"]);
	unban(&store, wide, Limits::operator())
		.await
		.expect("the operator may");
	disallow(&store, cidr("172.16.0.0/12"), Limits::operator())
		.await
		.expect("the operator may");
}

#[tokio::test]
async fn lifting_what_is_not_banned_and_removing_what_is_not_allowed_are_refused() {
	let store = FakeAdmin::default();
	let refusal = unban(
		&store,
		UnbanTarget::parse("203.0.113.9").expect("target"),
		Limits::operator(),
	)
	.await
	.expect_err("nothing there");
	assert_eq!(
		refusal.to_string(),
		"203.0.113.9 has no ban or failure record"
	);
	let refusal = disallow(&store, cidr("10.0.0.0/8"), Limits::operator())
		.await
		.expect_err("not listed");
	assert_eq!(refusal.to_string(), "10.0.0.0/8 is not on the allow list");
}

#[tokio::test]
async fn a_failing_store_is_reported_and_nothing_is_written() {
	let store = FakeAdmin::default();
	store.break_down();
	let refusal = ban(&store, target("203.0.113.9"), None, NOW, Limits::operator())
		.await
		.expect_err("down");
	assert!(matches!(refusal, Refusal::Store(_)), "{refusal}");
	assert!(store.writes().is_empty());
}

#[test]
fn durations_take_a_unit_and_reject_nonsense() {
	for (text, secs) in [
		("90", 90),
		("45s", 45),
		("90m", 5_400),
		("24h", 86_400),
		("2w", 1_209_600),
	] {
		assert_eq!(parse_duration(text), Ok(secs), "{text}");
	}
	for text in [
		"",
		"h",
		"0",
		"0h",
		"-5m",
		"1.5h",
		"3y",
		"99999d",
		"5 m",
		"99999999999999999999d",
	] {
		assert!(parse_duration(text).is_err(), "{text:?} must be rejected");
	}
}

/// A ban the listeners raised that a key turns into a manual one takes room
/// like any new manual ban: it is not a renewal.
#[tokio::test]
async fn making_an_automatic_ban_manual_counts_against_the_cap() {
	let store = FakeAdmin::default();
	for n in 0..API_MAX_MANUAL_BANS {
		let target = target(&format!("2001:db8:{:x}:{:x}::1", n / 250, n % 250));
		store.preload_manual(&target.subject(), NOW + 1_000);
	}
	store.preload_ban("ip:203.0.113.9", NOW + 1_000);
	let refusal = ban(&store, target("203.0.113.9"), None, NOW, Limits::api())
		.await
		.expect_err("a conversion is not a renewal");
	assert!(matches!(refusal, Refusal::Full("manual bans")), "{refusal}");
}

/// Requests that arrive together at the edge of the room do not all pass the
/// count: the store counts and writes as one step.
#[tokio::test]
async fn requests_at_the_edge_of_the_room_take_exactly_what_is_left() {
	let store = std::sync::Arc::new(FakeAdmin::default());
	for net in nets("10.", API_MAX_BAN_NETWORKS - 1) {
		store.preload_manual(&format!("cidr:{net}"), NOW + 1_000);
	}
	let mut tasks = tokio::task::JoinSet::new();
	for n in 0..16 {
		let store = store.clone();
		tasks.spawn(async move {
			ban(
				&*store,
				target(&format!("192.0.{n}.0/24")),
				None,
				NOW,
				Limits::api(),
			)
			.await
		});
	}
	let (mut placed, mut full) = (0, 0);
	while let Some(done) = tasks.join_next().await {
		match done.expect("task") {
			Ok(_) => placed += 1,
			Err(Refusal::Full("banned networks")) => full += 1,
			Err(other) => panic!("{other}"),
		}
	}
	assert_eq!((placed, full), (1, 15));
	let networks = store
		.ban_subjects()
		.iter()
		.filter(|s| s.starts_with("cidr:"))
		.count();
	assert_eq!(networks, API_MAX_BAN_NETWORKS);

	let allowed = std::sync::Arc::new(FakeAdmin::default());
	allowed.allow_entries(nets("10.", API_MAX_ALLOW_NETWORKS - 1));
	let mut tasks = tokio::task::JoinSet::new();
	for n in 0..16 {
		let allowed = allowed.clone();
		tasks.spawn(async move {
			allow(&*allowed, cidr(&format!("192.0.{n}.0/24")), Limits::api()).await
		});
	}
	let (mut placed, mut full) = (0, 0);
	while let Some(done) = tasks.join_next().await {
		match done.expect("task") {
			Ok(true) => placed += 1,
			Err(Refusal::Full("allowed networks")) => full += 1,
			other => panic!("{other:?}"),
		}
	}
	assert_eq!((placed, full), (1, 15));
	assert_eq!(allowed.allowed().len(), API_MAX_ALLOW_NETWORKS);
}
