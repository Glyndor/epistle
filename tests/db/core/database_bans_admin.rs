//! Live-database tests for the operator side of the ban store: manual bans,
//! network bans, unbanning, and the allow list that the ban policy consults.
//! They need a real PostgreSQL and only run when `DATABASE_URL` is set (the
//! `Database` CI workflow provides one); otherwise they skip, like
//! `tests/db/core/database_bans.rs`.
//!
//! The ban and allow tables are shared by every test in the run, so each test
//! works in its own `2001:db8:x:y::/64` block (the documentation range, never a
//! real client) chosen from a fresh UUID, and removes what it created.

use epistle::antispam::bans::{BanPolicy, BanStore, BanTarget, PgBanStore, parse_allow};
use epistle::config::DatabaseTls;

fn database_url() -> Option<String> {
	std::env::var("DATABASE_URL").ok().filter(|u| !u.is_empty())
}

fn now() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0)
}

/// A private documentation-range `/64` for one test, as its first four groups.
/// The 32 random bits make a collision with another test or a stale row
/// negligible.
fn fresh_block() -> String {
	let bytes = uuid::Uuid::now_v7().into_bytes();
	format!(
		"2001:db8:{:x}:{:x}",
		u16::from_be_bytes([bytes[12], bytes[13]]),
		u16::from_be_bytes([bytes[14], bytes[15]])
	)
}

fn policy() -> BanPolicy {
	BanPolicy {
		window_secs: 60,
		threshold: 5,
		base_secs: 60,
		max_secs: 600,
		known_network_window_secs: 60 * 60,
		known_network_max_per_account: 32,
		account_threshold_factor: 4,
	}
}

/// The tests of this file share the ban tables and the room a count is taken
/// against, so they run one at a time: a test that lifts its own network while
/// another counts would make room the other did not see.
static ONE_AT_A_TIME: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn connect() -> Option<(
	sqlx::PgPool,
	PgBanStore,
	tokio::sync::MutexGuard<'static, ()>,
)> {
	let url = database_url().or_else(|| {
		eprintln!("skipping: DATABASE_URL not set");
		None
	})?;
	let serial = ONE_AT_A_TIME.lock().await;
	let pool = epistle::db::connect(&url, DatabaseTls::Insecure, 5, None)
		.await
		.expect("connect and migrate");
	let store = PgBanStore::with_policy(pool.clone(), None, policy());
	Some((pool, store, serial))
}

/// Clear what a test left on `subject`. A success cannot lift an active ban,
/// so the check asks as of a moment after any ban the policy can set.
async fn clean_after(store: &PgBanStore, subject: &str) {
	store
		.clear_success(subject, now() + policy().max_secs + 1)
		.await;
}

async fn fail_times(store: &PgBanStore, subject: &str, times: usize) {
	for _ in 0..times {
		store.record_failure(subject, "smtp", now()).await;
	}
}

async fn failure_rows(pool: &sqlx::PgPool, subject: &str) -> i64 {
	sqlx::query_scalar("SELECT count(*) FROM auth_failure WHERE subject = $1")
		.bind(subject)
		.fetch_one(pool)
		.await
		.expect("count failures")
}

#[tokio::test]
async fn an_allow_listed_address_is_never_counted_or_banned() {
	let Some((pool, store, _serial)) = connect().await else {
		return;
	};
	let block = fresh_block();
	let allowed = format!("ip:{block}::10");
	let other = format!("ip:{block}::200");
	let net = parse_allow(&format!("{block}::/120")).expect("cidr");
	store.allow_add(net).await.expect("allow add");

	fail_times(&store, &allowed, 8).await;
	assert!(
		store.is_banned(&allowed, now()).await.is_none(),
		"eight failures from an allow-listed address must not ban it"
	);
	assert_eq!(
		failure_rows(&pool, &allowed).await,
		0,
		"failures are not even counted"
	);

	// A neighbour outside the allowed range is banned as usual.
	fail_times(&store, &other, 5).await;
	let ban = store.is_banned(&other, now()).await.expect("banned");
	assert!(ban.until_secs > now());

	store.allow_remove(net).await.expect("allow remove");
	store
		.remove_ban(BanTarget::parse(&format!("{block}::200")).expect("ip"))
		.await
		.expect("cleanup");
}

#[tokio::test]
async fn the_allow_list_overrides_a_ban_and_a_removal_restores_it_without_restart() {
	let Some((_pool, store, _serial)) = connect().await else {
		return;
	};
	let block = fresh_block();
	let subject = format!("ip:{block}::20");
	let target = BanTarget::parse(&format!("{block}::20")).expect("ip");
	store
		.add_ban(target, now(), now() + 600)
		.await
		.expect("ban");
	assert!(store.is_banned(&subject, now()).await.is_some());

	let net = parse_allow(&format!("{block}::/64")).expect("cidr");
	assert!(
		store.allow_add(net).await.expect("allow"),
		"first add inserts"
	);
	assert!(
		!store.allow_add(net).await.expect("allow again"),
		"second add is a no-op"
	);
	assert!(
		store.is_banned(&subject, now()).await.is_none(),
		"allow wins over a ban"
	);

	assert!(store.allow_remove(net).await.expect("remove"));
	assert!(!store.allow_remove(net).await.expect("remove again"));
	assert!(
		store.is_banned(&subject, now()).await.is_some(),
		"the ban applies again"
	);
	store.remove_ban(target).await.expect("cleanup");
}

#[tokio::test]
async fn a_network_ban_covers_every_address_in_it_and_no_other() {
	let Some((_pool, store, _serial)) = connect().await else {
		return;
	};
	let block = fresh_block();
	let target = BanTarget::parse(&format!("{block}::/64")).expect("cidr");
	store
		.add_ban(target, now(), now() + 600)
		.await
		.expect("ban");

	let inside = store.is_banned(&format!("ip:{block}::77"), now()).await;
	assert_eq!(inside.expect("inside is banned").reason, "manual ban");
	assert!(store.is_banned("ip:2001:db9::1", now()).await.is_none());
	// Account subjects are never matched against a network.
	assert!(store.is_banned("account:alice", now()).await.is_none());

	let (bans, failures) = store.remove_ban(target).await.expect("unban");
	assert_eq!((bans, failures), (1, 0));
	assert!(
		store
			.is_banned(&format!("ip:{block}::77"), now())
			.await
			.is_none()
	);
}

#[tokio::test]
async fn unbanning_an_address_also_clears_its_failure_counter() {
	let Some((pool, store, _serial)) = connect().await else {
		return;
	};
	let block = fresh_block();
	let subject = format!("ip:{block}::30");
	fail_times(&store, &subject, 5).await;
	assert!(store.is_banned(&subject, now()).await.is_some());

	let target = BanTarget::parse(&format!("{block}::30")).expect("ip");
	assert_eq!(store.remove_ban(target).await.expect("unban"), (1, 5));
	assert!(store.is_banned(&subject, now()).await.is_none());
	assert_eq!(failure_rows(&pool, &subject).await, 0);

	// With the counter cleared, four more failures do not ban again.
	fail_times(&store, &subject, 4).await;
	assert!(store.is_banned(&subject, now()).await.is_none());
	store.remove_ban(target).await.expect("cleanup");
}

#[tokio::test]
async fn list_shows_active_manual_bans_and_skips_expired_ones() {
	let Some((_pool, store, _serial)) = connect().await else {
		return;
	};
	let block = fresh_block();
	let live = BanTarget::parse(&format!("{block}::40")).expect("ip");
	let dead = BanTarget::parse(&format!("{block}::41")).expect("ip");
	let until = now() + 3600;
	store.add_ban(live, now(), until).await.expect("live");
	store
		.add_ban(dead, now() - 100, now() - 50)
		.await
		.expect("expired");

	let rows = store.list_bans(now()).await.expect("list");
	let row = rows
		.iter()
		.find(|r| r.subject == format!("ip:{block}::40"))
		.expect("live ban listed");
	assert_eq!((row.reason.as_str(), row.until_secs), ("manual ban", until));
	assert!(rows.iter().all(|r| r.subject != format!("ip:{block}::41")));

	// Adding again moves the end time instead of failing.
	store
		.add_ban(live, now(), until + 60)
		.await
		.expect("extend");
	let rows = store.list_bans(now()).await.expect("list");
	let row = rows
		.iter()
		.find(|r| r.subject == format!("ip:{block}::40"))
		.expect("listed");
	assert_eq!(row.until_secs, until + 60);
	store.remove_ban(live).await.expect("cleanup");
	store.remove_ban(dead).await.expect("cleanup");
}

#[tokio::test]
async fn removing_an_account_drops_its_pair_rows_and_nobody_elses() {
	let Some((_pool, store, _serial)) = connect().await else {
		return;
	};
	let tag = uuid::Uuid::now_v7().simple().to_string();
	let doomed = format!("gone-{}", &tag[..12]);
	let kept = format!("kept-{}", &tag[..12]);
	let doomed_pair = format!("pair:{doomed}|203.0.113.5");
	let doomed_account = format!("account:{doomed}");
	let kept_pair = format!("pair:{kept}|203.0.113.5");
	let t = now();
	for subject in [&doomed_pair, &doomed_account, &kept_pair] {
		// An account needs four times a pair's failures to be banned.
		let failures = if subject.starts_with("account:") {
			20
		} else {
			5
		};
		for _ in 0..failures {
			store.record_failure(subject, "imaps", t).await;
		}
		assert!(
			store.is_banned(subject, t).await.is_some(),
			"a banned subject must be reported as banned"
		);
	}
	store.remove_account(&doomed).await;
	assert!(store.is_banned(&doomed_pair, t).await.is_none());
	assert!(store.is_banned(&doomed_account, t).await.is_none());
	assert!(
		store.is_banned(&kept_pair, t).await.is_some(),
		"another account's pair must stay"
	);
	clean_after(&store, &kept_pair).await;
}

#[tokio::test]
async fn unbanning_an_ipv6_address_lifts_the_slash_64_it_is_counted_under() {
	let Some((_pool, store, _serial)) = connect().await else {
		return;
	};
	let block = fresh_block();
	let address: std::net::IpAddr = format!("{block}::7").parse().expect("address");
	let counted = epistle::antispam::bans::subject_client(address);
	assert_eq!(counted, format!("ip:{block}::"), "the /64, not the host");
	fail_times(&store, &counted, 5).await;
	assert!(store.is_banned(&counted, now()).await.is_some());
	store
		.remove_ban(BanTarget::Ip(address))
		.await
		.expect("remove ban");
	assert!(store.is_banned(&counted, now()).await.is_none());
}

#[tokio::test]
async fn an_account_needs_four_times_the_failures_of_a_client_to_be_banned() {
	let Some((_pool, store, _serial)) = connect().await else {
		return;
	};
	let tag = uuid::Uuid::now_v7().simple().to_string();
	let account = format!("account:thr-{}", &tag[..12]);
	let pair = format!("pair:thr-{}|203.0.113.5", &tag[..12]);
	let t = now();
	fail_times(&store, &pair, 5).await;
	assert!(store.is_banned(&pair, t).await.is_some(), "five ban a pair");
	fail_times(&store, &account, 19).await;
	assert!(
		store.is_banned(&account, t).await.is_none(),
		"nineteen do not ban an account"
	);
	fail_times(&store, &account, 1).await;
	let info = store.is_banned(&account, t).await.expect("twenty ban it");
	assert_eq!(info.reason, "20 failed authentications in 60 seconds");
	clean_after(&store, &pair).await;
	clean_after(&store, &account).await;
}

#[tokio::test]
async fn the_store_reports_whether_the_allow_list_covers_an_address() {
	let Some((_pool, store, _serial)) = connect().await else {
		return;
	};
	let block = fresh_block();
	let host: std::net::IpAddr = format!("{block}::10").parse().expect("host");
	let neighbour: std::net::IpAddr = format!("{block}::11").parse().expect("neighbour");
	let entry = parse_allow(&format!("{block}::10")).expect("entry");
	assert!(!store.is_allow_listed(host).await);
	store.allow_add(entry).await.expect("allow");
	assert!(store.is_allow_listed(host).await);
	assert!(
		!store.is_allow_listed(neighbour).await,
		"only the host, not its /64"
	);
	store.allow_remove(entry).await.expect("unallow");
}

/// The operations `epistle ban` and the `/api/v1/bans` routes share, run on
/// the database through the trait the routes hold.
#[tokio::test]
async fn the_shared_operations_run_on_the_database() {
	use epistle::antispam::bans::operator::{self as admin, BanAdmin, Limits, Refusal};

	let Some((_pool, store, _serial)) = connect().await else {
		return;
	};
	let store: &dyn BanAdmin = &store;
	let block = fresh_block();
	let spec = format!("{block}::30");
	let subject = format!("ip:{spec}");
	let target = BanTarget::parse(&spec).expect("ip");
	let net = parse_allow(&format!("{block}::/64")).expect("cidr");
	let at = now();

	let banned = admin::ban(store, target, Some(600), at, Limits::api())
		.await
		.expect("ban");
	assert_eq!(banned.until, at + 600);
	let rows = store.list_bans(at).await.expect("list");
	assert!(rows.iter().any(|row| row.subject == subject), "{rows:?}");

	assert!(
		admin::allow(store, net, Limits::api())
			.await
			.expect("allow")
	);
	let refusal = admin::ban(store, target, None, at, Limits::api())
		.await
		.expect_err("an allow-listed address is not banned");
	assert!(matches!(refusal, Refusal::AllowListed(_)), "{refusal}");
	admin::disallow(store, net, Limits::api())
		.await
		.expect("disallow");
	let refusal = admin::disallow(store, net, Limits::api())
		.await
		.expect_err("not there");
	assert!(matches!(refusal, Refusal::NotAllowed(_)), "{refusal}");

	let lifted = admin::unban(store, target.into(), Limits::api())
		.await
		.expect("unban");
	assert_eq!(lifted.bans, 1);
	let refusal = admin::unban(store, target.into(), Limits::api())
		.await
		.expect_err("nothing left");
	assert!(matches!(refusal, Refusal::NoBan(_)), "{refusal}");
}

/// Requests that arrive together at the edge of the room take no more than
/// what is left: the store counts and writes as one step. The tables are
/// shared with the other tests, so the room is set from what is there, and the
/// invariant is that no more than the one place left is taken.
#[tokio::test]
async fn bans_and_allow_entries_at_the_edge_of_the_room_are_taken_atomically() {
	use epistle::antispam::bans::operator::{AllowPlaced, AllowRoom, BanAdmin, BanRoom, Placed};

	let Some((_pool, store, _serial)) = connect().await else {
		return;
	};
	let store = std::sync::Arc::new(store);
	// Three groups of the address, so that the last one tells 16 networks of a
	// /64 apart; with four, the sixteen would be the same network.
	let full = fresh_block();
	let block = full
		.rsplit_once(':')
		.map_or(full.as_str(), |(head, _)| head);
	let at = now();
	let held = store
		.list_bans(at)
		.await
		.expect("list")
		.iter()
		.filter(|row| row.reason == epistle::antispam::bans::MANUAL_REASON)
		.filter(|row| row.subject.starts_with("cidr:"))
		.count();
	let room = BanRoom {
		max_manual: usize::MAX,
		max_networks: held + 1,
	};
	let mut tasks = tokio::task::JoinSet::new();
	let mut targets = Vec::new();
	for n in 0..16 {
		let target = BanTarget::parse(&format!("{block}:{n:x}::/64")).expect("network");
		targets.push(target);
		let store = store.clone();
		tasks.spawn(async move {
			let store: &dyn BanAdmin = &*store;
			store.add_ban_within(target, at, at + 600, room).await
		});
	}
	let mut placed = 0;
	while let Some(done) = tasks.join_next().await {
		if done.expect("task").expect("store") == Placed::Done {
			placed += 1;
		}
	}
	assert!(placed <= 1, "{placed} networks took the one place left");
	for target in targets {
		let _ = store.remove_ban(target).await;
	}

	let allowed = store.allow_list().await.expect("list");
	let networks = allowed
		.iter()
		.filter_map(|entry| parse_allow(entry).ok())
		.filter(|entry| !entry.is_host())
		.count();
	let room = AllowRoom {
		max_entries: usize::MAX,
		max_networks: networks + 1,
	};
	let mut tasks = tokio::task::JoinSet::new();
	let mut blocks = Vec::new();
	for n in 0..16 {
		let cidr = parse_allow(&format!("{block}:{n:x}::/64")).expect("block");
		blocks.push(cidr);
		let store = store.clone();
		tasks.spawn(async move {
			let store: &dyn BanAdmin = &*store;
			store.allow_add_within(cidr, room).await
		});
	}
	let mut added = 0;
	while let Some(done) = tasks.join_next().await {
		if done.expect("task").expect("store") == AllowPlaced::Added {
			added += 1;
		}
	}
	assert!(added <= 1, "{added} blocks took the one place left");
	for cidr in blocks {
		let _ = store.allow_remove(cidr).await;
	}
}
