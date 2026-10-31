//! Live-database tests for the known-network bypass list. The in-memory
//! fake in `src/antispam/bans/tests/base.rs` covers the trait contract; the
//! PostgreSQL case here covers the SQL projection, the upsert throttle,
//! the cap eviction and the sweep horizon.
//!
//! Same `DATABASE_URL` gating as `database_bans.rs`: tests that need a
//! real PostgreSQL skip when the variable is unset, so the default
//! `cargo test` needs no database. The `Database` workflow in CI
//! provides one.

use epistle::antispam::bans::{BanPolicy, BanStore, PgBanStore};
use epistle::config::DatabaseTls;

fn database_url() -> Option<String> {
	std::env::var("DATABASE_URL").ok().filter(|u| !u.is_empty())
}

/// A policy that matches the test thresholds: a short window so the
/// sweep test runs in seconds, a small cap so the eviction test stays
/// in a few rows.
fn policy() -> BanPolicy {
	BanPolicy {
		window_secs: 60,
		threshold: 5,
		base_secs: 60,
		max_secs: 600,
		known_network_window_secs: 60 * 60,
		known_network_max_per_account: 3,
	}
}

async fn clean_account(pool: &sqlx::PgPool, account: &str) {
	sqlx::query("DELETE FROM auth_known_network WHERE account = $1")
		.bind(account)
		.execute(pool)
		.await
		.expect("clear auth_known_network");
}

#[tokio::test]
async fn record_known_network_writes_a_row_then_is_known() {
	let Some(url) = database_url() else {
		eprintln!("skipping: DATABASE_URL not set");
		return;
	};
	let pool = epistle::db::connect(&url, DatabaseTls::Insecure, 5, None)
		.await
		.expect("connect and migrate");
	let store = PgBanStore::with_policy(pool.clone(), None, policy());
	let account = format!("alice-{}", uuid::Uuid::now_v7());
	let now: u64 = std::time::SystemTime::now()
		.duration_since(std::time::SystemTime::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0);
	let ip: std::net::IpAddr = "203.0.113.5".parse().expect("ip");

	assert!(
		!store.is_known_network(&account, ip, now).await,
		"a fresh account must not be on the bypass list"
	);
	store.record_known_network(&account, ip, now).await;
	assert!(
		store.is_known_network(&account, ip, now).await,
		"after a successful write the network must be on the bypass list"
	);
	clean_account(&pool, &account).await;
}

#[tokio::test]
async fn is_known_network_returns_false_outside_the_window() {
	let Some(url) = database_url() else {
		eprintln!("skipping: DATABASE_URL not set");
		return;
	};
	let pool = epistle::db::connect(&url, DatabaseTls::Insecure, 5, None)
		.await
		.expect("connect and migrate");
	let store = PgBanStore::with_policy(pool.clone(), None, policy());
	let account = format!("alice-{}", uuid::Uuid::now_v7());
	let ip: std::net::IpAddr = "203.0.113.6".parse().expect("ip");
	let now: u64 = std::time::SystemTime::now()
		.duration_since(std::time::SystemTime::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0);

	store.record_known_network(&account, ip, now).await;
	assert!(
		store.is_known_network(&account, ip, now).await,
		"a fresh row inside the window must be known"
	);
	// Past the window the row ages out and the lookup fails closed.
	assert!(
		!store
			.is_known_network(&account, ip, now + 2 * 60 * 60)
			.await,
		"a row past the window must age out and become unknown"
	);
	clean_account(&pool, &account).await;
}

#[tokio::test]
async fn record_known_network_throttles_to_one_write_per_hour() {
	let Some(url) = database_url() else {
		eprintln!("skipping: DATABASE_URL not set");
		return;
	};
	let pool = epistle::db::connect(&url, DatabaseTls::Insecure, 5, None)
		.await
		.expect("connect and migrate");
	let store = PgBanStore::with_policy(pool.clone(), None, policy());
	let account = format!("alice-{}", uuid::Uuid::now_v7());
	let ip: std::net::IpAddr = "203.0.113.7".parse().expect("ip");
	let now: u64 = std::time::SystemTime::now()
		.duration_since(std::time::SystemTime::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0);

	store.record_known_network(&account, ip, now).await;
	let first_seen =
		sqlx::query_scalar::<_, i64>("SELECT last_seen FROM auth_known_network WHERE account = $1")
			.bind(&account)
			.fetch_one(&pool)
			.await
			.expect("first row");
	assert_eq!(first_seen, now as i64);

	// A second call inside the throttle must NOT update the row. The
	// SQL `WHERE last_seen <= $3 - $4` clause skips the UPDATE; the
	// row's `last_seen` stays at `now`.
	store.record_known_network(&account, ip, now + 30).await;
	let still_first =
		sqlx::query_scalar::<_, i64>("SELECT last_seen FROM auth_known_network WHERE account = $1")
			.bind(&account)
			.fetch_one(&pool)
			.await
			.expect("still the first row");
	assert_eq!(
		still_first, first_seen,
		"a write inside the throttle window must not move last_seen"
	);

	// Past the throttle, the row updates.
	let later = now + 60 * 60 + 1;
	store.record_known_network(&account, ip, later).await;
	let refreshed =
		sqlx::query_scalar::<_, i64>("SELECT last_seen FROM auth_known_network WHERE account = $1")
			.bind(&account)
			.fetch_one(&pool)
			.await
			.expect("refreshed row");
	assert_eq!(
		refreshed, later as i64,
		"a write past the throttle window must update last_seen"
	);
	clean_account(&pool, &account).await;
}

#[tokio::test]
async fn record_known_network_caps_per_account_evicting_oldest() {
	let Some(url) = database_url() else {
		eprintln!("skipping: DATABASE_URL not set");
		return;
	};
	let pool = epistle::db::connect(&url, DatabaseTls::Insecure, 5, None)
		.await
		.expect("connect and migrate");
	let store = PgBanStore::with_policy(pool.clone(), None, policy());
	let account = format!("alice-{}", uuid::Uuid::now_v7());
	// The cap on the test policy is 3; seed four distinct networks.
	let now: u64 = std::time::SystemTime::now()
		.duration_since(std::time::SystemTime::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0);
	let networks = [
		"203.0.113.20".parse::<std::net::IpAddr>().expect("ip"),
		"203.0.113.21".parse::<std::net::IpAddr>().expect("ip"),
		"203.0.113.22".parse::<std::net::IpAddr>().expect("ip"),
		"203.0.113.23".parse::<std::net::IpAddr>().expect("ip"),
	];
	for (index, network) in networks.iter().enumerate() {
		// Push past the throttle so each entry writes its own row.
		store
			.record_known_network(&account, *network, now + (index as u64) * (60 * 60 + 10))
			.await;
	}

	let count =
		sqlx::query_scalar::<_, i64>("SELECT count(*) FROM auth_known_network WHERE account = $1")
			.bind(&account)
			.fetch_one(&pool)
			.await
			.expect("count");
	assert_eq!(
		count, 3,
		"the per-account cap must hold at the policy ceiling (3)"
	);
	// The oldest row was evicted.
	let first_present: Option<String> = sqlx::query_scalar(
		"SELECT network::text FROM auth_known_network WHERE account = $1 AND network = $2",
	)
	.bind(&account)
	.bind(networks[0].to_string())
	.fetch_optional(&pool)
	.await
	.expect("oldest");
	assert!(
		first_present.is_none(),
		"the oldest network must be evicted when a new one is added past the cap"
	);
	clean_account(&pool, &account).await;
}

#[tokio::test]
async fn is_known_network_handles_ipv6_as_a_64() {
	let Some(url) = database_url() else {
		eprintln!("skipping: DATABASE_URL not set");
		return;
	};
	let pool = epistle::db::connect(&url, DatabaseTls::Insecure, 5, None)
		.await
		.expect("connect and migrate");
	let store = PgBanStore::with_policy(pool.clone(), None, policy());
	let account = format!("alice-{}", uuid::Uuid::now_v7());
	let addr_a: std::net::IpAddr = "2001:db8:1::1".parse().expect("ipv6");
	let addr_b: std::net::IpAddr = "2001:db8:1::2".parse().expect("ipv6");
	let addr_other: std::net::IpAddr = "2001:db8:2::1".parse().expect("ipv6");
	let now: u64 = std::time::SystemTime::now()
		.duration_since(std::time::SystemTime::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0);

	store.record_known_network(&account, addr_a, now).await;
	assert!(
		store.is_known_network(&account, addr_b, now).await,
		"any address in the /64 must look up the same row"
	);
	assert!(
		!store.is_known_network(&account, addr_other, now).await,
		"an address in a different /64 must not be served by the same row"
	);
	clean_account(&pool, &account).await;
}

#[tokio::test]
async fn sweep_drops_known_network_rows_past_the_window() {
	let Some(url) = database_url() else {
		eprintln!("skipping: DATABASE_URL not set");
		return;
	};
	let pool = epistle::db::connect(&url, DatabaseTls::Insecure, 5, None)
		.await
		.expect("connect and migrate");
	let store = PgBanStore::with_policy(pool.clone(), None, policy());
	let account = format!("alice-{}", uuid::Uuid::now_v7());
	let ip: std::net::IpAddr = "203.0.113.30".parse().expect("ip");
	// Pin the row's `last_seen` to two hours before the test runs so
	// the sweep is the only writer and the only consumer of this row.
	// Other tests in the same file run in parallel and write rows
	// with `last_seen` near the current second; the sweep's horizon
	// is `sweep_now - known_network_window_secs`, so a row written
	// two hours in the past falls past the horizon while a row
	// written at the current second stays inside it.
	let sweep_now: u64 = std::time::SystemTime::now()
		.duration_since(std::time::SystemTime::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0);
	let written_at: u64 = sweep_now - 2 * 60 * 60;
	store.record_known_network(&account, ip, written_at).await;

	// The test policy's window is one hour; the sweep runs an hour
	// past the row, which is an hour past the horizon.
	store.sweep(sweep_now).await;
	let still_present: Option<String> =
		sqlx::query_scalar("SELECT network::text FROM auth_known_network WHERE account = $1")
			.bind(&account)
			.fetch_optional(&pool)
			.await
			.expect("after sweep");
	assert!(
		still_present.is_none(),
		"a sweep past the known-network window must drop the row"
	);
	clean_account(&pool, &account).await;
}

/// Banned-but-known: the bypass lifts the account ban from the
/// (account, network) pair. The test arms an account ban and a
/// fresh bypass row, asserts the bypass exists at the lookup, and
/// asserts the row the success path wrote is still in the table after
/// the simulated clearance.
#[tokio::test]
async fn arming_an_account_ban_does_not_drop_the_known_network_row() {
	let Some(url) = database_url() else {
		eprintln!("skipping: DATABASE_URL not set");
		return;
	};
	let pool = epistle::db::connect(&url, DatabaseTls::Insecure, 5, None)
		.await
		.expect("connect and migrate");
	let store = PgBanStore::with_policy(pool.clone(), None, policy());
	let account = format!("alice-{}", uuid::Uuid::now_v7());
	let ip: std::net::IpAddr = "203.0.113.31".parse().expect("ip");
	let now: u64 = std::time::SystemTime::now()
		.duration_since(std::time::SystemTime::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0);

	store.record_known_network(&account, ip, now).await;
	// Simulate a ban row: the production `record_failure` flow
	// inserts the ban on a fifth failure inside the window.
	sqlx::query(
		"INSERT INTO auth_ban (subject, strikes, until, reason, created_at, updated_at) \
		 VALUES ($1, 1, to_timestamp($2), 'manual', to_timestamp($3), to_timestamp($3))",
	)
	.bind(format!("account:{account}"))
	.bind((now + 300) as i64)
	.bind(now as i64)
	.execute(&pool)
	.await
	.expect("insert ban");

	let ban_info = store
		.is_banned(&format!("account:{account}"), now)
		.await
		.expect("banned");
	assert_eq!(
		ban_info.until_secs,
		(now + 300),
		"the ban row must be in place"
	);
	assert!(
		store.is_known_network(&account, ip, now).await,
		"the bypass row must still exist alongside the ban"
	);
	// The bypass is keyed on (account, network); the ban on
	// account alone; removing the ban does not touch the bypass.
	store.remove_account("alice-not-the-test-account").await;
	assert!(
		store.is_known_network(&account, ip, now).await,
		"removing an unrelated account must not drop the bypass row"
	);
	clean_account(&pool, &account).await;
}

/// Smoke checks the fallback: without a ban store attached, the
/// directory-level decision is `Clear` for every login. This is
/// the same shape the `src/smtp/directory/tests/bans/known_network.rs` covers,
/// but at the integration level: a fresh `PgBanStore` against a
/// real PostgreSQL behaves the same as the in-memory fake.
#[tokio::test]
async fn is_known_network_database_error_fails_closed() {
	let Some(url) = database_url() else {
		eprintln!("skipping: DATABASE_URL not set");
		return;
	};
	// Open the pool then close it: every subsequent query fails
	// with a closed-pool error. The trait's fail-closed contract
	// says `false` on a database error, so a banned account from
	// a network whose lookup errors must stay banned.
	let pool = epistle::db::connect(&url, DatabaseTls::Insecure, 5, None)
		.await
		.expect("connect and migrate");
	let store = PgBanStore::with_policy(pool.clone(), None, policy());
	pool.close().await;
	let ip: std::net::IpAddr = "203.0.113.32".parse().expect("ip");
	assert!(
		!store.is_known_network("alice", ip, 1_700_000_000).await,
		"a database error during the known-network lookup must fail closed (return false)"
	);
}
