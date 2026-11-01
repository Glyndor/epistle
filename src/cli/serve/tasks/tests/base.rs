//! Tests for `spawn_dkim_rotation` and the pure `decide_dkim_rotation`
//! policy it consumes.
//!
//! In a sibling file (not inline) because `src/cli/serve/tasks/mod.rs` is already at
//! the per-file line ceiling for the production code it carries.

use tracing::Level;

use super::super::super::super::trace::capture::run_with_capture;
use super::connect_database;
use super::dkim_rotation::{DkimRotationPlan, decide_dkim_rotation};
use crate::config::Config;

/// Minimal valid base config — `hostname` + `data_dir` are the only
/// unconditionally-required keys. The other sections are added per test.
const BASE: &str = r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
"#;

fn parse(toml: &str) -> Config {
	toml::from_str(toml).expect("parse config")
}

#[test]
fn rotation_runs_when_dns_is_present_without_rotate_days() {
	// [dkim] + [dns], no rotate_days: rotation runs with the constant
	// interval/overlap and no deprecation flag. The expected values are
	// spelled out in days and converted here so a constant change shows
	// up as a failing test.
	let config = parse(&format!(
		"{BASE}
[dkim]
selector = \"mail\"
key_file = \"/etc/mail/dkim.pem\"

[dns]
provider = \"cloudflare\"
zone = \"example.org\"
token = \"abc\"
"
	));
	assert_eq!(
		decide_dkim_rotation(&config),
		DkimRotationPlan::Run {
			interval: 90 * 86_400,
			overlap: 14 * 86_400,
			deprecated_fields_present: false,
			signing_domains: Vec::new(),
			out_of_zone: Vec::new(),
		}
	);
}

#[test]
fn rotation_runs_with_constants_when_legacy_fields_are_set() {
	// The legacy `rotate_days` / `rotate_overlap_days` values are captured
	// for backward compatibility but ignored: the effective timing comes
	// from the constants (not from the file), and the deprecation flag is
	// set. The file deliberately carries different values so a test that
	// leaked the file's values would fail loudly.
	let config = parse(&format!(
		"{BASE}
[dkim]
selector = \"mail\"
key_file = \"/etc/mail/dkim.pem\"
rotate_days = 7
rotate_overlap_days = 3

[dns]
provider = \"cloudflare\"
zone = \"example.org\"
token = \"abc\"
"
	));
	assert_eq!(
		decide_dkim_rotation(&config),
		DkimRotationPlan::Run {
			interval: 90 * 86_400,
			overlap: 14 * 86_400,
			deprecated_fields_present: true,
			signing_domains: Vec::new(),
			out_of_zone: Vec::new(),
		}
	);
}

#[test]
fn rotation_is_off_without_dns_and_logs_inactive_notice() {
	let config = parse(&format!(
		"{BASE}
[dkim]
selector = \"mail\"
key_file = \"/etc/mail/dkim.pem\"
"
	));
	assert_eq!(decide_dkim_rotation(&config), DkimRotationPlan::Off);

	// The caller (`spawn_dkim_rotation`) must leave a record at startup.
	// We exercise it directly so the log emission is captured.
	let events = run_with_capture(|| {
		super::spawn_dkim_rotation(&config, &None, None);
	});
	let notice = events
		.iter()
		.find(|e| e.level == Level::INFO)
		.expect("expected an inactivity notice when [dkim] is set but [dns] is not");
	let msg = notice
		.fields
		.get("message")
		.expect("message field")
		.as_str();
	assert!(
		msg.contains("rotation is inactive"),
		"inactive notice must explain why: {msg}"
	);
	assert!(
		msg.contains("[dns]"),
		"inactive notice must point at the missing [dns] section: {msg}"
	);
}

#[test]
fn spawn_dkim_rotation_warns_when_legacy_rotation_fields_are_set() {
	let config = parse(&format!(
		"{BASE}
[dkim]
selector = \"mail\"
key_file = \"/etc/mail/dkim.pem\"
rotate_days = 30

[dns]
provider = \"cloudflare\"
zone = \"example.org\"
token = \"abc\"
"
	));
	assert!(!config.dns.is_empty(), "test fixture must include [dns]");

	let events = run_with_capture(|| {
		super::spawn_dkim_rotation(&config, &None, None);
	});
	let warning = events
		.iter()
		.find(|e| e.level == Level::WARN)
		.expect("expected a deprecation warning for rotate_days");
	let msg = warning
		.fields
		.get("message")
		.expect("message field")
		.as_str();
	assert!(
		msg.contains("deprecated"),
		"warning must say the field is deprecated: {msg}"
	);
	// The effective values are spelled out so operators can confirm what
	// actually happens without reading the source.
	assert!(
		msg.contains(&format!("every {} days", crate::dkim::ROTATE_INTERVAL_DAYS)),
		"warning must state the effective interval: {msg}"
	);
	assert!(
		msg.contains(&format!("{} day overlap", crate::dkim::ROTATE_OVERLAP_DAYS)),
		"warning must state the effective overlap: {msg}"
	);
	// Structured fields are present too: useful for log search.
	assert_eq!(
		warning.fields.get("interval_days").map(String::as_str),
		Some("90")
	);
	assert_eq!(
		warning.fields.get("overlap_days").map(String::as_str),
		Some("14")
	);
}

#[test]
fn spawn_dkim_rotation_silent_when_legacy_fields_absent_and_dns_present() {
	// No legacy fields, [dns] is present: nothing deprecation-related is
	// logged (the rotation itself does spawn, but its first tick is on the
	// next hour and we don't wait for it here).
	let config = parse(&format!(
		"{BASE}
[dkim]
selector = \"mail\"
key_file = \"/etc/mail/dkim.pem\"

[dns]
provider = \"cloudflare\"
zone = \"example.org\"
token = \"abc\"
"
	));
	let events = run_with_capture(|| {
		super::spawn_dkim_rotation(&config, &None, None);
	});
	assert!(
		!events.iter().any(|e| e.level == Level::WARN),
		"clean config must not log a deprecation warning: {events:?}"
	);
	assert!(
		!events.iter().any(|e| e.level == Level::INFO),
		"clean config must not log the inactive notice: {events:?}"
	);
}

#[test]
fn rotation_is_off_when_dkim_section_is_absent() {
	// No [dkim]: there is nothing to rotate. This is intentionally silent
	// — the absence of [dkim] is visible from the surrounding config.
	let config = parse(BASE);
	assert_eq!(decide_dkim_rotation(&config), DkimRotationPlan::Off);

	let events = run_with_capture(|| {
		super::spawn_dkim_rotation(&config, &None, None);
	});
	assert!(
		events.is_empty(),
		"absent [dkim] must not log anything (the operator chose it): {events:?}"
	);
}

#[test]
fn rotation_partitions_domains_into_in_zone_and_out_of_zone() {
	// The decision must compute the set the rotator will publish for and
	// the set the operator has to fix. Both lists are sorted and deduped
	// (the helper builds a BTreeSet under the hood) so the assert can
	// compare exact contents without worrying about iteration order.
	let config = parse(&format!(
		"{BASE}
domains = [\"example.org\", \"mail.example.org\", \"other.example.net\"]
[domain_aliases]
\"alias.example.org\" = \"example.org\"

[dkim]
selector = \"mail\"
key_file = \"/etc/mail/dkim.pem\"

[dns]
provider = \"cloudflare\"
zone = \"example.org\"
token = \"abc\"
"
	));
	let plan = decide_dkim_rotation(&config);
	let DkimRotationPlan::Run {
		signing_domains,
		out_of_zone,
		..
	} = plan
	else {
		panic!("expected Run, got {plan:?}");
	};
	assert_eq!(
		signing_domains,
		vec![
			"alias.example.org".to_string(),
			"example.org".to_string(),
			"mail.example.org".to_string(),
		],
		"every domain inside the zone must be marked for publication"
	);
	assert_eq!(
		out_of_zone,
		vec!["other.example.net".to_string()],
		"domains outside the zone must be reported separately"
	);
}

#[test]
fn spawn_dkim_rotation_warns_and_skips_when_a_signing_domain_is_out_of_zone() {
	let config = parse(&format!(
		"{BASE}
domains = [\"example.org\", \"other.example.net\"]

[dkim]
selector = \"mail\"
key_file = \"/etc/mail/dkim.pem\"

[dns]
provider = \"cloudflare\"
zone = \"example.org\"
token = \"abc\"
"
	));
	let events = run_with_capture(|| {
		super::spawn_dkim_rotation(&config, &None, None);
	});
	let warning = events
		.iter()
		.find(|e| e.level == Level::WARN)
		.expect("expected an out-of-zone warning");
	let msg = warning
		.fields
		.get("message")
		.expect("message field")
		.as_str();
	assert!(
		msg.contains("rotation is disabled"),
		"warning must say rotation is disabled: {msg}"
	);
	assert!(
		msg.contains("[dns] zone"),
		"warning must point the operator at the [dns] zone field: {msg}"
	);
	let out_of_zone = warning
		.fields
		.get("out_of_zone")
		.expect("structured out_of_zone field")
		.as_str();
	assert!(
		out_of_zone.contains("other.example.net"),
		"structured field must name the offending domain: {out_of_zone}"
	);
	assert_eq!(
		warning.fields.get("zone").map(String::as_str),
		Some("example.org"),
		"structured field must echo the [dns] zone for context"
	);
}

#[test]
fn spawn_dkim_rotation_skips_silently_when_no_domains_are_configured() {
	// Empty [domains] and no aliases: there is nothing to publish, so the
	// out-of-zone path does not fire either. The startup log stays empty
	// (rotation runs on an empty set without ceremony).
	let config = parse(&format!(
		"{BASE}
[dkim]
selector = \"mail\"
key_file = \"/etc/mail/dkim.pem\"

[dns]
provider = \"cloudflare\"
zone = \"example.org\"
token = \"abc\"
"
	));
	let plan = decide_dkim_rotation(&config);
	let DkimRotationPlan::Run {
		signing_domains,
		out_of_zone,
		..
	} = plan
	else {
		panic!("expected Run, got {plan:?}");
	};
	assert!(signing_domains.is_empty());
	assert!(out_of_zone.is_empty());
	let events = run_with_capture(|| {
		super::spawn_dkim_rotation(&config, &None, None);
	});
	assert!(
		!events.iter().any(|e| e.level == Level::WARN),
		"empty domain list must not log an out-of-zone warning: {events:?}"
	);
}

// --- database startup -----------------------------------------------------

/// A minimal config with a `[database]` section pointing at a host that cannot
/// resolve, so `connect_database` always takes a failure branch.
fn config_with_unreachable_database(directory: bool) -> Config {
	let toml = format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"/tmp\"\n\n\
		 [database]\nurl = \"postgres://mail@db.invalid/mail\"\ndirectory = {directory}\n"
	);
	toml::from_str(&toml).expect("config")
}

#[tokio::test]
async fn no_database_section_yields_no_pool() {
	let config: Config =
		toml::from_str("hostname = \"mail.example.org\"\ndata_dir = \"/tmp\"\n").expect("config");
	let metrics = crate::metrics::Metrics::new();
	let pool = connect_database(&config, &metrics)
		.await
		.expect("no database is not an error");
	assert!(pool.is_none());
	assert_eq!(metrics.snapshot().get("database_unavailable"), Some(&0));
}

#[tokio::test]
async fn unreachable_database_without_directory_starts_and_counts() {
	let config = config_with_unreachable_database(false);
	let metrics = crate::metrics::Metrics::new();
	let pool = connect_database(&config, &metrics)
		.await
		.expect("an antispam-only database must not stop the start");
	// Degraded: no pool, so every consumer sees the same shape as no database.
	assert!(pool.is_none());
	// The warning alone is not an alert; the counter is what the alert engine reads.
	assert_eq!(metrics.snapshot().get("database_unavailable"), Some(&1));
	assert!(
		metrics
			.render()
			.contains("mail_database_unavailable_total 1\n"),
		"{}",
		metrics.render()
	);
}

#[tokio::test]
async fn unreachable_database_with_directory_is_fatal_and_says_why() {
	let config = config_with_unreachable_database(true);
	let metrics = crate::metrics::Metrics::new();
	let error = connect_database(&config, &metrics)
		.await
		.expect_err("the SQL directory cannot degrade");
	let message = error.to_string();
	// The operator has to be able to tell this fatal case from the degraded one.
	assert!(message.contains("directory = true"), "{message}");
	assert!(
		message.contains("accounts are resolved from it"),
		"{message}"
	);
	assert!(message.contains("fatal for that reason only"), "{message}");
	// A fatal start is not a degradation, so it must not fire the advisory counter.
	assert_eq!(metrics.snapshot().get("database_unavailable"), Some(&0));
}

// --- single-signature DKIM startup warning ------------------------------

#[test]
fn single_signature_dkim_warning_is_none_without_a_dkim_section() {
	let config = parse(BASE);
	assert!(
		super::single_signature_dkim_warning(&config).is_none(),
		"missing [dkim] must not warn (an unsigned server is a different finding)"
	);
}

#[test]
fn single_signature_dkim_warning_uses_the_dkim_method_text() {
	// The helper is the one shared text source for serve / config-check /
	// verify-dns. Drift between the three call sites is exactly what this
	// test is supposed to catch: the helper forwards what `Dkim` says.
	let config = parse(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"

[dkim]
selector = "mail"
key_file = "/etc/mail/dkim.pem"
"#,
	);
	let warning = super::single_signature_dkim_warning(&config)
		.expect("missing RSA must surface a startup warning");
	assert!(
		warning.contains("signs with one key only"),
		"warning must reuse the wording the Dkim method produces: {warning}"
	);
	assert!(
		warning.contains("dkim-keygen --rsa"),
		"warning must point at the remedy command: {warning}"
	);
	assert!(
		warning.contains(crate::config::DKIM_RSA_REQUIRED_FROM),
		"warning must name the version that flips to refusal: {warning}"
	);
}

#[test]
fn single_signature_dkim_warning_is_none_when_both_rsa_fields_are_set() {
	let config = parse(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"

[dkim]
selector = "mail"
key_file = "/etc/mail/dkim.pem"
rsa_selector = "rsa1"
rsa_key_file = "/etc/mail/rsa.pem"
"#,
	);
	assert!(
		super::single_signature_dkim_warning(&config).is_none(),
		"both RSA fields set: helper must stay silent so the call sites do too"
	);
}

// --- ban sweep honours the operator's known-network window --------------

async fn seed_known_network_row(
	pool: &sqlx::PgPool,
	account: &str,
	network: &str,
	last_seen_secs: i64,
) {
	sqlx::query("INSERT INTO auth_known_network (account, network, last_seen, updated_at) VALUES ($1, $2, $3, to_timestamp($3))")
		.bind(account).bind(network).bind(last_seen_secs)
		.execute(pool).await.expect("insert auth_known_network row");
}

async fn known_networks_for(pool: &sqlx::PgPool, account: &str) -> Vec<String> {
	sqlx::query_scalar(
		"SELECT network::text FROM auth_known_network WHERE account = $1 ORDER BY last_seen DESC",
	)
	.bind(account)
	.fetch_all(pool)
	.await
	.expect("query auth_known_network")
}

/// The hourly sweeper that purges `auth_known_network` reads its window
/// from the operator's `[limits] known-network-window`. The previous
/// wiring built the sweep store with `BanPolicy::default()`, so a row at
/// `now - 8 days` survived a 7-day window until the 30-day default took
/// it; the inverse (`60-day` window, `now - 45 days`) was over-purged.
/// This test pins both directions against a live PostgreSQL so a future
/// revert of the wiring fails by assertion, not by compile error.
///
/// Skipped without `DATABASE_URL` (the same gating the rest of the live
/// database suite uses; the `Database` CI workflow sets it).
#[tokio::test]
async fn run_ban_sweep_once_uses_the_configured_known_network_window() {
	let Some(url) = std::env::var("DATABASE_URL").ok().filter(|u| !u.is_empty()) else {
		eprintln!("skipping: DATABASE_URL not set");
		return;
	};
	let pool = crate::db::connect(&url, crate::config::DatabaseTls::Insecure, 5, None)
		.await
		.expect("connect and migrate");
	let now: u64 = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0);
	const DAY: i64 = 24 * 60 * 60;

	// First direction: the operator sets a 7-day window and a row at
	// `now - 8 days` falls outside it; the sweep must drop it. With the
	// pre-fix wiring (default 30-day window) the row survives, so this
	// assertion is what catches a revert. Two networks because the
	// primary key on `auth_known_network` is `(account, network)`.
	let account_short = format!("alice-{}", uuid::Uuid::now_v7());
	seed_known_network_row(
		&pool,
		&account_short,
		"203.0.113.50",
		(now as i64) - 8 * DAY,
	)
	.await;
	seed_known_network_row(
		&pool,
		&account_short,
		"203.0.113.51",
		(now as i64) - 2 * DAY,
	)
	.await;
	super::run_ban_sweep_once(&pool, 7 * DAY as u64, now).await;
	let present_short = known_networks_for(&pool, &account_short).await;
	assert_eq!(
		present_short.len(),
		1,
		"a 7-day window must drop the `now - 8 days` row and keep the `now - 2 days` one; pre-fix scaffold returned all rows"
	);
	assert_eq!(
		present_short.first().map(String::as_str),
		Some("203.0.113.51"),
		"the survivor must be the row inside the window"
	);

	// Second direction: the operator sets a 60-day window and a row at
	// `now - 45 days` is inside it; the sweep must keep it. With the
	// pre-fix wiring (default 30-day window) the row is purged, which is
	// what this assertion catches. Two networks again because of the
	// primary key.
	let account_long = format!("alice-{}", uuid::Uuid::now_v7());
	seed_known_network_row(
		&pool,
		&account_long,
		"203.0.113.52",
		(now as i64) - 45 * DAY,
	)
	.await;
	seed_known_network_row(
		&pool,
		&account_long,
		"203.0.113.53",
		(now as i64) - 90 * DAY,
	)
	.await;
	super::run_ban_sweep_once(&pool, 60 * DAY as u64, now).await;
	let present_long = known_networks_for(&pool, &account_long).await;
	assert_eq!(
		present_long.len(),
		1,
		"a 60-day window must keep the `now - 45 days` row and drop the `now - 90 days` one; pre-fix scaffold dropped both"
	);
	assert_eq!(
		present_long.first().map(String::as_str),
		Some("203.0.113.52"),
		"the survivor must be the row inside the 60-day window"
	);

	sqlx::query("DELETE FROM auth_known_network WHERE account IN ($1, $2)")
		.bind(&account_short)
		.bind(&account_long)
		.execute(&pool)
		.await
		.expect("cleanup");
}
