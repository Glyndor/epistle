//! A right password, or a right app password, on an account that may not sign
//! in through this protocol is refused after the same work as a wrong one:
//! the same password hashes and the same questions and writes to the ban
//! store. Otherwise a quicker refusal would confirm a guess. The same holds
//! for a login with no password of its own (an account that only has app
//! passwords, or lives in a directory the server only binds to).

use std::sync::Arc;

use super::Directory;
use super::decoy_counters::DecoyCounters;
use crate::antispam::bans::BanPolicy;
use crate::antispam::bans::tests::FakeBanStore;
use crate::config::Protocol;
use crate::directory_store::AppPassword;
use crate::test_fixtures as fixtures;

/// Has app passwords and no password of its own.
const NO_PASSWORD: &str = "gina";
/// Signs in through the API only.
const API_ONLY: &str = "dave";
/// The same account without the restriction.
const OPEN_TWIN: &str = "erin";

/// The secret of the second app password of each account.
fn second_app_secret() -> &'static str {
	static VALUE: std::sync::LazyLock<String> = std::sync::LazyLock::new(fixtures::fresh_secret);
	VALUE.as_str()
}

fn app(label: &str, secret: &str) -> AppPassword {
	AppPassword {
		label: label.to_string(),
		hash: crate::smtp::auth::tests::hash(secret),
		expires_at: None,
		ip_cidr: None,
		save_sent: None,
	}
}

/// Two accounts alike in everything but the protocol allowlist, each holding
/// the same two app passwords that open.
fn directory() -> Directory {
	let hash = crate::smtp::auth::tests::hash(fixtures::password());
	Directory::new(
		["example.org".to_string()],
		[
			(format!("{API_ONLY}@example.org"), API_ONLY.to_string()),
			(format!("{OPEN_TWIN}@example.org"), OPEN_TWIN.to_string()),
			(
				format!("{NO_PASSWORD}@example.org"),
				NO_PASSWORD.to_string(),
			),
		],
	)
	.with_password_hashes([API_ONLY, OPEN_TWIN].map(|name| (name.to_string(), hash.clone())))
	.with_app_passwords(
		[API_ONLY, OPEN_TWIN, NO_PASSWORD]
			.into_iter()
			.flat_map(|name| {
				[
					(name.to_string(), app("first", fixtures::second_password())),
					(name.to_string(), app("second", second_app_secret())),
				]
			}),
	)
	.with_allowed_protocols([(API_ONLY.to_string(), vec![Protocol::Api])])
}

/// What one attempt cost: password hashes, ban-store questions, ban-store writes.
fn cost_of(login: &str, password: &str) -> ((usize, usize, usize), Option<String>) {
	let store = FakeBanStore::new(BanPolicy::default());
	let counters = Arc::new(DecoyCounters::default());
	let directory = directory()
		.with_ban_store(Arc::new(store.clone()))
		.with_decoy_counters(counters.clone());
	let peer = Some("203.0.113.5".parse().expect("address"));
	let outcome = directory.authenticate_with_ip(login, password, peer, Protocol::Imaps);
	(
		(
			counters.hashes(),
			store.call_count("is_banned"),
			store.call_count("record_failure"),
		),
		outcome,
	)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_right_secret_on_a_refused_protocol_costs_what_a_wrong_password_does() {
	let (wrong, outcome) = cost_of(OPEN_TWIN, fixtures::wrong_password());
	assert_eq!(outcome, None);
	assert_eq!(wrong.0, 3, "the primary password and the two app passwords");
	for (what, login, secret) in [
		("the right password", API_ONLY, fixtures::password()),
		(
			"the first app password",
			API_ONLY,
			fixtures::second_password(),
		),
		("the second app password", API_ONLY, second_app_secret()),
		("a wrong password", API_ONLY, fixtures::wrong_password()),
		(
			"an unknown login",
			"nobody-here",
			fixtures::wrong_password(),
		),
	] {
		let (cost, outcome) = cost_of(login, secret);
		assert_eq!(outcome, None, "{what} on a refused protocol is refused");
		assert_eq!(cost, wrong, "{what}");
	}
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_same_secrets_open_the_account_on_a_protocol_it_allows() {
	for secret in [
		fixtures::password(),
		fixtures::second_password(),
		second_app_secret(),
	] {
		let directory = directory();
		let outcome = directory.authenticate(OPEN_TWIN, secret, Protocol::Imaps);
		assert_eq!(outcome.as_deref(), Some(OPEN_TWIN));
		let api = directory.authenticate(API_ONLY, secret, Protocol::Api);
		assert_eq!(api.as_deref(), Some(API_ONLY));
	}
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_login_without_a_password_of_its_own_is_refused_after_the_same_work() {
	let (wrong, _) = cost_of(OPEN_TWIN, fixtures::wrong_password());
	for login in [NO_PASSWORD, "gina@example.org", "nobody-here"] {
		for secret in [fixtures::wrong_password(), fixtures::second_password()] {
			let (cost, outcome) = cost_of(login, secret);
			assert_eq!(outcome, None, "{login}");
			assert_eq!(cost, wrong, "{login}");
		}
	}
}
