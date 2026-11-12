//! A directory that stalls, lies about a frame or floods results must cost
//! one failed call: an error, little memory, and a bounded wait.

use super::raw::{Script, start};
use super::{DEADLINE, config};
use crate::directory_store::ldap::LdapAuthenticator;
use crate::directory_store::ldap::limits::Limits;
use crate::directory_store::ldap::load_with_limits;
use ldap3::LdapError;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

const ENTRIES: usize = 50;

fn limits() -> Limits {
	Limits {
		timeout: Duration::from_millis(800),
		entries: ENTRIES,
	}
}

type Loaded = Result<Vec<crate::directory_store::LdapAccount>, LdapError>;

/// Run the loader on a detached thread, so that a loader which never returns
/// fails this guard instead of hanging the test, and report the most memory
/// that thread held at once.
async fn load(url: &str) -> (Loaded, usize, Duration) {
	let config = config(url);
	let (tx, rx) = tokio::sync::oneshot::channel();
	let worker = std::thread::spawn(move || {
		let started = Instant::now();
		let (result, peak) = crate::sieve::test_peak_bytes(|| load_with_limits(&config, limits()));
		let _ = tx.send((result, peak, started.elapsed()));
	});
	let outcome = tokio::time::timeout(DEADLINE, rx)
		.await
		.expect("LDAP loader exceeded the deadline")
		.expect("loader thread panicked");
	worker.join().expect("loader thread joined");
	outcome
}

#[tokio::test]
async fn bind_that_never_answers_times_out() {
	let (url, _connections, _peer) = start(Script::SilentBind).await;
	let (result, _, elapsed) = load(&url).await;
	assert!(
		matches!(&result, Err(LdapError::Timeout { .. })),
		"{result:?}"
	);
	assert!(elapsed < DEADLINE, "{elapsed:?}");
}

#[tokio::test]
async fn silent_server_does_not_hold_the_login_worker() {
	let (url, connections, _peer) = start(Script::SilentBind).await;
	let (tx, rx) = tokio::sync::oneshot::channel();
	let worker = std::thread::spawn(move || {
		let auth = LdapAuthenticator::with_limits(config(&url), limits());
		let password = crate::test_fixtures::password();
		// The second login only runs if the first one gave the worker back.
		let first = auth.authenticate("alice", password);
		let second = auth.authenticate("bob", password);
		let _ = tx.send((first, second));
	});
	let outcome = tokio::time::timeout(DEADLINE * 2, rx)
		.await
		.expect("logins exceeded the deadline")
		.expect("login thread panicked");
	worker.join().expect("login thread joined");
	assert_eq!(outcome, (None, None));
	assert_eq!(connections.load(Ordering::SeqCst), 2, "one try per login");
}

#[tokio::test]
async fn truncated_ber_frame_is_an_error() {
	let (url, _connections, _peer) = start(Script::TruncatedBind).await;
	let (result, _, elapsed) = load(&url).await;
	assert!(result.is_err(), "{result:?}");
	assert!(elapsed < DEADLINE, "{elapsed:?}");
}

#[tokio::test]
async fn frame_declaring_four_gib_is_an_error_with_small_memory() {
	let (url, _connections, _peer) = start(Script::HugeBerLength).await;
	let (result, peak, elapsed) = load(&url).await;
	assert!(
		matches!(&result, Err(LdapError::Timeout { .. })),
		"{result:?}"
	);
	assert!(elapsed < DEADLINE, "{elapsed:?}");
	assert!(peak < 4 * 1024 * 1024, "held {peak} bytes for a header");
}

#[tokio::test]
async fn empty_message_envelope_is_an_error() {
	let (url, _connections, _peer) = start(Script::EmptyFrame).await;
	let (result, _, elapsed) = load(&url).await;
	assert!(result.is_err(), "{result:?}");
	assert!(elapsed < DEADLINE, "{elapsed:?}");
}

#[tokio::test]
async fn endless_result_stream_is_refused_at_the_entry_cap() {
	let (url, _connections, _peer) = start(Script::Entries {
		count: 20_000,
		finish: false,
	})
	.await;
	let (result, peak, _) = load(&url).await;
	assert!(
		matches!(&result, Err(LdapError::Io { source })
			if source.to_string().contains("more than 50 entries")),
		"{result:?}"
	);
	assert!(peak < 2 * 1024 * 1024, "held {peak} bytes");
}

/// Positive control: the cap refuses entry 51, not entry 50. Without this the
/// refusal above would be just as green if every search were refused.
#[tokio::test]
async fn results_exactly_at_the_cap_are_loaded() {
	let (url, _connections, _peer) = start(Script::Entries {
		count: ENTRIES,
		finish: true,
	})
	.await;
	let (result, _, _) = load(&url).await;
	let accounts = result.expect("a directory of exactly the cap");
	assert_eq!(accounts.len(), ENTRIES);
}
