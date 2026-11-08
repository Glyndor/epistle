//! A burst of wrong passwords cannot be verified more times than the ban
//! allows, whatever the width of the password gate, and a success whose check
//! was in flight when a ban was armed cannot lift that ban.
//!
//! The ban check and the strike are separated by the password hash. Without
//! something holding them together, every guess of a burst passes the check
//! before the first strike lands, so a burst as wide as the gate is verified
//! in full and the strikes pile up behind the ban (each one past the limit
//! also escalates the next ban).

use std::net::IpAddr;
use std::sync::{Arc, Barrier};

use super::Directory;
use super::gate_fixture::*;
use crate::antispam::bans::tests::base::FakeBanStore;
use crate::antispam::bans::{self, BanInfo, BanPolicy, BanStore};
use crate::config::Protocol;
use crate::smtp::directory::hash_gate::{HashGate, Verdict};
use crate::test_fixtures as fixtures;

/// A gate wide enough to let the whole burst hash at the same moment, with no
/// limit on the line: the width of the gate must not be what bounds the guesses.
const WIDE: usize = 64;

const PROTOCOLS: [Protocol; 6] = [
	Protocol::Submission,
	Protocol::Submissions,
	Protocol::Imaps,
	Protocol::Pop3s,
	Protocol::ManageSieve,
	Protocol::WebDav,
];

fn ip(text: &str) -> Option<IpAddr> {
	Some(text.parse().expect("address"))
}

fn setup() -> (Arc<Directory>, FakeBanStore) {
	let store = FakeBanStore::new(BanPolicy::default());
	let directory = gate_directory()
		.with_ban_store(Arc::new(store.clone()))
		.with_hash_gate(Arc::new(HashGate::new(WIDE, usize::MAX)));
	(Arc::new(directory), store)
}

/// One wrong password per entry, all released together from a barrier, each on
/// its own thread. Every verdict must be a plain refusal.
async fn burst(directory: &Arc<Directory>, attempts: Vec<(Protocol, String, Option<IpAddr>)>) {
	let start = Arc::new(Barrier::new(attempts.len()));
	let tasks: Vec<_> = attempts
		.into_iter()
		.map(|(protocol, login, from)| {
			let (directory, start) = (Arc::clone(directory), Arc::clone(&start));
			tokio::task::spawn_blocking(move || {
				start.wait();
				directory.authenticate_verdict(&login, fixtures::wrong_password(), from, protocol)
			})
		})
		.collect();
	for task in tasks {
		assert_eq!(
			task.await.expect("guess task"),
			Verdict::Refused,
			"a wrong password is refused, never turned away as busy"
		);
	}
}

fn now() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.expect("clock")
		.as_secs()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_burst_from_one_client_over_every_listener_is_verified_up_to_the_threshold_only() {
	let (directory, store) = setup();
	let client = ip("203.0.113.7");
	let attempts = (0..24)
		.map(|n| (PROTOCOLS[n % PROTOCOLS.len()], OPEN.to_string(), client))
		.collect();
	burst(&directory, attempts).await;
	for (n, subject) in [
		bans::subject_client(client.expect("ip")),
		bans::subject_pair(OPEN, client),
		bans::subject_account(OPEN),
	]
	.into_iter()
	.enumerate()
	{
		assert_eq!(
			store.failure_count(&subject, 0),
			5,
			"subject {n}: five guesses were verified, the other nineteen met the ban"
		);
	}
	let ban = store
		.is_banned(&bans::subject_client(client.expect("ip")), now())
		.await
		.expect("the client is banned");
	assert!(
		ban.until_secs <= now() + BanPolicy::default().base_secs,
		"one ban of the first length, not an escalated one: {ban:?}"
	);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_burst_rotating_over_accounts_from_one_client_is_counted_on_the_client() {
	let (directory, store) = setup();
	let client = ip("203.0.113.8");
	let logins = [OPEN, TWO_FACTOR, DISABLED, "ghost"];
	let attempts = (0..24)
		.map(|n| {
			(
				Protocol::Imaps,
				logins[n % logins.len()].to_string(),
				client,
			)
		})
		.collect();
	burst(&directory, attempts).await;
	assert_eq!(
		store.failure_count(&bans::subject_client(client.expect("ip")), 0),
		5,
		"the client stops at its limit however many accounts it rotates over"
	);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_burst_rotating_inside_an_ipv6_slash_64_is_one_client() {
	let (directory, store) = setup();
	let attempts = (0..24)
		.map(|n| {
			let from = ip(&format!("2001:db8:5:6:{n:x}::{n:x}"));
			(PROTOCOLS[n % PROTOCOLS.len()], OPEN.to_string(), from)
		})
		.collect();
	burst(&directory, attempts).await;
	let slash_64 = bans::subject_client("2001:db8:5:6::1".parse().expect("address"));
	assert_eq!(store.failure_count(&slash_64, 0), 5);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_burst_from_many_clients_stops_at_the_account_limit() {
	let (directory, store) = setup();
	let attempts = (1..=40u8)
		.map(|n| {
			let from = ip(&format!("198.51.100.{n}"));
			(
				PROTOCOLS[usize::from(n) % PROTOCOLS.len()],
				OPEN.to_string(),
				from,
			)
		})
		.collect();
	burst(&directory, attempts).await;
	let limit = BanPolicy::default().threshold_for(&bans::subject_account(OPEN)) as usize;
	assert_eq!(limit, 20);
	assert_eq!(
		store.failure_count(&bans::subject_account(OPEN), 0),
		limit,
		"forty clients with one guess each: the account is verified up to its own limit"
	);
}

/// A store that behaves as the fake and, right after it answers "not banned"
/// to the sixth ban question (the second look the directory takes at the
/// account, just before it hashes), arms a ban on the pair and the account
/// the way a concurrent burst of failures would.
#[derive(Debug)]
struct ArmsInFlight {
	inner: FakeBanStore,
	questions: std::sync::atomic::AtomicUsize,
	subjects: [String; 2],
}

type Fut<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

impl BanStore for ArmsInFlight {
	fn record_failure(&self, subject: &str, protocol: &str, now_secs: u64) -> Fut<'_, ()> {
		self.inner.record_failure(subject, protocol, now_secs)
	}

	fn is_banned(&self, subject: &str, now_secs: u64) -> Fut<'_, Option<BanInfo>> {
		let subject = subject.to_string();
		let nth = self
			.questions
			.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
			+ 1;
		Box::pin(async move {
			let answer = self.inner.is_banned(&subject, now_secs).await;
			if nth == 6 {
				for armed in &self.subjects {
					self.inner.arm_ban(
						armed,
						BanInfo {
							until_secs: now_secs + 900,
							reason: "armed in flight".to_string(),
						},
					);
				}
			}
			answer
		})
	}

	fn clear_success(&self, subject: &str, now_secs: u64) -> Fut<'_, ()> {
		self.inner.clear_success(subject, now_secs)
	}

	fn sweep(&self, now_secs: u64) -> Fut<'_, ()> {
		self.inner.sweep(now_secs)
	}

	fn remove_account(&self, account: &str) -> Fut<'_, ()> {
		self.inner.remove_account(account)
	}

	fn record_known_network(&self, account: &str, ip: IpAddr, now_secs: u64) -> Fut<'_, ()> {
		self.inner.record_known_network(account, ip, now_secs)
	}
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_success_whose_check_was_in_flight_when_a_ban_was_armed_does_not_lift_it() {
	let owner_ip = ip("203.0.113.9");
	let subjects = [
		bans::subject_pair(OPEN, owner_ip),
		bans::subject_account(OPEN),
	];
	let inner = FakeBanStore::new(BanPolicy::default());
	// History a careless clear would wipe: four failures behind each subject.
	for subject in &subjects {
		for _ in 0..4 {
			inner.record_failure(subject, "imaps", now()).await;
		}
	}
	let store = Arc::new(ArmsInFlight {
		inner: inner.clone(),
		questions: std::sync::atomic::AtomicUsize::new(0),
		subjects: subjects.clone(),
	});
	let directory = gate_directory().with_ban_store(store.clone());
	let verdict = tokio::task::spawn_blocking(move || {
		directory.authenticate_verdict(OPEN, fixtures::password(), owner_ip, Protocol::Imaps)
	})
	.await
	.expect("sign-in task");
	assert!(
		store.questions.load(std::sync::atomic::Ordering::SeqCst) >= 6,
		"the sign-in asked twice, so the ban was armed between the check and the outcome"
	);
	assert!(
		matches!(verdict, Verdict::Admitted { .. }),
		"the check that began before the ban still decides on its own proof"
	);
	for (n, subject) in subjects.iter().enumerate() {
		assert!(
			inner.is_banned(subject, now()).await.is_some(),
			"subject {n}: the ban armed in flight is still in force after the success"
		);
		assert_eq!(
			inner.failure_count(subject, 0),
			4,
			"subject {n}: and the failures behind it were not wiped"
		);
	}
}
