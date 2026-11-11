//! A directory that cannot be asked in time is not a wrong password, and the
//! answer does not depend on whether the login exists. An attempt that cost
//! the directory a connection counts against the client that made it; one
//! that never left the queue counts for nothing.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use super::Directory;
use super::gate_fixture::*;
use crate::antispam::bans::BanPolicy;
use crate::antispam::bans::tests::base::FakeBanStore;
use crate::config::Protocol;
use crate::directory_store::LdapAuthenticator;
use crate::directory_store::ldap::limits::Limits;
use crate::smtp::directory::hash_gate::Verdict;
use crate::test_support::fixtures;

fn ldap_at(port: u16) -> Arc<LdapAuthenticator> {
	let config = toml::from_str(&format!(
		r#"
url = "ldap://127.0.0.1:{port}"
bind_dn = "cn=svc"
bind_password = "p"
base_dn = "dc=example,dc=org"
user_filter = "(uid=%s)"
account_attribute = "uid"
mail_attribute = "mail"
"#
	))
	.expect("parse ldap config");
	Arc::new(LdapAuthenticator::with_queue(
		config,
		Limits {
			timeout: Duration::from_millis(200),
			entries: 1000,
		},
		4,
	))
}

/// A directory that accepts the connection and never says a word.
fn ldap_that_never_answers() -> Arc<LdapAuthenticator> {
	let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
	let port = listener.local_addr().expect("addr").port();
	std::thread::spawn(move || {
		let mut held = Vec::new();
		for stream in listener.incoming() {
			held.push(stream);
		}
	});
	ldap_at(port)
}

/// A directory nothing listens at: the connection is refused.
fn ldap_that_is_down() -> Arc<LdapAuthenticator> {
	let port = std::net::TcpListener::bind("127.0.0.1:0")
		.expect("bind")
		.local_addr()
		.expect("addr")
		.port();
	ldap_at(port)
}

fn directory_with(ldap: Arc<LdapAuthenticator>) -> Directory {
	gate_directory()
		.with_ldap(Some(ldap))
		.with_ban_store(Arc::new(FakeBanStore::new(BanPolicy::default())))
}

const CLIENT: &str = "203.0.113.5";

fn attempt(directory: &Directory, login: &str, password: &str) -> Verdict {
	let ip: IpAddr = CLIENT.parse().expect("address");
	directory.authenticate_verdict(login, password, Some(ip), Protocol::Imaps)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_answer_is_busy_for_every_login_whether_it_exists_or_not() {
	let directory = directory_with(ldap_that_never_answers());
	for login in ["nobody-here", OPEN] {
		assert_eq!(
			attempt(&directory, login, fixtures::wrong_password()),
			Verdict::Busy,
			"{login}"
		);
	}
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn attempts_that_reached_a_silent_directory_ban_the_client() {
	let directory = directory_with(ldap_that_never_answers());
	for _ in 0..5 {
		assert_eq!(
			attempt(&directory, "nobody-here", fixtures::wrong_password()),
			Verdict::Busy
		);
	}
	assert_eq!(
		attempt(&directory, OPEN, fixtures::password()),
		Verdict::Refused,
		"the client that kept the directory waiting is banned, even for a right password"
	);
}

fn rows_after(login: &'static str, silent: bool) -> Vec<(String, usize)> {
	let store = FakeBanStore::new(BanPolicy::default());
	let ldap = if silent {
		ldap_that_never_answers()
	} else {
		ldap_that_is_down()
	};
	let directory = gate_directory()
		.with_ldap(Some(ldap))
		.with_ban_store(Arc::new(store.clone()));
	let verdict = attempt(&directory, login, fixtures::wrong_password());
	assert_eq!(verdict, Verdict::Busy, "{login}");
	store.failure_shape()
}

fn kinds(shape: &[(String, usize)]) -> Vec<&str> {
	shape.iter().map(|(kind, _)| kind.as_str()).collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_local_password_counts_against_account_and_client_in_either_state() {
	for silent in [true, false] {
		assert_eq!(
			kinds(&rows_after(OPEN, silent)),
			["account", "ip", "pair"],
			"reached: {silent}"
		);
	}
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_login_the_directory_could_not_decide_counts_against_the_client_alone() {
	for silent in [true, false] {
		assert_eq!(
			kinds(&rows_after("nobody-here", silent)),
			["ip"],
			"reached: {silent}: an outage must not lock an account out"
		);
	}
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn undecided_attempts_add_up_against_the_client() {
	let directory = directory_with(ldap_that_is_down());
	for _ in 0..5 {
		assert_eq!(
			attempt(&directory, "nobody-here", fixtures::wrong_password()),
			Verdict::Busy
		);
	}
	assert_eq!(
		attempt(&directory, OPEN, fixtures::password()),
		Verdict::Refused,
		"the client is banned: saturating the directory gives it no free attempts"
	);
}

/// Events captured while `work` runs: `(event, fields)` per tracing event.
fn events_during(work: impl FnOnce()) -> Vec<std::collections::HashMap<String, String>> {
	use std::sync::Mutex;
	use tracing::field::{Field, Visit};
	use tracing_subscriber::layer::{Context, SubscriberExt};

	struct Collect(Arc<Mutex<Vec<std::collections::HashMap<String, String>>>>);
	struct Fields<'a>(&'a mut std::collections::HashMap<String, String>);
	impl Visit for Fields<'_> {
		fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
			self.0
				.insert(field.name().to_string(), format!("{value:?}"));
		}
	}
	impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Collect {
		fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
			let mut fields = std::collections::HashMap::new();
			event.record(&mut Fields(&mut fields));
			self.0.lock().unwrap().push(fields);
		}
	}
	crate::cli::trace::capture::keep_callsites_live();
	let seen = Arc::new(Mutex::new(Vec::new()));
	let subscriber = tracing_subscriber::Registry::default().with(Collect(seen.clone()));
	tracing::subscriber::with_default(subscriber, work);
	seen.lock().unwrap().clone()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn auth_busy_is_written_for_every_login_and_login_failed_only_when_one_was_decided() {
	let directory = directory_with(ldap_that_is_down());
	let names_for = |login: &'static str| -> Vec<String> {
		let mut names: Vec<String> = events_during(|| {
			attempt(&directory, login, fixtures::wrong_password());
		})
		.into_iter()
		.filter_map(|fields| fields.get("event").cloned())
		.filter(|event| event.contains("auth."))
		.collect();
		names.sort();
		names
	};
	let known = names_for(OPEN);
	let unknown = names_for("nobody-here");
	assert_eq!(known.len(), 2, "{known:?}");
	assert!(known.iter().any(|name| name.contains("auth.busy")));
	assert!(known.iter().any(|name| name.contains("auth.login_failed")));
	assert_eq!(unknown.len(), 1, "{unknown:?}");
	assert!(unknown[0].contains("auth.busy"));
}
