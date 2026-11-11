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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn attempts_that_never_reached_the_directory_ban_nobody() {
	let directory = directory_with(ldap_that_is_down());
	for _ in 0..6 {
		assert_eq!(
			attempt(&directory, "nobody-here", fixtures::wrong_password()),
			Verdict::Busy
		);
	}
	assert_eq!(
		attempt(&directory, OPEN, fixtures::password()),
		Verdict::Admitted {
			account: OPEN.to_string(),
			label: None
		}
	);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wrong_local_password_counts_even_when_the_directory_is_down() {
	let directory = directory_with(ldap_that_is_down());
	for _ in 0..5 {
		assert_eq!(
			attempt(&directory, OPEN, fixtures::wrong_password()),
			Verdict::Busy
		);
	}
	assert_eq!(
		attempt(&directory, OPEN, fixtures::password()),
		Verdict::Refused,
		"five refused local passwords ban the client, with the directory up or down"
	);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn only_a_checked_credential_is_a_failed_login_in_the_audit_counters() {
	let metrics = Arc::new(crate::metrics::Metrics::new());
	let directory = directory_with(ldap_that_is_down()).with_metrics(metrics.clone());
	let failed = || {
		metrics
			.snapshot()
			.get("auth_login_failed")
			.copied()
			.unwrap_or(0)
	};
	assert_eq!(
		attempt(&directory, "nobody-here", fixtures::wrong_password()),
		Verdict::Busy
	);
	assert_eq!(failed(), 0, "nothing was checked for a login nobody holds");
	assert_eq!(
		attempt(&directory, OPEN, fixtures::wrong_password()),
		Verdict::Busy
	);
	assert_eq!(failed(), 1, "a local password was checked and refused");
}
