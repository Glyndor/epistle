//! What the error guard counts: a client's own errors, and apart from those
//! the replies for messages that cannot be read. A busy server is neither.

use super::*;
use crate::smtp::directory::hash_gate::Verdict;
use base64::Engine;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

struct Probe {
	busy: bool,
}

impl Backend for Probe {
	fn verify(&self, _: &str, _: &str, _: Option<std::net::IpAddr>) -> Option<String> {
		Some("alice".into())
	}
	fn verify_checked(&self, user: &str, pass: &str, ip: Option<std::net::IpAddr>) -> Verdict {
		if self.busy {
			Verdict::Busy
		} else {
			match self.verify(user, pass, ip) {
				Some(account) => Verdict::Admitted {
					account,
					label: None,
				},
				None => Verdict::Refused,
			}
		}
	}
	fn list(&self, _: &str) -> Vec<(String, usize)> {
		vec![("m".into(), 1)]
	}
	fn fetch(&self, _: &str, _: &str) -> Option<Vec<u8>> {
		None
	}
	fn remove(&self, _: &str, _: &[String]) {}
}

/// A backend that refuses every password, so a sign-in never completes.
struct Refusing;

impl Backend for Refusing {
	fn verify(&self, _: &str, _: &str, _: Option<std::net::IpAddr>) -> Option<String> {
		None
	}
	fn list(&self, _: &str) -> Vec<(String, usize)> {
		vec![("m".into(), 1)]
	}
	fn fetch(&self, _: &str, _: &str) -> Option<Vec<u8>> {
		None
	}
	fn remove(&self, _: &str, _: &[String]) {}
}

/// Send `input`, read everything the server says until it closes.
async fn exchange<B: Backend + Send + 'static>(backend: B, input: String) -> String {
	let (mut client, server) = duplex(1 << 20);
	let task = tokio::spawn(run(
		server,
		backend,
		None,
		SessionClock::start(DEFAULT_PREAUTH_TIMEOUT, TIMEOUT),
		None,
	));
	client.write_all(input.as_bytes()).await.expect("write");
	let mut out = Vec::new();
	tokio::time::timeout(Duration::from_secs(10), client.read_to_end(&mut out))
		.await
		.expect("the server never closed")
		.expect("read");
	let _ = task.await;
	String::from_utf8_lossy(&out).to_string()
}

#[tokio::test]
async fn replies_about_a_busy_server_do_not_count_as_client_errors() {
	let attempt = base64::engine::general_purpose::STANDARD.encode("\0alice\0x");
	let mut input = String::new();
	for _ in 0..(MAX_ERROR_STREAK + 10) {
		input.push_str(&format!("AUTH PLAIN {attempt}\r\n"));
	}
	input.push_str("QUIT\r\n");
	let seen = exchange(Probe { busy: true }, input).await;
	assert!(seen.contains("[SYS/TEMP]"), "{seen}");
	assert!(!seen.contains("too many errors"), "{seen}");
	assert!(seen.trim_end().ends_with("+OK bye"), "{seen}");
}

#[tokio::test]
async fn a_message_that_cannot_be_read_does_not_hit_the_client_error_limit() {
	let mut input = String::from("USER alice\r\nPASS x\r\n");
	for _ in 0..(MAX_ERROR_STREAK + 10) {
		input.push_str("RETR 1\r\n");
	}
	input.push_str("QUIT\r\n");
	let seen = exchange(Probe { busy: false }, input).await;
	assert!(seen.contains("[SYS/PERM]"), "{seen}");
	assert!(!seen.contains("too many errors"), "{seen}");
	assert!(seen.trim_end().ends_with("+OK bye"), "{seen}");
}

#[tokio::test]
async fn asking_again_and_again_for_a_message_that_cannot_be_read_ends_the_session() {
	let mut input = String::from("USER alice\r\nPASS x\r\n");
	for _ in 0..(MAX_UNAVAILABLE_STREAK + 5) {
		input.push_str("RETR 1\r\n");
	}
	let seen = exchange(Probe { busy: false }, input).await;
	assert!(seen.trim_end().ends_with("-ERR too many errors"), "{seen}");
	assert_eq!(
		seen.matches("[SYS/PERM]").count(),
		MAX_UNAVAILABLE_STREAK as usize - 1
	);
}

/// A valid `USER` between two failing passwords does not clear the streak:
/// the acceptance of the `USER` is one half of a sign-in the password can
/// still refuse, so the client reaches the cap.
#[tokio::test]
async fn a_valid_user_between_failed_passwords_still_reaches_the_cap() {
	let mut input = String::new();
	for _ in 0..(MAX_ERROR_STREAK + 2) {
		input.push_str("USER alice\r\nPASS wrong\r\n");
	}
	let seen = exchange(Refusing, input).await;
	assert_eq!(
		seen.matches("+OK send PASS").count(),
		MAX_ERROR_STREAK as usize,
		"{seen}"
	);
	assert_eq!(
		seen.matches("-ERR authentication failed").count(),
		MAX_ERROR_STREAK as usize - 1,
		"{seen}"
	);
	assert!(seen.trim_end().ends_with("-ERR too many errors"), "{seen}");
}
