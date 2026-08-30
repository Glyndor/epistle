//! `MAIL FROM` rejects with `452` when the data filesystem is too full to
//! hold another message, and accepts when there is room. The disk-space
//! guard is injected so the tests do not have to fill a real filesystem.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::tests_basic::*;
use super::*;

/// A guard whose probe yields `bytes` free bytes on every call and counts
/// how many times the probe ran.
fn counting_guard(bytes: u64) -> (Arc<DiskGuard>, Arc<AtomicUsize>) {
	let calls = Arc::new(AtomicUsize::new(0));
	let count = Arc::clone(&calls);
	let probe: super::super::diskspace::ProbeFn = Arc::new(move || {
		count.fetch_add(1, Ordering::Relaxed);
		Some(bytes)
	});
	(
		Arc::new(DiskGuard::with_probe(
			std::path::PathBuf::from("/tmp"),
			probe,
		)),
		calls,
	)
}

#[test]
fn mail_from_accepts_when_disk_has_room() {
	let (guard, calls) = counting_guard(MAX_MESSAGE_SIZE as u64 * 2);
	let mut session = greeted().with_disk_guard(guard);
	let action = session.command_line("MAIL FROM:<a@example.org>");
	assert_eq!(reply_code(&action), 250);
	// One probe at MAIL FROM; the cache then absorbs any follow-up calls
	// within the TTL window.
	assert_eq!(calls.load(Ordering::Relaxed), 1);
}

#[test]
fn mail_from_rejects_with_452_when_disk_is_full() {
	let (guard, _) = counting_guard(MAX_MESSAGE_SIZE as u64 / 2);
	let mut session = greeted().with_disk_guard(guard);
	let action = session.command_line("MAIL FROM:<a@example.org>");
	assert_eq!(reply_code(&action), 452);
	// The rejection keeps the session in `Connected` so the next MAIL FROM
	// can be tried without an RSET, matching the existing MAIL FROM error
	// handling.
	let after = session.command_line("RCPT TO:<b@example.org>");
	assert_eq!(reply_code(&after), 503);
}

#[test]
fn mail_from_does_not_poll_filesystem_twice_within_ttl() {
	let (guard, calls) = counting_guard(MAX_MESSAGE_SIZE as u64 * 2);
	let mut session = greeted().with_disk_guard(Arc::clone(&guard));
	session.command_line("MAIL FROM:<a@example.org>");
	session.command_line("RSET");
	session.command_line("MAIL FROM:<c@example.org>");
	session.command_line("RSET");
	session.command_line("MAIL FROM:<d@example.org>");
	// Three MAIL FROM commands inside the cache window must share one
	// sample; the second and third hit the cache instead of re-probing.
	assert_eq!(calls.load(Ordering::Relaxed), 1);
}

#[test]
fn mail_from_probe_failure_accepts() {
	// A probe that errors out fails open: the alternative is a hard reject
	// loop that masks the real problem. The downstream spool write will
	// surface `ENOSPC` if the low space is genuine.
	let probe: super::super::diskspace::ProbeFn = Arc::new(|| None);
	let guard = Arc::new(DiskGuard::with_probe(
		std::path::PathBuf::from("/tmp"),
		probe,
	));
	let mut session = greeted().with_disk_guard(guard);
	let action = session.command_line("MAIL FROM:<a@example.org>");
	assert_eq!(reply_code(&action), 250);
}
