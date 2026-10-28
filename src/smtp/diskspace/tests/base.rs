use super::*;

use crate::smtp::session::MAX_MESSAGE_SIZE;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Build a guard backed by a counting probe. The probe returns the bytes
/// the closure yields (or `None` to simulate a syscall failure).
fn guard_with_probe(probe: impl Fn() -> Option<u64> + Send + Sync + 'static) -> DiskGuard {
	DiskGuard::with_probe(std::path::PathBuf::from("/tmp"), Arc::new(probe))
}

#[test]
fn rejects_when_free_space_below_threshold() {
	let calls = Arc::new(AtomicUsize::new(0));
	let probe_calls = Arc::clone(&calls);
	let guard = guard_with_probe(move || {
		probe_calls.fetch_add(1, Ordering::Relaxed);
		Some(1024)
	});
	assert!(!guard.has_room(2048));
	assert_eq!(calls.load(Ordering::Relaxed), 1);
}

#[test]
fn accepts_when_free_space_at_or_above_threshold() {
	let guard = guard_with_probe(|| Some(MAX_MESSAGE_SIZE as u64));
	assert!(guard.has_room(MAX_MESSAGE_SIZE as u64));
	let guard = guard_with_probe(|| Some(MAX_MESSAGE_SIZE as u64 * 2));
	assert!(guard.has_room(MAX_MESSAGE_SIZE as u64));
}

#[test]
fn cache_reuses_sample_within_ttl() {
	let calls = Arc::new(AtomicUsize::new(0));
	let probe_calls = Arc::clone(&calls);
	let guard = guard_with_probe(move || {
		probe_calls.fetch_add(1, Ordering::Relaxed);
		Some(MAX_MESSAGE_SIZE as u64)
	});
	// Three calls inside one TTL window share the first sample.
	assert!(guard.has_room(1));
	assert!(guard.has_room(1));
	assert!(guard.has_room(1));
	assert_eq!(calls.load(Ordering::Relaxed), 1);
}

#[test]
fn probe_failure_fails_open() {
	// A probe that returns None (the equivalent of statvfs erroring) must
	// not turn into a hard reject; the downstream write surfaces the real
	// problem if it persists.
	let guard = guard_with_probe(|| None);
	assert!(guard.has_room(MAX_MESSAGE_SIZE as u64));
	assert!(guard.has_room(u64::MAX));
}

#[test]
fn default_probe_reads_real_filesystem() {
	// `/tmp` is a real directory on every Unix host this project builds on.
	// Its free space is whatever it is today; the only invariant is that
	// the call returns `Some(_)` and is non-zero.
	let probe = DiskGuard::new(std::path::PathBuf::from("/tmp"));
	let sample = probe.refresh();
	assert!(sample.is_some(), "statvfs(/tmp) should succeed");
	assert!(sample.unwrap() > 0, "free space should be positive");
}
