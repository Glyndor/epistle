//! Envelope edits shared between the delivery worker and the operator CLI.

use super::*;
use std::sync::Arc;
use std::time::Duration;

fn sample_message() -> AcceptedMessage {
	AcceptedMessage {
		reverse_path: "alice@example.org".into(),
		recipients: vec!["bob@example.org".into()],
		data: b"Subject: hi\r\n\r\nsecret body\r\n".to_vec(),
		require_tls: false,
		mailbox: None,
		tlsrpt_verified: false,
		no_dsn: Vec::new(),
	}
}

fn open_with_entry() -> (tempfile::TempDir, Arc<FsSpool>, Uuid) {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = Arc::new(FsSpool::open(dir.path()).expect("open spool"));
	let id = spool.store(&sample_message()).expect("store");
	(dir, spool, id)
}

#[test]
fn envelope_written_before_the_hold_fields_still_loads() {
	let (dir, spool, id) = open_with_entry();
	let legacy = format!(
		r#"{{"id":"{id}","reverse_path":"a@example.org","recipients":["b@example.org"],"attempts":2,"next_attempt":9}}"#
	);
	fs::write(dir.path().join(format!("spool/new/{id}.json")), legacy).expect("write");
	let envelope = spool.load_envelope(id).expect("load");
	assert_eq!(envelope.attempts, 2);
	assert_eq!(envelope.held, None);
	assert_eq!(envelope.held_secs, 0);
	assert_eq!(envelope.last_error, None);
}

#[test]
fn a_normal_envelope_does_not_serialize_the_hold_fields() {
	let (dir, _spool, id) = open_with_entry();
	let json = fs::read_to_string(dir.path().join(format!("spool/new/{id}.json"))).expect("read");
	assert!(!json.contains("held"), "unexpected hold field in {json}");
	assert!(!json.contains("last_error"), "unexpected field in {json}");
}

#[test]
fn hold_keeps_the_first_start_and_release_accumulates_held_time() {
	let (_dir, spool, id) = open_with_entry();
	spool.update_envelope(id, |e| e.hold(100)).expect("hold");
	let again = spool
		.update_envelope(id, |e| e.hold(500))
		.expect("hold again");
	assert_eq!(again.held, Some(100));
	let released = spool
		.update_envelope(id, |e| e.release(160))
		.expect("release");
	assert_eq!(released.held, None);
	assert_eq!(released.held_secs, 60);
	// Releasing an entry that is not held changes nothing.
	let unchanged = spool
		.update_envelope(id, |e| e.release(900))
		.expect("release");
	assert_eq!(unchanged.held_secs, 60);
}

#[test]
fn record_attempt_stores_a_bounded_last_error() {
	let (_dir, spool, id) = open_with_entry();
	let long = "x".repeat(5000);
	assert_eq!(spool.record_attempt(id, 77, &long).expect("attempt"), 1);
	let envelope = spool.load_envelope(id).expect("load");
	assert_eq!(envelope.next_attempt, 77);
	assert_eq!(
		envelope.last_error.as_deref().map(str::len),
		Some(LAST_ERROR_MAX)
	);
}

#[test]
fn concurrent_edits_are_not_lost() {
	let (_dir, spool, id) = open_with_entry();
	let workers: Vec<_> = (0..8)
		.map(|_| {
			let spool = Arc::clone(&spool);
			std::thread::spawn(move || {
				for _ in 0..40 {
					spool
						.update_envelope(id, |e| e.attempts += 1)
						.expect("update");
				}
			})
		})
		.collect();
	for worker in workers {
		worker.join().expect("join");
	}
	assert_eq!(spool.load_envelope(id).expect("load").attempts, 320);
}

#[test]
fn an_edit_waits_for_the_spool_lock() {
	let (_dir, spool, id) = open_with_entry();
	let guard = spool.lock().expect("lock");
	let editor = {
		let spool = Arc::clone(&spool);
		std::thread::spawn(move || spool.update_envelope(id, |e| e.attempts += 1))
	};
	std::thread::sleep(Duration::from_millis(300));
	assert_eq!(
		spool.load_envelope(id).expect("load").attempts,
		0,
		"the edit must not land while another process holds the lock"
	);
	drop(guard);
	editor.join().expect("join").expect("update");
	assert_eq!(spool.load_envelope(id).expect("load").attempts, 1);
}

#[test]
fn a_removal_waits_for_the_spool_lock_so_an_edit_cannot_resurrect_the_entry() {
	let (dir, spool, id) = open_with_entry();
	let guard = spool.lock().expect("lock");
	let remover = {
		let spool = Arc::clone(&spool);
		std::thread::spawn(move || spool.remove(id))
	};
	std::thread::sleep(Duration::from_millis(300));
	assert!(
		dir.path().join(format!("spool/new/{id}.json")).exists(),
		"the removal must not run while another process holds the lock"
	);
	drop(guard);
	remover.join().expect("join").expect("remove");
	let missing = spool.update_envelope(id, |e| e.attempts += 1);
	assert_eq!(
		missing.expect_err("entry is gone").kind(),
		std::io::ErrorKind::NotFound
	);
	assert!(!dir.path().join(format!("spool/new/{id}.json")).exists());
}

#[test]
fn load_envelope_never_reads_the_message_body() {
	let (dir, spool, id) = open_with_entry();
	fs::remove_file(dir.path().join(format!("spool/new/{id}.eml"))).expect("remove body");
	assert!(spool.load_envelope(id).is_ok());
}
