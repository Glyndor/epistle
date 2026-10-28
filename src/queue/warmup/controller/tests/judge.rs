//! Judging a day reads that whole day of the delivery log, which on a busy
//! server is a large file. The queue's own calls never do it, and the read
//! never holds the lock the queue's calls take: the server's timer does it
//! off the runtime (see `open_warmup`), and the queue goes on meanwhile.

use std::sync::mpsc;
use std::time::Duration;

use super::base::{enable, granted};
use super::*;

/// Midnight UTC of the test day.
const MIDNIGHT: u64 = 20_375 * 86_400;
const TOMORROW: u64 = MIDNIGHT + 86_400;

/// Make the delivery log of the test day a pipe nobody writes to, so that
/// reading it blocks until [`unblock`].
fn blocking_day(dir: &Path) -> PathBuf {
	let logs = dir.join("deliverylog");
	std::fs::create_dir_all(&logs).expect("mkdir");
	let path = logs.join(format!(
		"{}.jsonl",
		crate::storage::delivery_log::day_name(day_of(MIDNIGHT))
	));
	let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).expect("path");
	// SAFETY: a valid NUL-terminated path; mkfifo has no other effect.
	let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
	assert_eq!(rc, 0, "mkfifo: {}", std::io::Error::last_os_error());
	path
}

/// Let a reader blocked on the pipe at `path` see the end of it.
fn unblock(path: &Path) {
	drop(std::fs::OpenOptions::new().write(true).open(path));
}

/// Run `call` on its own thread and give it `secs` to return.
fn within<T: Send + 'static>(secs: u64, call: impl FnOnce() -> T + Send + 'static) -> Option<T> {
	let (sender, receiver) = mpsc::channel();
	std::thread::spawn(move || {
		let _ = sender.send(call());
	});
	receiver.recv_timeout(Duration::from_secs(secs)).ok()
}

#[test]
fn the_queue_never_waits_for_a_day_to_be_judged() {
	let dir = tempfile::tempdir().expect("tempdir");
	enable(dir.path(), |_| {});
	let log = DeliveryLog::open(dir.path(), 30);
	let warmup = Arc::new(Warmup::open(dir.path(), Some(log), MIDNIGHT));
	assert_eq!(
		granted(warmup.grant(Group::Gmail, "system", 3, MIDNIGHT)).0,
		3
	);
	let pipe = blocking_day(dir.path());

	// The first call of the new day opens it without reading the log.
	let queue = Arc::clone(&warmup);
	let first = within(5, move || {
		queue.grant(Group::Gmail, "system", 1, TOMORROW + 10)
	});
	assert_eq!(
		first,
		Some(Grant::Limited {
			granted: 1,
			until: TOMORROW + 10
		}),
		"the queue's call returned without reading the day"
	);

	// The timer reads it, and the queue is not held up while it does.
	let timer = Arc::clone(&warmup);
	let ticking = std::thread::spawn(move || timer.tick(TOMORROW + 20));
	std::thread::sleep(Duration::from_millis(200));
	let queue = Arc::clone(&warmup);
	let during = within(5, move || {
		queue.blocked(Group::Gmail, "system", TOMORROW + 30)
	});
	unblock(&pipe);
	ticking.join().expect("tick");
	assert!(
		during.is_some(),
		"the queue's call returned during the read"
	);

	// And the day was judged once the read was over.
	let (_, state) = warmup.snapshot();
	let gmail = state.group(Group::Gmail);
	assert_eq!(
		gmail.history.back().map(|record| (record.day, record.sent)),
		Some((day_of(MIDNIGHT), 3))
	);
	assert_eq!(gmail.sent, 1, "today's count is today's");
	assert_eq!(state.closing, None);
}

#[test]
fn a_day_still_to_judge_survives_a_restart() {
	let dir = tempfile::tempdir().expect("tempdir");
	enable(dir.path(), |_| {});
	let warmup = Warmup::open(dir.path(), None, MIDNIGHT);
	assert_eq!(
		granted(warmup.grant(Group::Gmail, "system", 3, MIDNIGHT)).0,
		3
	);
	// The new day opens; the server stops before its timer judged the last.
	assert!(warmup.blocked(Group::Gmail, "system", TOMORROW).is_none());
	drop(warmup);
	let again = Warmup::open(dir.path(), None, TOMORROW + 5);
	again.tick(TOMORROW + 5);
	let (_, state) = again.snapshot();
	assert_eq!(
		state
			.group(Group::Gmail)
			.history
			.back()
			.map(|record| (record.day, record.sent)),
		Some((day_of(MIDNIGHT), 3))
	);
}

#[test]
fn a_smarthost_throttling_relayed_mail_does_not_back_a_group_off() {
	use crate::storage::{DeliveryOutcome, DeliveryRecord};
	let dir = tempfile::tempdir().expect("tempdir");
	enable(dir.path(), |_| {});
	let log = DeliveryLog::open(dir.path(), 30);
	let warmup = Warmup::open(dir.path(), Some(log.clone()), MIDNIGHT)
		.with_relays(vec!["smtp-relay.google.com".to_string()]);
	assert_eq!(
		granted(warmup.grant(Group::Gmail, "system", 3, MIDNIGHT)).0,
		3
	);
	for n in 0..13 {
		let (outcome, remote, reply) = match n < 3 {
			true => (
				DeliveryOutcome::Delivered,
				"gmail-smtp-in.l.google.com",
				"250 OK",
			),
			false => (
				DeliveryOutcome::Deferred,
				"smtp-relay.google.com",
				"421 4.7.0 slow down",
			),
		};
		log.append(&DeliveryRecord {
			time: MIDNIGHT + 60,
			spool_id: uuid::Uuid::nil(),
			account: None,
			from: "alice@sender.example".into(),
			recipient: format!("user{n}@gmail.com"),
			outcome,
			remote: Some(remote.into()),
			reply: Some(reply.into()),
			attempt: 1,
			extra: Default::default(),
			class: Default::default(),
		})
		.expect("append");
	}
	warmup.tick(TOMORROW + 5);
	let (_, state) = warmup.snapshot();
	let judged = state.group(Group::Gmail).history.back().cloned();
	assert_eq!(
		judged.map(|record| (record.attempted, record.deferred, record.verdict)),
		Some((3, 0, crate::queue::warmup::policy::Verdict::Good))
	);
}
