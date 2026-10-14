//! The scheduler's own bounds: filling slots never walks the whole queue,
//! and a conversation that panics gives its slot and recipients back.

use std::sync::Arc;

use uuid::Uuid;

use super::*;
use crate::queue::resolver::{ConnectFuture, Connector};
use crate::smtp::session::AcceptedMessage;
use crate::storage::FsSpool;

const JOBS: usize = 2000;

/// A connector whose every connection attempt panics.
struct Broken;

impl Connector for Broken {
	fn connect(&self, _domain: &str, _policy: Option<&crate::mtasts::Policy>) -> ConnectFuture<'_> {
		Box::pin(async { panic!("connector bug") })
	}
}

fn worker(dir: &std::path::Path) -> Worker {
	let spool = FsSpool::open(dir).expect("open spool");
	Worker::new(spool, Arc::new(Broken), "mail.sender.example").with_concurrency(8, 1)
}

fn job(domain: &str, sender: &str) -> Job {
	Job {
		id: Uuid::now_v7(),
		domain: domain.to_string(),
		sender: sender.to_string(),
		recipients: vec![format!("user@{domain}")],
	}
}

#[test]
fn a_queue_stuck_behind_a_busy_destination_is_not_walked_on_every_fill() {
	let dir = tempfile::tempdir().expect("tempdir");
	let worker = worker(dir.path());
	let busy = worker
		.claims
		.take(
			worker.limits,
			Uuid::now_v7(),
			("busy.example", "other"),
			&[],
		)
		.expect("a slot for busy.example");
	let mut schedule = Schedule::default();
	for _ in 0..JOBS {
		schedule.waiting.push_back(job("busy.example", "sender"));
	}

	// One fill per conversation that ends elsewhere.
	for _ in 0..JOBS {
		worker.fill(&mut schedule);
	}

	assert!(
		schedule.examined <= JOBS,
		"{} jobs looked at for {JOBS} fills",
		schedule.examined
	);
	assert_eq!(schedule.waiting.len(), JOBS);
	drop(busy);
	worker.fill(&mut schedule);
	assert!(
		schedule.waiting.is_empty(),
		"once the slot is free the jobs start"
	);
}

#[test]
fn many_destinations_waiting_for_a_full_worker_cost_nothing_to_fill() {
	let dir = tempfile::tempdir().expect("tempdir");
	let worker = worker(dir.path());
	let running: Vec<_> = (0..8)
		.map(|n| {
			worker
				.claims
				.take(
					worker.limits,
					Uuid::now_v7(),
					(&format!("r{n}.example"), &format!("running{n}")),
					&[],
				)
				.expect("slot")
		})
		.collect();
	let mut schedule = Schedule::default();
	for n in 0..JOBS {
		schedule
			.waiting
			.push_back(job(&format!("d{n}.example"), &format!("s{}", n % 50)));
	}

	for _ in 0..JOBS {
		worker.fill(&mut schedule);
	}

	assert_eq!(schedule.examined, 0);
	assert_eq!(schedule.waiting.len(), JOBS);
	drop(running);
}

#[test]
fn a_sender_at_its_share_is_set_aside_after_one_look() {
	let dir = tempfile::tempdir().expect("tempdir");
	let worker = worker(dir.path());
	let share = worker.limits.per_sender();
	assert_eq!(share, 6, "three quarters of eight");
	let flooding: Vec<_> = (0..share)
		.map(|n| {
			worker
				.claims
				.take(
					worker.limits,
					Uuid::now_v7(),
					(&format!("hung{n}.example"), "account:flood"),
					&[],
				)
				.expect("slot")
		})
		.collect();
	assert!(
		worker
			.claims
			.take(
				worker.limits,
				Uuid::now_v7(),
				("one-more.example", "account:flood"),
				&[]
			)
			.is_err(),
		"the share is a cap"
	);
	let mut schedule = Schedule::default();
	for n in 0..JOBS {
		schedule
			.waiting
			.push_back(job(&format!("d{n}.example"), "account:flood"));
	}
	schedule
		.waiting
		.push_back(job("ok.example", "account:other"));

	for _ in 0..JOBS {
		worker.fill(&mut schedule);
	}

	// The other sender's job was taken at the first fill (it is not in the
	// spool, so it is dropped), and the flood was looked at once per fill.
	assert_eq!(schedule.waiting.len(), JOBS);
	assert!(
		schedule.examined <= JOBS + 1,
		"{} jobs looked at",
		schedule.examined
	);
	drop(flooding);
}

#[tokio::test]
async fn a_conversation_that_panics_gives_back_its_slot_and_recipients() {
	let dir = tempfile::tempdir().expect("tempdir");
	let worker = worker(dir.path());
	let recipient = "bob@remote.example";
	worker
		.spool
		.store(
			&AcceptedMessage {
				reverse_path: "alice@sender.example".into(),
				recipients: vec![recipient.to_string()],
				data: b"Subject: hi\r\n\r\nbody\r\n".to_vec(),
				require_tls: false,
				mailbox: None,
				tlsrpt_verified: false,
				no_dsn: Vec::new(),
				sender_verified: false,
			},
			None,
			&std::collections::BTreeMap::new(),
		)
		.expect("store");
	let id = worker.spool.list().expect("list")[0];

	assert_eq!(worker.pass().await.expect("pass"), 0);

	assert!(!worker.claims.holds(id, recipient));
	assert!(
		worker
			.claims
			.has_room(crate::queue::limits::Limits::new(1, 1))
	);
	let state = worker
		.spool
		.load_envelope(id)
		.expect("envelope")
		.recipient_state(recipient);
	assert_eq!(state.attempts, 1);
	assert_eq!(
		state.last_error.as_deref(),
		Some("internal error during delivery")
	);
}

#[test]
fn a_delivery_under_way_does_not_lift_a_hold_still_in_force() {
	let dir = tempfile::tempdir().expect("tempdir");
	let worker = worker(dir.path());
	let busy = job("busy.example", "account:alice");
	let throttled = Conversation::all(
		&["a@busy.example".to_string()],
		Some("mx.busy.example".into()),
		DeliveryError::Transient("421 4.7.0 slow down".into()),
	);
	worker.pace(&busy, &throttled, 1000);
	let delivered = Conversation {
		remote: Some("mx.busy.example".into()),
		results: vec![("b@busy.example".to_string(), Ok(()))],
		slowed: None,
		held_until: None,
	};

	worker.pace(&busy, &delivered, 1030);

	let holds = worker.spool.load_holds().expect("holds");
	assert!(backoff::is_held(&holds, "busy.example", 1030));
	assert!(backoff::is_held(&holds, "mx:mx.busy.example", 1030));

	worker.pace(&busy, &delivered, 1060);
	assert!(worker.spool.load_holds().expect("holds").is_empty());
}
