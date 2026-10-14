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

fn job(domain: &str) -> Job {
	Job {
		id: Uuid::now_v7(),
		domain: domain.to_string(),
		recipients: vec![format!("user@{domain}")],
	}
}

#[test]
fn a_queue_stuck_behind_a_busy_destination_is_not_walked_on_every_fill() {
	let dir = tempfile::tempdir().expect("tempdir");
	let worker = worker(dir.path());
	let busy = worker
		.claims
		.take(worker.limits, Uuid::now_v7(), "busy.example", &[])
		.expect("a slot for busy.example");
	let mut schedule = Schedule::default();
	for _ in 0..JOBS {
		schedule.push_back(job("busy.example"));
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
	assert_eq!(schedule.queued["busy.example"].len(), JOBS);
	drop(busy);
	worker.fill(&mut schedule);
	assert!(
		schedule.queued.is_empty() && schedule.order.is_empty(),
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
				.take(worker.limits, Uuid::now_v7(), &format!("r{n}.example"), &[])
				.expect("slot")
		})
		.collect();
	let mut schedule = Schedule::default();
	for n in 0..JOBS {
		schedule.push_back(job(&format!("d{n}.example")));
	}

	for _ in 0..JOBS {
		worker.fill(&mut schedule);
	}

	assert_eq!(schedule.examined, 0);
	assert_eq!(schedule.order.len(), JOBS);
	drop(running);
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
	let throttled = Conversation::all(
		&["a@busy.example".to_string()],
		Some("mx.busy.example".into()),
		DeliveryError::Transient("421 4.7.0 slow down".into()),
	);
	worker.pace("busy.example", &throttled, 1000);
	let delivered = Conversation {
		remote: Some("mx.busy.example".into()),
		results: vec![("b@busy.example".to_string(), Ok(()))],
		slowed: None,
		held_until: None,
	};

	worker.pace("busy.example", &delivered, 1030);

	let holds = worker.spool.load_holds().expect("holds");
	assert!(backoff::is_held(&holds, "busy.example", 1030));
	assert!(backoff::is_held(&holds, "mx:mx.busy.example", 1030));

	worker.pace("busy.example", &delivered, 1060);
	assert!(worker.spool.load_holds().expect("holds").is_empty());
}
