//! Pause floors, receiver groups and admission use in-process SMTP streams.

use super::super::backoff::store;
use super::*;
use std::time::Duration;

const FIRST: &str = "one.google.com";
const SECOND: &str = "two.google.com";

#[tokio::test]
async fn provider_pause_is_the_maximum_of_the_floor_and_the_backoff_step() {
	for (reply, minimum, step) in [
		("421 4.7.28 anything", 1200, 60),
		("451 4.3.0 [TSS04] anything", 1200, 60),
		("421 4.7.28 anything", 120, 900),
	] {
		let dir = tempfile::tempdir().expect("tempdir");
		let remote = FakeRemote::default();
		remote.hosted("busy.example", FIRST, greeting(reply));
		let (worker, now) = worker_for(dir.path(), &["bob@busy.example"], &remote);
		let worker = worker.with_provider_pause(minimum).with_backoff(vec![step]);
		worker.pass().await.expect("pass");
		let until = now + minimum.max(step);
		assert_eq!(
			hold(&worker, &Destination::domain("busy.example"), now)
				.expect("held")
				.until,
			until
		);
		// A different recipient domain behind another MX in the same group
		// must not connect, even after the ordinary one-minute step.
		remote.hosted("hosted.example", SECOND, Script::default());
		store(&worker.spool, &["carol@hosted.example"]);
		worker.set_now(until - 1);
		worker.pass().await.expect("still paused");
		assert_eq!(remote.connections(FIRST), 1);
		assert_eq!(remote.connections(SECOND), 0);
		let envelope = worker
			.spool
			.list()
			.expect("list")
			.into_iter()
			.map(|id| worker.spool.load_envelope(id).expect("envelope"))
			.find(|env| env.recipients == ["carol@hosted.example"])
			.expect("waiting");
		assert_eq!(envelope.recipient_state("carol@hosted.example").attempts, 0);
	}
}

#[tokio::test]
async fn yahoo_marker_at_the_end_of_long_prose_survives_a_restart() {
	let dir = tempfile::tempdir().expect("tempdir");
	let remote = FakeRemote::default();
	let reply = format!("451 4.3.0 {} [TSS04]", "x".repeat(230));
	remote.hosted("busy.example", "one.yahoodns.net", greeting(&reply));
	let (worker, now) = worker_for(dir.path(), &["bob@busy.example"], &remote);
	worker.pass().await.expect("pass");
	drop(worker);
	remote.hosted("hosted.example", "two.yahoodns.net", Script::default());
	let worker = Worker::new(
		FsSpool::open(dir.path()).expect("spool"),
		Arc::new(remote.clone()),
		"mail.sender.example",
	);
	store(&worker.spool, &["carol@hosted.example"]);
	worker.set_now(now + 599);
	worker.pass().await.expect("restarted");
	assert_eq!(remote.connections("two.yahoodns.net"), 0);
	assert!(
		worker
			.holds()
			.provider_held("two.yahoodns.net", now + 599)
			.is_some()
	);
}

#[tokio::test(start_paused = true)]
async fn a_throttled_group_resumes_with_one_connection_across_domains_and_passes() {
	let dir = tempfile::tempdir().expect("tempdir");
	let remote = FakeRemote::default();
	remote.hosted("busy.example", FIRST, greeting("421 4.7.28 anything"));
	let (worker, now) = worker_for(dir.path(), &["bob@busy.example"], &remote);
	worker.pass().await.expect("initial pause");
	drop(worker);
	let worker = Worker::new(
		FsSpool::open(dir.path()).expect("spool"),
		Arc::new(remote.clone()),
		"mail.sender.example",
	)
	.with_concurrency(8, 8);
	worker.set_now(now + 600);
	for (domain, host, recipient) in [
		("busy.example", FIRST, "bob@busy.example"),
		("hosted.example", SECOND, "carol@hosted.example"),
	] {
		remote.hosted(
			domain,
			host,
			Script {
				data: Some("451 4.7.28 new wording".into()),
				delay: Some(Duration::from_secs(10)),
				..Script::default()
			},
		);
		if domain != "busy.example" {
			store(&worker.spool, &[recipient]);
		}
	}
	let (first, second) = tokio::join!(worker.pass(), worker.pass());
	assert_eq!(
		first.expect("first pass") + second.expect("overlapping pass"),
		0
	);
	assert_eq!(
		remote.most_at_once_total(),
		1,
		"one socket for the whole group"
	);
	assert_eq!(
		remote.connections(FIRST) + remote.connections(SECOND),
		2,
		"one initial rejection and just one connection after the pause"
	);
}

#[tokio::test]
async fn a_provider_rate_limit_at_greeting_does_not_try_a_second_mx() {
	let dir = tempfile::tempdir().expect("tempdir");
	let remote = FakeRemote::default();
	remote.exchangers(
		"busy.example",
		vec![greeting("421 4.7.28 arbitrary"), Script::default()],
	);
	let (worker, now) = worker_for(dir.path(), &["bob@busy.example"], &remote);
	worker.pass().await.expect("pass");
	assert_eq!(remote.connections("mx2.busy.example"), 0);
	assert_eq!(remote.copies("bob@busy.example"), 0);
	assert_eq!(
		hold(&worker, &Destination::domain("busy.example"), now)
			.expect("hold")
			.until,
		now + 600
	);
}
