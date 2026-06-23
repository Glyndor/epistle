//! Microbenchmarks for the outbound queue and on-disk store hot paths: SRS
//! envelope rewriting, bounce/DSN construction, the filesystem spool
//! (store/load), and the suppression-list lookup every recipient hits before
//! a send. These run on every queued message, so they are where throughput
//! regressions show up first (`cargo bench --bench queue`).

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};

use epistle::queue::SuppressionList;
use epistle::queue::bounce;
use epistle::queue::srs::Srs;
use epistle::smtp::session::AcceptedMessage;
use epistle::storage::FsSpool;

/// A representative message body for spool/bounce benchmarks.
fn sample_message() -> AcceptedMessage {
	let mut data =
		b"From: sender@example.com\r\nTo: rcpt@example.net\r\nSubject: hi\r\n\r\n".to_vec();
	data.extend(std::iter::repeat_n(b'x', 4096));
	AcceptedMessage {
		reverse_path: "sender@example.com".to_string(),
		recipients: vec!["rcpt@example.net".to_string()],
		data,
		require_tls: false,
		mailbox: None,
		no_dsn: Vec::new(),
	}
}

fn srs(c: &mut Criterion) {
	let srs = Srs::new(b"benchmark-secret-key");
	c.bench_function("srs_forward", |b| {
		b.iter(|| {
			black_box(srs.forward(
				black_box("alice"),
				black_box("sender.example"),
				black_box("forwarder.example"),
				black_box(20_000),
			))
		});
	});

	let rewritten = srs.forward("alice", "sender.example", "forwarder.example", 20_000);
	// The bare SRS0 local-part, as it would arrive on a bounce.
	let local = rewritten.split('@').next().unwrap().to_string();
	c.bench_function("srs_reverse", |b| {
		b.iter(|| black_box(srs.reverse(black_box(&local), black_box(20_000), black_box(21))));
	});
}

fn bounce_dsn(c: &mut Criterion) {
	let msg = sample_message();
	let recipients = vec!["rcpt@example.net".to_string()];
	c.bench_function("bounce_build", |b| {
		b.iter(|| {
			black_box(bounce::build(
				black_box("mail.example.org"),
				black_box("sender@example.com"),
				black_box(&recipients),
				black_box("550 5.1.1 no such user"),
				black_box(&msg.data),
				std::time::UNIX_EPOCH,
			))
		});
	});
}

fn spool(c: &mut Criterion) {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = FsSpool::open(dir.path()).expect("open spool");
	let msg = sample_message();

	c.bench_function("spool_store", |b| {
		b.iter(|| black_box(spool.store(black_box(&msg)).expect("store")));
	});

	let id = spool.store(&msg).expect("store");
	c.bench_function("spool_load", |b| {
		b.iter(|| black_box(spool.load(black_box(id)).expect("load")));
	});
}

fn suppression(c: &mut Criterion) {
	let dir = tempfile::tempdir().expect("tempdir");
	let list = SuppressionList::open(dir.path()).expect("open list");
	list.suppress("dead@example.net");

	c.bench_function("suppression_hit", |b| {
		b.iter(|| black_box(list.is_suppressed(black_box("dead@example.net"))));
	});
	c.bench_function("suppression_miss", |b| {
		b.iter(|| black_box(list.is_suppressed(black_box("live@example.net"))));
	});
}

criterion_group!(benches, srs, bounce_dsn, spool, suppression);
criterion_main!(benches);
