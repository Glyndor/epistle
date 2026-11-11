//! A message reaches the real SMTP listener while the records of its sender
//! come from a hostile authority, or while its body is built to make the
//! screens work. The listener must answer within the deadline, never take a
//! lookup failure for a clean sender, and keep serving.

use std::time::{Duration, Instant};

use epistle::dnsbl::Dnsbl;
use epistle::smtp::server::Server;

use super::smtp_harness::*;
use super::wire::{Reply, Wire};

/// Generous: a loaded machine needs seconds, a loop or a flood never ends.
/// 50 hosts, each looked up by name and by registered domain, over A and AAAA,
/// plus the sender's own records.
const HOST_LOOKUPS: usize = 50 * 2 * 2 + 16;

const DELIVERY_BOUND: Duration = Duration::from_secs(14);

struct Delivery {
	answer: String,
	/// What the sink kept, lossily decoded.
	kept: Vec<String>,
	/// Lookups the authority answered.
	queries: usize,
}

/// Send one message from an unauthenticated peer.
async fn deliver_through(
	wire: Wire,
	configure: impl FnOnce(Server) -> Server,
	body: &[u8],
	max_queries: usize,
) -> Delivery {
	let (dns, authority) = wire.shared();
	let server = Harness::start(|s| configure(s.with_spf(dns))).await;
	let mut client = server.connect().await;
	helo(&mut client).await;
	send(&mut client, b"MAIL FROM:<sender@sender.example>\r\n").await;
	expect(&mut client, OK).await;
	send(&mut client, b"RCPT TO:<tester@epistle.test>\r\n").await;
	expect(&mut client, OK).await;
	send(&mut client, b"DATA\r\n").await;
	let go = line(&mut client).await.expect("DATA reply").expect("open");
	assert!(go.starts_with("354"), "DATA: {go:?}");
	let started = Instant::now();
	send(&mut client, body).await;
	let answer = line(&mut client).await.expect("end of DATA").expect("open");
	let elapsed = started.elapsed();
	eprintln!("answer in {elapsed:?}: {answer:?}");
	assert!(elapsed < DELIVERY_BOUND, "the listener took {elapsed:?}");
	quit(&mut client).await;
	let queries = authority.queries();
	assert!(
		(1..=max_queries).contains(&queries),
		"expected at most {max_queries} lookups, got {queries}"
	);
	server.healthy().await;
	Delivery {
		answer,
		kept: server
			.sink
			.messages()
			.iter()
			.map(|m| String::from_utf8_lossy(&m.data).into_owned())
			.collect(),
		queries,
	}
}

async fn deliver(reply: Reply) -> Delivery {
	deliver_through(Wire::tcp(reply).await, |server| server, BODY, 64).await
}

fn assert_deferred(delivery: &Delivery) {
	assert!(
		delivery.answer.starts_with("451 4.4.3"),
		"{:?}",
		delivery.answer
	);
	assert!(delivery.kept.is_empty(), "a deferred message was kept");
}

fn assert_accepted_as(delivery: &Delivery, spf: &str) {
	assert!(delivery.answer.starts_with("250"), "{:?}", delivery.answer);
	assert_eq!(delivery.kept.len(), 1);
	let stamp = format!("Received-SPF: {spf} ");
	assert!(delivery.kept[0].contains(&stamp), "no {stamp:?} stamp");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_lookup_defers_the_message_instead_of_passing_it() {
	// Mutation: map Err(_) to Ok(Vec::new()) in SystemDns::lookup.
	assert_deferred(&deliver(Reply::Servfail).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_truncated_answer_without_tcp_defers_the_message() {
	// Mutation: map Err(_) to Ok(Vec::new()) in SystemDns::lookup.
	let wire = Wire::truncated_without_tcp().await;
	assert_deferred(&deliver_through(wire, |server| server, BODY, 64).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn answers_that_say_the_sender_publishes_nothing_are_not_a_failure() {
	// Mutation: NoRecordsFound => Err(Temporary) in SystemDns::lookup.
	for reply in [Reply::Loop, Reply::Nodata, Reply::Nxdomain] {
		assert_accepted_as(&deliver(reply).await, "none");
	}
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_hostile_record_set_is_a_permerror_and_not_a_pass() {
	// Mutation: disable the second-record guard in SPF fetch_record.
	for reply in [Reply::LargeTxt, Reply::Thousand] {
		assert_accepted_as(&deliver(reply).await, "permerror");
	}
}

/// `count` links to distinct hosts, one per short line.
fn links(count: usize) -> Vec<u8> {
	let mut body = b"From: sender@remote.test\r\nSubject: links\r\n\r\n".to_vec();
	for n in 0..count {
		body.extend(format!("http://h{n}.spam.example/\r\n").bytes());
	}
	body.extend(b".\r\n");
	body
}

/// One token of a million characters, folded into lines the listener takes.
fn long_token() -> Vec<u8> {
	let mut body = b"From: sender@remote.test\r\nSubject: token\r\n\r\n".to_vec();
	for _ in 0..1100 {
		body.extend(vec![b'a'; 900]);
		body.extend(b"\r\n");
	}
	body.extend(b".\r\n");
	body
}

/// HTML nested far deeper than any parser should follow.
fn nested_html() -> Vec<u8> {
	let mut body = b"From: sender@remote.test\r\nContent-Type: text/html\r\n\r\n".to_vec();
	for _ in 0..8192 {
		body.extend(b"<div>\r\n");
	}
	body.extend(b"<a href=\"http://deep.spam.example/\">x</a>\r\n.\r\n");
	body
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hostile_bodies_are_screened_inside_the_time_and_lookup_bounds() {
	// Mutation: raise DEFAULT_HOST_CAP, or drop the cap, in screen_dnsbl.
	let url_screen = |server: Server| {
		server.with_dnsbl(Dnsbl::new([]).with_url_zones(["uribl.test".to_string()]))
	};
	let flood = deliver_through(
		Wire::tcp(Reply::Nxdomain).await,
		url_screen,
		&links(100_000),
		HOST_LOOKUPS,
	)
	.await;
	assert_accepted_as(&flood, "none");
	assert!(
		flood.queries >= 50,
		"the URL screen did not look at the hosts: {} lookups",
		flood.queries
	);
	for body in [long_token(), nested_html()] {
		let delivery =
			deliver_through(Wire::tcp(Reply::Nxdomain).await, url_screen, &body, 12).await;
		assert_accepted_as(&delivery, "none");
	}
}
