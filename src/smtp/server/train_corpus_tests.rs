//! What the server teaches the shared corpus, and from whom.
//!
//! The mail comes from anyone, so `train_corpus` decides what is worth
//! learning (ham only from a verified sender), names the source the budget
//! is counted under, and counts what the corpus did not take.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};

use super::Server;
use crate::antispam::corpus::BayesScorer;
use crate::antispam::shared_training::TrainSource;
use crate::smtp::session::AcceptedMessage;
use crate::smtp::sink::MemorySink;

type Call = (TrainSource, usize, bool);

/// Records every `train_from` call and answers with a fixed verdict.
struct Recorder {
	calls: Mutex<Vec<Call>>,
	accept: bool,
}

impl Recorder {
	fn new(accept: bool) -> Arc<Self> {
		Arc::new(Recorder {
			calls: Mutex::new(Vec::new()),
			accept,
		})
	}

	fn calls(&self) -> Vec<Call> {
		self.calls.lock().expect("calls").clone()
	}
}

impl BayesScorer for Recorder {
	fn score<'a>(
		&'a self,
		_scope: &'a str,
		_text: &'a str,
	) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<f64, sqlx::Error>> + Send + 'a>>
	{
		Box::pin(async { Ok(0.5) })
	}

	fn score_for_account<'a>(
		&'a self,
		_account: &'a str,
		_text: &'a [u8],
	) -> crate::antispam::trainer::TrainerFuture<'a, Option<f64>> {
		Box::pin(async { None })
	}

	fn train_from(&self, source: &TrainSource, data: &[u8], spam: bool) -> bool {
		self.calls
			.lock()
			.expect("calls")
			.push((source.clone(), data.len(), spam));
		self.accept
	}
}

fn server_with(recorder: &Arc<Recorder>) -> Server {
	Server::new("mail.example.org", Arc::new(MemorySink::new()))
		.with_bayes(recorder.clone() as Arc<dyn BayesScorer>)
}

fn message(verified: bool) -> AcceptedMessage {
	AcceptedMessage {
		reverse_path: "Sender@Mail.Example.NET".to_string(),
		recipients: vec!["bob@example.org".to_string()],
		data: b"Subject: hi\r\n\r\nbody\r\n".to_vec(),
		sender_verified: verified,
		..Default::default()
	}
}

fn peer() -> Option<IpAddr> {
	Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)))
}

fn dropped(server: &Server) -> u64 {
	server
		.metrics
		.snapshot()
		.get("bayes_training_dropped")
		.copied()
		.unwrap_or(0)
}

#[test]
fn ham_from_a_sender_the_server_did_not_verify_teaches_nothing() {
	let recorder = Recorder::new(true);
	server_with(&recorder).train_corpus(&message(false), peer(), false);
	assert!(recorder.calls().is_empty());
}

#[test]
fn ham_from_a_verified_sender_is_learned() {
	let recorder = Recorder::new(true);
	let message = message(true);
	server_with(&recorder).train_corpus(&message, peer(), false);
	let expected = TrainSource::new(peer(), Some("Mail.Example.NET"));
	assert_eq!(
		recorder.calls(),
		vec![(expected, message.data.len(), false)]
	);
}

#[test]
fn spam_is_learned_whether_or_not_the_sender_was_verified() {
	let recorder = Recorder::new(true);
	let server = server_with(&recorder);
	server.train_corpus(&message(false), peer(), true);
	server.train_corpus(&message(true), peer(), true);
	let spam: Vec<bool> = recorder.calls().iter().map(|call| call.2).collect();
	assert_eq!(spam, vec![true, true]);
}

#[test]
fn a_job_the_corpus_refuses_is_counted() {
	let recorder = Recorder::new(false);
	let server = server_with(&recorder);
	server.train_corpus(&message(true), peer(), true);
	server.train_corpus(&message(true), peer(), true);
	assert_eq!(dropped(&server), 2);

	let accepting = Recorder::new(true);
	let server = server_with(&accepting);
	server.train_corpus(&message(true), peer(), true);
	assert_eq!(dropped(&server), 0);
}

#[test]
fn a_server_without_a_corpus_teaches_nothing_and_counts_nothing() {
	let server = Server::new("mail.example.org", Arc::new(MemorySink::new()));
	server.train_corpus(&message(true), peer(), true);
	assert_eq!(dropped(&server), 0);
}

/// The whole path: a message accepted from 192.0.2.7 with `spf` as the
/// sender domain's record, and what the shared corpus was asked to learn.
async fn accepted_with(spf: &str) -> Vec<Call> {
	use tokio::io::{AsyncReadExt, AsyncWriteExt};

	let records =
		std::collections::HashMap::from([("sender.example".to_string(), vec![spf.to_string()])]);
	let recorder = Recorder::new(true);
	let directory = super::DirectoryHandle::new(crate::smtp::directory::Directory::new(
		["example.org".to_string()],
		[("bob@example.org".to_string(), "bob".to_string())],
	));
	let server = server_with(&recorder)
		.with_directory(directory)
		.with_spf(Arc::new(crate::dkim::test_support::KeyDns(records)));
	let (client, server_stream) = tokio::io::duplex(64 * 1024);
	let task = tokio::spawn(async move { server.handle(server_stream, peer()).await });
	let (mut read, mut write) = tokio::io::split(client);
	write
		.write_all(
			b"EHLO client.example.org\r\nMAIL FROM:<eve@sender.example>\r\n\
			  RCPT TO:<bob@example.org>\r\nDATA\r\nSubject: hi\r\n\r\nhello\r\n.\r\nQUIT\r\n",
		)
		.await
		.expect("write");
	write.shutdown().await.expect("shutdown");
	let mut output = Vec::new();
	read.read_to_end(&mut output).await.expect("read");
	task.await.expect("task").expect("server result");
	recorder.calls()
}

#[tokio::test]
async fn mail_accepted_from_a_verified_sender_teaches_ham_with_its_source() {
	let calls = accepted_with("v=spf1 ip4:192.0.2.0/24 -all").await;
	let source = TrainSource::new(peer(), Some("sender.example"));
	assert_eq!(calls.len(), 1);
	assert_eq!((&calls[0].0, calls[0].2), (&source, false));
}

#[tokio::test]
async fn mail_accepted_from_an_unverified_sender_teaches_nothing() {
	assert!(accepted_with("v=spf1 ~all").await.is_empty());
}
