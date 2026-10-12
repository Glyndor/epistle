//! Tests for `handle_bayes_thresholds`, the SMTP pass that decides on
//! its own when the Bayesian score is high enough. Sibling file
//! (`run_band_tests.rs`) is already at the per-file line ceiling for the
//! scope-picker cases; the threshold tests live here so neither file
//! crosses the 500-code-line cap.

use std::sync::Arc;

use tokio::io::AsyncReadExt;

use crate::smtp::server::DirectoryHandle;
use crate::smtp::server::Server;
use crate::smtp::server::run_band::BayesOutcome;
use crate::smtp::sink::MemorySink;

/// Always-trusted, configurable-score scorer. Implements the bare
/// subset the Bayes-threshold pass reaches: `is_trusted` and
/// `score_for_account`. The default `is_trusted` on the trait would
/// return true for any fake, so it is exercised here only through the
/// `trusted` knob.
struct TrustedScorer {
	score: f64,
	trusted: bool,
}

impl TrustedScorer {
	fn new(score: f64) -> Arc<Self> {
		Arc::new(Self {
			score,
			trusted: true,
		})
	}
	fn with_trusted(self: &Arc<Self>, trusted: bool) -> Arc<Self> {
		Arc::new(Self {
			score: self.score,
			trusted,
		})
	}
}

impl crate::antispam::corpus::BayesScorer for TrustedScorer {
	fn score<'a>(
		&'a self,
		_scope: &'a str,
		_text: &'a str,
	) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<f64, sqlx::Error>> + Send + 'a>>
	{
		let score = self.score;
		Box::pin(async move { Ok(score) })
	}
	fn score_for_account<'a>(
		&'a self,
		_account: &'a str,
		_text: &'a [u8],
	) -> crate::antispam::trainer::TrainerFuture<'a, Option<f64>> {
		let score = self.score;
		Box::pin(async move { Some(score) })
	}
	fn is_trusted<'a>(
		&'a self,
		_scope: &'a str,
	) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>> {
		let trusted = self.trusted;
		Box::pin(async move { trusted })
	}
}

/// Build a server with the given scorer and the test directory (just
/// `bob`/`alice` as local accounts of `example.org`). The thresholds are
/// picked per test.
fn bayes_server(
	sink: Arc<MemorySink>,
	scorer: Arc<dyn crate::antispam::corpus::BayesScorer>,
	junk_at: f64,
	reject_at: Option<f64>,
) -> Server {
	let directory = DirectoryHandle::new(crate::smtp::directory::Directory::new(
		["example.org".to_string()],
		[
			("alice@example.org".to_string(), "alice".to_string()),
			("bob@example.org".to_string(), "bob".to_string()),
		],
	));
	Server::new("mail.example.org", sink)
		.with_directory(directory)
		.with_bayes(scorer)
		.with_bayes_thresholds(junk_at, reject_at)
}

/// Build an `AcceptedMessage` referencing bob at the SMTP level.
fn sample_message(reverse_path: &str, body: &[u8]) -> crate::smtp::session::AcceptedMessage {
	crate::smtp::session::AcceptedMessage {
		reverse_path: reverse_path.to_string(),
		recipients: vec!["bob@example.org".to_string()],
		data: body.to_vec(),
		..Default::default()
	}
}

/// A score above `junk_at` and below `reject_at` lands the message in
/// the Junk mailbox with the spam-marking headers stamped on the raw
/// bytes. The test asserts both outcomes: the mailbox hint changes and
/// the X-Spam-Status / X-Spam-Score pair is at the top of the header
/// block.
#[tokio::test]
async fn score_above_junk_at_routes_to_junk_with_headers() {
	let scorer = TrustedScorer::new(0.97);
	let mut message = sample_message("alice@example.org", b"From: a@b\r\n\r\nbody\r\n");
	let server = bayes_server(Arc::new(MemorySink::new()), scorer, 0.95, None);
	let mut sink = Vec::<u8>::new();
	let outcome = server
		.handle_bayes_thresholds(&mut message, false, &mut sink)
		.await
		.expect("call");
	assert_eq!(outcome, BayesOutcome::SendToJunk);
	assert_eq!(
		message.mailbox.as_deref(),
		Some("Junk"),
		"junk mailbox hint must be set"
	);
	let text = std::str::from_utf8(&message.data).expect("utf-8");
	assert!(
		text.starts_with("X-Spam-Status: Yes\r\n"),
		"X-Spam-Status must come first: {text:?}"
	);
	assert!(
		text.contains("X-Spam-Score: 0.970000\r\n"),
		"X-Spam-Score must carry the raw score: {text:?}"
	);
}

/// A score at or above `reject_at` is refused with the exact `550
/// 5.7.1` line. The test pipes the writer through a tokio duplex so
/// the recorded reply can be inspected byte-for-byte.
#[tokio::test]
async fn score_above_reject_at_sends_550_5_7_1() {
	let scorer = TrustedScorer::new(0.99);
	let mut message = sample_message("alice@example.org", b"From: a@b\r\n\r\nbody\r\n");
	let server = bayes_server(Arc::new(MemorySink::new()), scorer, 0.95, Some(0.98));
	let (mut writer, mut reader) = tokio::io::duplex(4096);
	let outcome = server
		.handle_bayes_thresholds(&mut message, false, &mut writer)
		.await
		.expect("call");
	drop(writer);
	let mut got = Vec::new();
	reader.read_to_end(&mut got).await.expect("drain");
	assert_eq!(outcome, BayesOutcome::Rejected);
	let text = std::str::from_utf8(&got).expect("utf-8");
	assert!(
		text.contains("550 5.7.1 message rejected as spam"),
		"the rejected reply must carry the exact line, got: {text}"
	);
}

/// Below both thresholds the function returns Continue and the message
/// is left untouched: mailbox stays None and `X-Spam-Status` is not
/// injected.
#[tokio::test]
async fn score_below_thresholds_is_a_no_op() {
	let scorer = TrustedScorer::new(0.10);
	let body = b"From: a@b\r\n\r\nbody\r\n".to_vec();
	let original_data = body.clone();
	let mut message = sample_message("alice@example.org", &body);
	let server = bayes_server(Arc::new(MemorySink::new()), scorer, 0.95, Some(0.99));
	let mut sink = Vec::<u8>::new();
	let outcome = server
		.handle_bayes_thresholds(&mut message, false, &mut sink)
		.await
		.expect("call");
	assert_eq!(outcome, BayesOutcome::Continue);
	assert!(
		message.mailbox.is_none(),
		"a clean message must not be redirected"
	);
	assert_eq!(
		message.data, original_data,
		"the raw bytes must not grow an X-Spam-Status header"
	);
}

/// An unauthenticated session is the documented hot path; an
/// authenticated one is the documented cold path and must never be
/// scored or punished. The test toggles `is_authenticated` and
/// observes the same Continue outcome with a high-score scorer.
#[tokio::test]
async fn an_authenticated_session_is_never_scored() {
	let scorer = TrustedScorer::new(1.0);
	let mut message = sample_message("alice@example.org", b"From: a@b\r\n\r\nbody\r\n");
	let server = bayes_server(Arc::new(MemorySink::new()), scorer, 0.95, Some(0.5));
	let mut sink = Vec::<u8>::new();
	let outcome = server
		.handle_bayes_thresholds(&mut message, true, &mut sink)
		.await
		.expect("call");
	assert_eq!(outcome, BayesOutcome::Continue);
}

/// The minimum-training guard: a corpus below the trusted threshold is
/// `is_trusted(scope) == false`, so the pass must not score, junk or
/// reject anything. The scorer reports an absurdly high score, but the
/// guard precedes the score. Without the guard the same input would
/// trip `bayes_reject_at`.
#[tokio::test]
async fn an_untrained_corpus_never_junks() {
	let base = TrustedScorer::new(1.0);
	let scorer = base.with_trusted(false);
	let mut message = sample_message("alice@example.org", b"From: a@b\r\n\r\nbody\r\n");
	let server = bayes_server(Arc::new(MemorySink::new()), scorer, 0.95, Some(0.5));
	let mut sink = Vec::<u8>::new();
	let outcome = server
		.handle_bayes_thresholds(&mut message, false, &mut sink)
		.await
		.expect("call");
	assert_eq!(outcome, BayesOutcome::Continue);
}

/// A bounce (the null reverse path) is not a recipient-bound message and
/// carries no useful spam signal. The pass must skip it even at
/// extreme scores so a delivery-status DSN does not end up in Junk.
#[tokio::test]
async fn a_bounce_is_never_junked() {
	let scorer = TrustedScorer::new(1.0);
	let mut message = sample_message("", b"From: a@b\r\n\r\nbody\r\n");
	let server = bayes_server(Arc::new(MemorySink::new()), scorer, 0.95, Some(0.5));
	let mut sink = Vec::<u8>::new();
	let outcome = server
		.handle_bayes_thresholds(&mut message, false, &mut sink)
		.await
		.expect("call");
	assert_eq!(outcome, BayesOutcome::Continue);
	assert!(
		message.mailbox.is_none(),
		"bounces must keep the default mailbox hint"
	);
}
