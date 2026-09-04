//! SMTP-level tests for SubjectPass.
//!
//! Split out of `server_tests.rs` to stay under the line limit, matching
//! the precedent set by `server_tests_auth.rs`.

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::smtp::sink::MemorySink;

fn subjectpass_directory() -> DirectoryHandle {
	DirectoryHandle::new(Directory::new(
		["example.org".to_string()],
		[
			("alice@example.org".to_string(), "alice".to_string()),
			("bob@example.org".to_string(), "bob".to_string()),
			("b@example.org".to_string(), "bob".to_string()),
		],
	))
}

/// DNS stub that lists 192.0.2.7 on the `bl.example` blocklist. Copied
/// from `server_tests.rs` because the struct lives in that module and is
/// not reachable across the test-module boundary.
struct SubjectpassListingDns;

type DnsFuture<'a, T> =
	std::pin::Pin<Box<dyn Future<Output = Result<T, crate::spf::DnsFailure>> + Send + 'a>>;

impl crate::spf::DnsLookup for SubjectpassListingDns {
	fn txt(&self, _name: &str) -> DnsFuture<'_, Vec<String>> {
		Box::pin(async { Ok(Vec::new()) })
	}

	fn addresses(&self, name: &str) -> DnsFuture<'_, Vec<std::net::IpAddr>> {
		let listed = name == "7.2.0.192.bl.example";
		Box::pin(async move {
			Ok(if listed {
				vec!["127.0.0.2".parse().expect("ip")]
			} else {
				Vec::new()
			})
		})
	}

	fn mx(&self, _name: &str) -> DnsFuture<'_, Vec<String>> {
		Box::pin(async { Ok(Vec::new()) })
	}
}

/// Deterministic Bayesian scorer for the SubjectPass tests: always returns
/// the same fixed probability so the SMTP path's "is_uncertain" branch is
/// taken without a real database. The training path is a no-op (no DB to
/// write to); the SMTP tests assert the message is *not* stored when the
/// challenge fires and *is* stored when the retry passes.
struct FixedScorer(f64);

impl crate::antispam::corpus::BayesScorer for FixedScorer {
	fn score<'a>(
		&'a self,
		_scope: &'a str,
		_text: &'a str,
	) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<f64, sqlx::Error>> + Send + 'a>>
	{
		let score = self.0;
		Box::pin(async move { Ok(score) })
	}
}

fn subjectpass_script(body_extra: &[u8]) -> Vec<u8> {
	let mut script = b"EHLO client.example.org\r\n\
MAIL FROM:<alice@example.org>\r\n\
RCPT TO:<bob@example.org>\r\n\
DATA\r\n"
		.to_vec();
	script.extend_from_slice(body_extra);
	script.extend_from_slice(b".\r\nQUIT\r\n");
	script
}

fn subject_pass() -> crate::antispam::subjectpass::SubjectPass {
	// Deterministic key: the tests issue their own tokens against this
	// SubjectPass instance and then paste the same instance's output into
	// the script.
	crate::antispam::subjectpass::SubjectPass::with_key([0xAB; 32])
}

#[tokio::test]
async fn an_uncertain_message_without_an_llm_is_challenged_with_a_token() {
	// A real sender retrying after the tempfail is the desired behaviour,
	// so the test asserts the 450 carries a token the sender can paste.
	let sink = Arc::new(MemorySink::new());
	let scorer: Arc<dyn crate::antispam::corpus::BayesScorer> = Arc::new(FixedScorer(0.5));
	let server = Server::new("mail.example.org", sink.clone() as Arc<dyn MessageSink>)
		.with_directory(subjectpass_directory())
		.with_bayes(scorer)
		.with_subjectpass(subject_pass());

	let (client, server_stream) = tokio::io::duplex(64 * 1024);
	let task = tokio::spawn(async move { server.handle(server_stream, None).await });

	let script = subjectpass_script(b"Subject: hello\r\n\r\nbody\r\n");
	let (mut client_read, mut client_write) = tokio::io::split(client);
	client_write.write_all(&script).await.expect("write");
	client_write.shutdown().await.expect("shutdown");
	let mut output = Vec::new();
	client_read.read_to_end(&mut output).await.expect("read");
	task.await.expect("task").expect("server result");

	let output = String::from_utf8(output).expect("ascii");
	assert!(
		output.contains("450 4.7.1"),
		"expected the 450 challenge reply, got: {output}"
	);
	assert!(
		output.contains("EP-"),
		"expected a SubjectPass token in the reply, got: {output}"
	);
	assert!(
		output.contains("resend"),
		"expected the human-readable retry hint, got: {output}"
	);
	// The message must not have been stored or trained as spam.
	assert!(
		sink.messages().is_empty(),
		"challenged message must not be stored"
	);
}

#[tokio::test]
async fn the_retry_with_the_token_in_the_subject_is_accepted() {
	// Mint a token for (alice@example.org, bob@example.org, today), then
	// resend with the token in the subject: the SMTP path must accept it.
	let pass = subject_pass();
	let token = pass.issue("alice@example.org", "bob@example.org", unix_day_now());

	let sink = Arc::new(MemorySink::new());
	let scorer: Arc<dyn crate::antispam::corpus::BayesScorer> = Arc::new(FixedScorer(0.5));
	let server = Server::new("mail.example.org", sink.clone() as Arc<dyn MessageSink>)
		.with_directory(subjectpass_directory())
		.with_bayes(scorer)
		.with_subjectpass(pass);

	let (client, server_stream) = tokio::io::duplex(64 * 1024);
	let task = tokio::spawn(async move { server.handle(server_stream, None).await });

	let body = format!("Subject: retry {token}\r\n\r\nbody\r\n");
	let script = subjectpass_script(body.as_bytes());
	let (mut client_read, mut client_write) = tokio::io::split(client);
	client_write.write_all(&script).await.expect("write");
	client_write.shutdown().await.expect("shutdown");
	let mut output = Vec::new();
	client_read.read_to_end(&mut output).await.expect("read");
	task.await.expect("task").expect("server result");

	let output = String::from_utf8(output).expect("ascii");
	assert!(
		!output.contains("450 4.7.1"),
		"the retry should not be challenged again, got: {output}"
	);
	// The token-bearing retry is accepted: the message lands in the sink.
	assert_eq!(sink.messages().len(), 1, "expected the retry to be stored");
	let stored = String::from_utf8(sink.messages()[0].data.clone()).expect("ascii");
	assert!(
		stored.contains(&token),
		"the stored message should still carry the token in the subject: {stored}"
	);
}

#[tokio::test]
async fn a_listed_client_is_still_refused_even_with_a_valid_token() {
	// The check runs after DNSBL/SPF/DMARC and the scanner hook, so a
	// valid token never overrides a hard rejection. ListingDns (defined
	// in `server_tests.rs`) lists 192.0.2.7 on the `bl.example` zone.
	let pass = subject_pass();
	let token = pass.issue("alice@example.org", "bob@example.org", unix_day_now());

	let sink = Arc::new(MemorySink::new());
	let scorer: Arc<dyn crate::antispam::corpus::BayesScorer> = Arc::new(FixedScorer(0.5));
	let server = Server::new("mail.example.org", sink.clone() as Arc<dyn MessageSink>)
		.with_directory(subjectpass_directory())
		.with_spf(Arc::new(SubjectpassListingDns))
		.with_dnsbl(crate::dnsbl::Dnsbl::new(["bl.example".to_string()]))
		.with_bayes(scorer)
		.with_subjectpass(pass);

	let (client, server_stream) = tokio::io::duplex(64 * 1024);
	let peer = Some("192.0.2.7".parse().expect("ip"));
	let task = tokio::spawn(async move { server.handle(server_stream, peer).await });

	let body = format!("Subject: retry {token}\r\n\r\nbody\r\n");
	let script = subjectpass_script(body.as_bytes());
	let (mut client_read, mut client_write) = tokio::io::split(client);
	client_write.write_all(&script).await.expect("write");
	client_write.shutdown().await.expect("shutdown");
	let mut output = Vec::new();
	client_read.read_to_end(&mut output).await.expect("read");
	task.await.expect("task").expect("server result");

	let output = String::from_utf8(output).expect("ascii");
	assert!(
		output.contains("554") && output.contains("DNS blocklist"),
		"a listed client must be refused regardless of the token, got: {output}"
	);
	assert!(sink.messages().is_empty(), "listed client must not deliver");
}

#[tokio::test]
async fn with_subjectpass_off_the_band_behaves_as_before() {
	// No subjectpass wired in: a Bayes score of 0.5 with no LLM hook must
	// be accepted (the prior behaviour, where the band only acts when an
	// LLM is configured to decide).
	let sink = Arc::new(MemorySink::new());
	let scorer: Arc<dyn crate::antispam::corpus::BayesScorer> = Arc::new(FixedScorer(0.5));
	let server = Server::new("mail.example.org", sink.clone() as Arc<dyn MessageSink>)
		.with_directory(subjectpass_directory())
		.with_bayes(scorer);

	let (client, server_stream) = tokio::io::duplex(64 * 1024);
	let task = tokio::spawn(async move { server.handle(server_stream, None).await });

	let script = subjectpass_script(b"Subject: hello\r\n\r\nbody\r\n");
	let (mut client_read, mut client_write) = tokio::io::split(client);
	client_write.write_all(&script).await.expect("write");
	client_write.shutdown().await.expect("shutdown");
	let mut output = Vec::new();
	client_read.read_to_end(&mut output).await.expect("read");
	task.await.expect("task").expect("server result");

	let output = String::from_utf8(output).expect("ascii");
	assert!(
		!output.contains("450 4.7.1"),
		"with subjectpass off, no challenge must be issued, got: {output}"
	);
	assert_eq!(sink.messages().len(), 1);
}

/// `unix_day_now` mirrors the helper in `run.rs`; redeclared here so the
/// test's token matches the server's verifier clock.
fn unix_day_now() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs() / 86_400)
		.unwrap_or(0)
}
