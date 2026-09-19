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

/// Bayesian scorer for the SubjectPass tests: always returns the same
/// probability, so the band branch is taken without a database, and records
/// every training call so a test can assert what the server taught the
/// corpus (`true` is spam, `false` is ham).
struct FixedScorer {
	score: f64,
	trained: std::sync::Mutex<Vec<bool>>,
}

impl FixedScorer {
	fn new(score: f64) -> Arc<Self> {
		Arc::new(FixedScorer {
			score,
			trained: std::sync::Mutex::new(Vec::new()),
		})
	}

	fn trained(&self) -> Vec<bool> {
		self.trained.lock().expect("trained lock").clone()
	}
}

impl crate::antispam::corpus::BayesScorer for FixedScorer {
	fn score<'a>(
		&'a self,
		_scope: &'a str,
		_text: &'a str,
	) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<f64, sqlx::Error>> + Send + 'a>>
	{
		let score = self.score;
		Box::pin(async move { Ok(score) })
	}

	fn train(&self, _scope: &str, _text: &str, spam: bool) {
		self.trained.lock().expect("trained lock").push(spam);
	}
}

const SENDER: &str = "alice@example.org";
const RECIPIENT: &str = "bob@example.org";

fn subjectpass_script(reverse_path: &str, headers_and_body: &[u8]) -> Vec<u8> {
	let mut script = format!(
		"EHLO client.example.org\r\nMAIL FROM:<{reverse_path}>\r\nRCPT TO:<{RECIPIENT}>\r\nDATA\r\n"
	)
	.into_bytes();
	script.extend_from_slice(headers_and_body);
	script.extend_from_slice(b".\r\nQUIT\r\n");
	script
}

fn subject_pass() -> crate::antispam::subjectpass::SubjectPass {
	// A fresh key per test: each test issues its own tokens against the
	// instance it hands to the server.
	let mut bytes = [0u8; 32];
	bytes[..16].copy_from_slice(uuid::Uuid::now_v7().as_bytes());
	bytes[16..].copy_from_slice(uuid::Uuid::now_v7().as_bytes());
	crate::antispam::subjectpass::SubjectPass::with_key(bytes)
}

fn band_server(sink: &Arc<MemorySink>, scorer: &Arc<FixedScorer>) -> Server {
	Server::new("mail.example.org", sink.clone() as Arc<dyn MessageSink>)
		.with_directory(subjectpass_directory())
		.with_bayes(scorer.clone() as Arc<dyn crate::antispam::corpus::BayesScorer>)
}

/// Drive one whole SMTP conversation and return everything the server said.
async fn converse(server: Server, peer: Option<std::net::IpAddr>, script: Vec<u8>) -> String {
	let (client, server_stream) = tokio::io::duplex(64 * 1024);
	let task = tokio::spawn(async move { server.handle(server_stream, peer).await });
	let (mut client_read, mut client_write) = tokio::io::split(client);
	client_write.write_all(&script).await.expect("write");
	client_write.shutdown().await.expect("shutdown");
	let mut output = Vec::new();
	client_read.read_to_end(&mut output).await.expect("read");
	task.await.expect("task").expect("server result");
	String::from_utf8(output).expect("ascii")
}

#[tokio::test]
async fn an_uncertain_message_without_an_llm_is_refused_with_a_token() {
	// The refusal is permanent so the sending MTA bounces at once, and the
	// bounce is where the author reads the token.
	let sink = Arc::new(MemorySink::new());
	let scorer = FixedScorer::new(0.5);
	let server = band_server(&sink, &scorer).with_subjectpass(subject_pass());

	let script = subjectpass_script(SENDER, b"Subject: hello\r\n\r\nbody\r\n");
	let output = converse(server, None, script).await;

	assert!(
		output.contains("550 5.7.1 this message needs a human"),
		"expected the 550 challenge reply, got: {output}"
	);
	assert!(
		output.contains("EP-"),
		"expected a SubjectPass token in the reply, got: {output}"
	);
	// A challenged message is neither stored nor taught to the corpus: the
	// server has not decided it is spam, it has asked a question.
	assert!(
		sink.messages().is_empty(),
		"challenged message must not be stored"
	);
	assert_eq!(
		scorer.trained(),
		Vec::<bool>::new(),
		"a challenged message must not train the corpus"
	);
}

#[tokio::test]
async fn the_resend_with_the_token_in_the_subject_is_accepted() {
	let pass = subject_pass();
	let token = pass.issue(SENDER, RECIPIENT, unix_day_now());

	let sink = Arc::new(MemorySink::new());
	let scorer = FixedScorer::new(0.5);
	let server = band_server(&sink, &scorer).with_subjectpass(pass);

	let body = format!("Subject: retry {token}\r\n\r\nbody\r\n");
	let output = converse(server, None, subjectpass_script(SENDER, body.as_bytes())).await;

	assert!(
		!output.contains("550 5.7.1"),
		"the resend should not be challenged again, got: {output}"
	);
	assert_eq!(sink.messages().len(), 1, "expected the resend to be stored");
	let stored = String::from_utf8(sink.messages()[0].data.clone()).expect("ascii");
	assert!(
		stored.contains(&token),
		"the stored message should still carry the token in the subject: {stored}"
	);
	// The accepted resend is ham, the same as any accepted message.
	assert_eq!(scorer.trained(), vec![false]);
}

#[tokio::test]
async fn a_listed_client_is_still_refused_even_with_a_valid_token() {
	// The check runs after DNSBL/SPF/DMARC and the scanner hook, so a
	// valid token never overrides a hard rejection.
	let pass = subject_pass();
	let token = pass.issue(SENDER, RECIPIENT, unix_day_now());

	let sink = Arc::new(MemorySink::new());
	let scorer = FixedScorer::new(0.5);
	let server = band_server(&sink, &scorer)
		.with_spf(Arc::new(SubjectpassListingDns))
		.with_dnsbl(crate::dnsbl::Dnsbl::new(["bl.example".to_string()]))
		.with_subjectpass(pass);

	let peer = Some("192.0.2.7".parse().expect("ip"));
	let body = format!("Subject: retry {token}\r\n\r\nbody\r\n");
	let output = converse(server, peer, subjectpass_script(SENDER, body.as_bytes())).await;

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
	let scorer = FixedScorer::new(0.5);
	let server = band_server(&sink, &scorer);

	let script = subjectpass_script(SENDER, b"Subject: hello\r\n\r\nbody\r\n");
	let output = converse(server, None, script).await;

	assert!(
		!output.contains("550 5.7.1"),
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
