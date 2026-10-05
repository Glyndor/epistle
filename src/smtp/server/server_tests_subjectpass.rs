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

/// Directory used by the per-account scope tests: identical to
/// [`subjectpass_directory`] but adds `sales@example.org` as a
/// multi-target alias whose first member is `bob`.
fn alias_directory() -> DirectoryHandle {
	let aliases = [(
		"sales@example.org".to_string(),
		crate::smtp::directory::AliasSpec {
			members: vec![
				"bob@example.org".to_string(),
				"alice@example.org".to_string(),
			],
			senders: Vec::new(),
			hidden: false,
			list_id: None,
		},
	)];
	DirectoryHandle::new(
		Directory::new(
			["example.org".to_string()],
			[
				("alice@example.org".to_string(), "alice".to_string()),
				("bob@example.org".to_string(), "bob".to_string()),
				("b@example.org".to_string(), "bob".to_string()),
			],
		)
		.with_aliases(aliases),
	)
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
	account_score: std::sync::Mutex<Option<f64>>,
	trained: std::sync::Mutex<Vec<bool>>,
	/// Every `account` argument the scorer was asked to score against, in
	/// the order it was asked. The band is expected to consult the scope
	/// that the recipient resolved to, not the envelope address.
	accounts_asked: std::sync::Mutex<Vec<String>>,
}

impl FixedScorer {
	fn new(score: f64) -> Arc<Self> {
		Arc::new(FixedScorer {
			score,
			account_score: std::sync::Mutex::new(Some(score)),
			trained: std::sync::Mutex::new(Vec::new()),
			accounts_asked: std::sync::Mutex::new(Vec::new()),
		})
	}

	/// Force the per-account scorer to `None`, mirroring the DB-hiccup path
	/// where `score_for_account` cannot resolve. `score(scope, text)` still
	/// answers the configured value, so a test that accidentally reaches
	/// for the wrong method is not silently mis-tested.
	fn with_unavailable_account_score(self: &Arc<Self>) {
		*self.account_score.lock().expect("account_score lock") = None;
	}

	fn trained(&self) -> Vec<bool> {
		self.trained.lock().expect("trained lock").clone()
	}

	fn accounts_asked(&self) -> Vec<String> {
		self.accounts_asked
			.lock()
			.expect("accounts_asked lock")
			.clone()
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

	fn score_for_account<'a>(
		&'a self,
		account: &'a str,
		_text: &'a [u8],
	) -> crate::antispam::trainer::TrainerFuture<'a, Option<f64>> {
		self.accounts_asked
			.lock()
			.expect("accounts_asked lock")
			.push(account.to_string());
		let value = *self.account_score.lock().expect("account_score lock");
		Box::pin(async move { value })
	}

	fn train(&self, _scope: &str, _text: &str, spam: bool) {
		self.trained.lock().expect("trained lock").push(spam);
	}
}

const SENDER: &str = "alice@example.org";
const RECIPIENT: &str = "bob@example.org";

fn subjectpass_script(reverse_path: &str, headers_and_body: &[u8]) -> Vec<u8> {
	subjectpass_script_for(reverse_path, RECIPIENT, headers_and_body)
}

/// Same script with the recipient picked by the caller, used by the
/// per-account scope tests that need to deliver to a non-default address.
fn subjectpass_script_for(reverse_path: &str, recipient: &str, headers_and_body: &[u8]) -> Vec<u8> {
	let mut script = format!(
		"EHLO client.example.org\r\nMAIL FROM:<{reverse_path}>\r\nRCPT TO:<{recipient}>\r\nDATA\r\n"
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
	band_server_with(sink, scorer, subjectpass_directory())
}

/// Same as `band_server` but lets the caller pick the directory. The
/// per-account scope tests use this to plug in an alias-aware directory.
fn band_server_with(
	sink: &Arc<MemorySink>,
	scorer: &Arc<FixedScorer>,
	directory: DirectoryHandle,
) -> Server {
	Server::new("mail.example.org", sink.clone() as Arc<dyn MessageSink>)
		.with_directory(directory)
		.with_bayes(scorer.clone() as Arc<dyn crate::antispam::corpus::BayesScorer>)
}

/// Drive one whole SMTP conversation and return everything the server said.
async fn converse(server: Server, peer: Option<std::net::IpAddr>, script: Vec<u8>) -> String {
	let (client, server_stream) = tokio::io::duplex(64 * 1024);
	let driver = tokio::spawn(async move { server.handle(server_stream, peer).await });
	let (mut client_read, mut client_write) = tokio::io::split(client);
	client_write.write_all(&script).await.expect("write");
	client_write.shutdown().await.expect("shutdown");
	let mut output = Vec::new();
	client_read.read_to_end(&mut output).await.expect("read");
	driver.await.expect("driver join").expect("server result");
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

#[tokio::test]
async fn a_null_reverse_path_is_never_challenged() {
	// MAIL FROM:<> is a bounce: the envelope sender is empty, no person
	// will ever paste a token into a bounce subject, and refusing the
	// bounce would break delivery reports. SubjectPass is configured
	// and the Bayes score would otherwise be inside the band, but the
	// band has to step out of the way for the null sender.
	let sink = Arc::new(MemorySink::new());
	let scorer = FixedScorer::new(0.5);
	let server = band_server(&sink, &scorer).with_subjectpass(subject_pass());

	let script = subjectpass_script("", b"Subject: bounce\r\n\r\nbody\r\n");
	let output = converse(server, None, script).await;

	assert!(
		!output.contains("550 5.7.1"),
		"a bounce must not be challenged, got: {output}"
	);
	// The bounce continues down the normal accept path, which trains the
	// ham corpus exactly as any other accepted unauthenticated message.
	assert_eq!(
		scorer.trained(),
		vec![false],
		"a bounce delivered through the normal path trains the ham corpus"
	);
	// Delivery still happened (the bounce reaches its recipient like
	// any other accepted message).
	assert_eq!(sink.messages().len(), 1, "a bounce must be delivered");
}

#[tokio::test]
async fn a_per_account_scorer_returning_none_accepts_without_a_challenge() {
	// The band cannot read a per-account score (DB hiccup or an
	// untrained scope that the corpus could not even resolve). The
	// SMTP path must not punish the message for a backend error:
	// refuse to challenge, accept the message, and let it continue
	// down the normal delivery path.
	let sink = Arc::new(MemorySink::new());
	let scorer = FixedScorer::new(0.5);
	scorer.with_unavailable_account_score();
	let server = band_server(&sink, &scorer).with_subjectpass(subject_pass());

	let script = subjectpass_script(SENDER, b"Subject: hello\r\n\r\nbody\r\n");
	let output = converse(server, None, script).await;

	assert!(
		!output.contains("550 5.7.1"),
		"a missing per-account score must not produce a SubjectPass challenge, got: {output}"
	);
	// The message still flows through the normal accept path and is
	// stored.
	assert_eq!(
		sink.messages().len(),
		1,
		"the message must still be delivered"
	);
}

/// `unix_day_now` mirrors the helper in `run.rs`; redeclared here so the
/// test's token matches the server's verifier clock.
fn unix_day_now() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs() / 86_400)
		.unwrap_or(0)
}

/// The uncertain band must score under the scope of the account the
/// recipient resolves to, not the envelope address. The scorer records
/// every `account` it was asked about, so the test pins both the
/// delivery itself and the scope string the server consulted.
#[tokio::test]
async fn the_band_scores_under_the_resolved_account_scope() {
	let sink = Arc::new(MemorySink::new());
	let scorer = FixedScorer::new(0.5);
	let server = band_server(&sink, &scorer).with_subjectpass(subject_pass());

	// RCPT TO:<alice@example.org>: the band must ask the scorer for
	// `alice`, the directory-resolved account name. The envelope
	// address (`alice@example.org`) would be the wrong key: training
	// writes to the account name, so a query by address always misses
	// the per-account corpus.
	let script = subjectpass_script_for(
		SENDER,
		"alice@example.org",
		b"Subject: hello\r\n\r\nbody\r\n",
	);
	let output = converse(server, None, script).await;
	assert!(
		sink.messages().is_empty(),
		"no SubjectPass token was supplied, so the message must be challenged: {output}"
	);
	assert_eq!(
		scorer.accounts_asked(),
		vec!["alice".to_string()],
		"the band asked the scorer for the envelope address, not the resolved account"
	);
}

/// Same shape, but the recipient is a multi-target alias. The alias's
/// first member is the scope the SMTP server should consult, so the
/// scorer is asked for `bob` (and not for `sales@example.org`).
#[tokio::test]
async fn an_alias_recipient_scores_under_the_first_member_account() {
	let sink = Arc::new(MemorySink::new());
	let scorer = FixedScorer::new(0.5);
	let server =
		band_server_with(&sink, &scorer, alias_directory()).with_subjectpass(subject_pass());

	let script = subjectpass_script_for(
		SENDER,
		"sales@example.org",
		b"Subject: hello\r\n\r\nbody\r\n",
	);
	let output = converse(server, None, script).await;
	assert!(
		sink.messages().is_empty(),
		"no SubjectPass token was supplied, so the message must be challenged: {output}"
	);
	assert_eq!(
		scorer.accounts_asked(),
		vec!["bob".to_string()],
		"the band must score the alias under its first member account"
	);
}

/// A scanner that returned `Quarantine` (an existing disposition) and
/// `SubjectPass` are both configured. Before this fix, the band ran
/// after the scanner and challenged the message with a 550 anyway,
/// discarding the quarantine and teaching the spam corpus on every
/// retry. The band must step out of the way once `mailbox` is set so
/// the scanner's disposition is honoured and a retried message is
/// only ever trained once.
struct QuarantineStubHook;

impl crate::antispam::hook::MailHook for QuarantineStubHook {
	fn scan(
		&self,
		_raw: &[u8],
	) -> std::pin::Pin<Box<dyn Future<Output = crate::antispam::hook::HookVerdict> + Send + '_>> {
		Box::pin(async { crate::antispam::hook::HookVerdict::Quarantine })
	}
}

#[tokio::test]
async fn a_scanner_quarantine_with_subjectpass_does_not_challenge_again() {
	let sink = Arc::new(MemorySink::new());
	let scorer = FixedScorer::new(0.5);
	let server = band_server(&sink, &scorer)
		.with_hook(Arc::new(QuarantineStubHook) as Arc<dyn crate::antispam::hook::MailHook>)
		.with_subjectpass(subject_pass());

	let script = subjectpass_script(SENDER, b"Subject: hello\r\n\r\nbody\r\n");
	let output = converse(server, None, script).await;

	assert!(
		!output.contains("550 5.7.1"),
		"a scanner quarantine must not be re-challenged by SubjectPass; got: {output}"
	);
	// The scanner has decided this is spam and trained it once. The
	// band must not add a second training call on the same message:
	// a challenged discard would have trained nothing, while a
	// retried message would have been trained at least once more.
	assert_eq!(
		scorer.trained(),
		vec![true],
		"only the scanner's spam training call must happen"
	);
}
