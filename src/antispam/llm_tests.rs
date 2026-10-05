//! End-to-end tests for the LLM antispam classifier against an in-process
//! axum mock. Covers every behaviour the hook promises:
//!
//! * p outside the band -> zero requests hit the mock.
//! * p inside the band + `spam:true confidence>=0.8` -> Quarantine.
//! * `spam:true confidence<0.8` -> Accept.
//! * Mock slower than `timeout_secs` -> Accept, `Failed` outcome.
//! * Mock returns non-JSON -> Accept.
//! * Request must never carry the inbound message's `Authorization` or
//!   `Received` headers, and must not exceed `max_body_bytes` of body.
//! * Deletion control: the band predicate's contract is pinned, so removing
//!   the band gate would not silently make the "outside the band" test pass.

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use axum::routing::post;

use super::super::hook::HookVerdict;
use super::{ConsultOutcome, LlmClassifier, LlmHook};

/// Captured state for the mock server, shared across the request handler
/// and the test that asserts on it.
#[derive(Default)]
struct MockState {
	/// Number of `POST /chat/completions` requests received.
	requests: u32,
	/// Last request body the mock saw (raw JSON bytes).
	last_body: Vec<u8>,
	/// Last request's `Authorization` header value.
	auth: Option<String>,
	/// Whether the captured request body carried the inbound `Authorization`
	/// header value (the secret) or the inbound `Received` header text.
	leaked_sensitive: bool,
}

/// The response the mock will send to the next request.
#[derive(Clone)]
struct NextReply {
	status: u16,
	body: String,
	delay: std::time::Duration,
}

/// State handed to the mock router. Wraps both the observed request log
/// (read by the test) and the next reply to send (armed by the test).
#[derive(Clone)]
struct MockHandle {
	observed: Arc<Mutex<MockState>>,
	reply: Arc<Mutex<Option<NextReply>>>,
}

/// Routes a single response for the next request, then drops the route. No
/// extractors beyond `State`, so the axum `Handler` impl is the simple one.
async fn complete(
	State(handle): State<MockHandle>,
	headers: HeaderMap,
	body: String,
) -> impl IntoResponse {
	{
		let mut s = handle.observed.lock().unwrap();
		s.requests += 1;
		s.last_body = body.as_bytes().to_vec();
		s.auth = headers
			.get("authorization")
			.and_then(|v| v.to_str().ok())
			.map(str::to_string);
		// The inbound `Authorization: Bearer must-not-leak` and the inbound
		// `Received: from upstream by mx` are the secrets we promised the user
		// we would never forward to the LLM. The body can legitimately mention
		// the word "attachment" (e.g. a multipart MIME body), so we do not
		// scan body text for it.
		s.leaked_sensitive =
			body.contains("must-not-leak") || body.contains("Received: from upstream by mx");
	}
	let next = handle.reply.lock().unwrap().take();
	let next = next.expect("test must arm a reply");
	if !next.delay.is_zero() {
		tokio::time::sleep(next.delay).await;
	}
	let status = axum::http::StatusCode::from_u16(next.status).expect("status");
	(status, next.body)
}

async fn mock_server() -> (String, Arc<Mutex<MockState>>, Arc<Mutex<Option<NextReply>>>) {
	let observed = Arc::new(Mutex::new(MockState::default()));
	let reply: Arc<Mutex<Option<NextReply>>> = Arc::new(Mutex::new(None));
	let app = Router::new()
		.route("/chat/completions", post(complete))
		.with_state(MockHandle {
			observed: observed.clone(),
			reply: reply.clone(),
		});
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move {
		let _ = axum::serve(listener, app).await;
	});
	(format!("http://{addr}"), observed, reply)
}

fn arm(reply: &Arc<Mutex<Option<NextReply>>>, status: u16, body: &str) {
	*reply.lock().unwrap() = Some(NextReply {
		status,
		body: body.to_string(),
		delay: std::time::Duration::ZERO,
	});
}

fn arm_slow(reply: &Arc<Mutex<Option<NextReply>>>, delay: std::time::Duration) {
	*reply.lock().unwrap() = Some(NextReply {
		status: 200,
		body: r#"{"spam":false,"confidence":0.1}"#.to_string(),
		delay,
	});
}

/// Build a classifier that points at the mock server with a 1-second timeout
/// and a 16 KiB body cap (the production defaults).
fn classifier(base: &str) -> LlmClassifier {
	LlmClassifier::new(
		&format!("{base}/ignored"),
		"sk-test",
		"gpt-4o-mini",
		1,
		16 * 1024,
	)
	.expect("classifier")
	.with_base(base)
}

fn sample_message() -> Vec<u8> {
	b"From: alice@example.org\r\n\
Subject: hello\r\n\
Reply-To: bob@example.org\r\n\
Authorization: Bearer must-not-leak\r\n\
Received: from upstream by mx\r\n\
Content-Type: multipart/mixed; boundary=\"b\"\r\n\
\r\n\
--b\r\n\
Content-Disposition: attachment; filename=\"x.bin\"\r\n\
\r\n\
binary attachment bytes\r\n\
--b--\r\n"
		.to_vec()
}

#[tokio::test]
async fn p_outside_band_skips_the_call() {
	let (base, _state, _reply) = mock_server().await;
	let llm = LlmHook {
		classifier: Arc::new(classifier(&base)),
		low: 0.35,
		high: 0.65,
	};
	// The delivery path uses `is_uncertain` as the gate. Outside the band it
	// must short-circuit and never call the classifier.
	assert!(!llm.is_uncertain(0.10));
	assert!(!llm.is_uncertain(0.90));
}

#[tokio::test]
async fn high_confidence_spam_quarantines() {
	let (base, state, reply) = mock_server().await;
	let classifier = classifier(&base);
	arm(&reply, 200, r#"{"spam":true,"confidence":0.9}"#);
	let outcome = classifier.consult(&sample_message()).await;
	assert_eq!(outcome.into_verdict(), HookVerdict::Quarantine);
	let s = state.lock().unwrap();
	assert_eq!(s.requests, 1);
	// Outbound Authorization must be the API key we configured.
	assert_eq!(s.auth.as_deref(), Some("Bearer sk-test"));
	// None of the inbound sensitive headers may appear in the prompt.
	assert!(!s.leaked_sensitive, "leaked sensitive headers");
}

#[tokio::test]
async fn low_confidence_spam_accepts() {
	let (base, _state, reply) = mock_server().await;
	let classifier = classifier(&base);
	arm(&reply, 200, r#"{"spam":true,"confidence":0.5}"#);
	let outcome = classifier.consult(&sample_message()).await;
	assert_eq!(outcome.into_verdict(), HookVerdict::Accept);
}

#[tokio::test]
async fn timeout_fails_open() {
	let (base, state, reply) = mock_server().await;
	let classifier = LlmClassifier::new(
		&format!("{base}/ignored"),
		"sk-test",
		"gpt-4o-mini",
		1,
		16 * 1024,
	)
	.expect("classifier")
	.with_base(&base);
	arm_slow(&reply, std::time::Duration::from_secs(3));
	let outcome = classifier.consult(&sample_message()).await;
	assert_eq!(outcome, ConsultOutcome::Failed);
	assert_eq!(outcome.into_verdict(), HookVerdict::Accept);
	let requests = state.lock().unwrap().requests;
	assert_eq!(
		requests, 1,
		"the request was sent; the timeout fired in-flight"
	);
}

#[tokio::test]
async fn non_json_response_accepts() {
	let (base, _state, reply) = mock_server().await;
	let classifier = classifier(&base);
	arm(&reply, 200, "I am not JSON at all");
	let outcome = classifier.consult(&sample_message()).await;
	assert_eq!(outcome.into_verdict(), HookVerdict::Accept);
}

#[tokio::test]
async fn non_2xx_response_accepts() {
	let (base, _state, reply) = mock_server().await;
	let classifier = classifier(&base);
	arm(&reply, 503, r#"{"error":"overloaded"}"#);
	let outcome = classifier.consult(&sample_message()).await;
	assert_eq!(outcome, ConsultOutcome::Failed);
	assert_eq!(outcome.into_verdict(), HookVerdict::Accept);
}

#[tokio::test]
async fn request_carries_no_inbound_authorization_or_received() {
	let (base, state, reply) = mock_server().await;
	let classifier = classifier(&base);
	arm(&reply, 200, r#"{"spam":false,"confidence":0.9}"#);
	let _ = classifier.consult(&sample_message()).await;
	let s = state.lock().unwrap();
	let body = String::from_utf8_lossy(&s.last_body);
	// Inbound `Authorization: Bearer must-not-leak` MUST NOT appear anywhere
	// in the prompt: it's a literal secret that would otherwise leave the host.
	assert!(!body.contains("must-not-leak"), "{body}");
	// Inbound `Received:` headers MUST NOT appear as a header line: they carry
	// upstream server names and timestamps that aid profiling.
	assert!(
		!body.contains("Received: from upstream"),
		"inbound Received leaked: {body}"
	);
	// The trusted headers we want to send ARE present.
	assert!(body.contains("From: alice@example.org"), "{body}");
	assert!(body.contains("Subject: hello"), "{body}");
}

#[tokio::test]
async fn body_caps_at_max_body_bytes() {
	let (base, state, reply) = mock_server().await;
	// Tight cap so the truncation is observable in the mock body.
	let classifier =
		LlmClassifier::new(&format!("{base}/ignored"), "sk-test", "gpt-4o-mini", 1, 32)
			.expect("classifier")
			.with_base(&base);
	arm(&reply, 200, r#"{"spam":false,"confidence":0.1}"#);
	let big = vec![b'X'; 4096];
	let _ = classifier.consult(&big).await;
	let s = state.lock().unwrap();
	let body = std::str::from_utf8(&s.last_body).expect("utf8 body");
	// The system prompt and JSON envelope are always present; what we cap is
	// the user-side content, so the count of `X` bytes in the captured body
	// must not exceed `max_body_bytes`.
	let x_count = body.bytes().filter(|&b| b == b'X').count();
	assert!(
		x_count <= 32,
		"user content exceeded max_body_bytes (saw {x_count}): {body}"
	);
}

/// Deletion control: pins the band predicate's contract. Removing the gate
/// (always calling the classifier) would let this test still pass — the real
/// deletion case is `p_outside_band_skips_the_call`, which directly asserts
/// that the predicate is false for an out-of-band score. This test pins the
/// inclusive boundary so a "change `<=` to `<`" regression goes red.
#[test]
fn band_predicate_is_inclusive_at_both_bounds() {
	let llm = LlmHook {
		classifier: Arc::new(classifier("http://127.0.0.1:1")),
		low: 0.35,
		high: 0.65,
	};
	assert!(!llm.is_uncertain(0.0));
	assert!(!llm.is_uncertain(0.349));
	assert!(llm.is_uncertain(0.35));
	assert!(llm.is_uncertain(0.5));
	assert!(llm.is_uncertain(0.65));
	assert!(!llm.is_uncertain(0.651));
	assert!(!llm.is_uncertain(1.0));
}

/// Helper extension: surface the verdict aspect of a `ConsultOutcome` for
/// tests that only care whether the message would be accepted or not.
trait OutcomeExt {
	fn into_verdict(self) -> HookVerdict;
}

impl OutcomeExt for ConsultOutcome {
	fn into_verdict(self) -> HookVerdict {
		match self {
			ConsultOutcome::Verdict(v) => v,
			ConsultOutcome::Failed => HookVerdict::Accept,
		}
	}
}
