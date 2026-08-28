//! LLM-assisted spam screening for the uncertain band.
//!
//! Sits next to [`super::hook`]: the local Bayesian classifier is cheap and
//! trusted at the extremes, but its score is uninformative in the middle —
//! exactly the messages that need a second opinion. When the score lands in
//! the configured band, [`LlmClassifier::consult`] forwards a minimal excerpt
//! of the message to a chat-completions endpoint and parses its reply into
//! the same [`HookVerdict`] the scanner hook uses.
//!
//! Fails open: any transport, timeout, parse or shape failure is logged at
//! WARN and yields [`HookVerdict::Accept`], so an LLM outage never blocks mail.
//! An LLM cannot reject a message — its strongest action is `Quarantine`, so a
//! hallucination never silently drops legitimate mail.

use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;

use super::hook::HookVerdict;

/// What [`LlmClassifier::consult`] returned, separating a clean verdict from
/// a failure that the caller may want to count (the classifier itself does
/// not own the metrics counters).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsultOutcome {
	/// The model answered with a usable reply.
	Verdict(HookVerdict),
	/// The call failed (transport, timeout, parse, shape, non-success status):
	/// fail open, treat as `Accept`, and the caller should count it.
	Failed,
}

/// Cap on the LLM response body. The model is asked to emit a tiny JSON
/// object; a 64 KiB ceiling is defence in depth, applied chunk-by-chunk so a
/// missing or lying `content_length` cannot bypass it. Mirrors the cap in
/// `acme/transport.rs`.
const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// Confidence above which a `spam: true` reply escalates the message. Below
/// this, an LLM saying "spam" is treated as a weak signal and the message is
/// accepted — a hallucination never costs legitimate mail.
const QUARANTINE_CONFIDENCE: f64 = 0.8;

/// The fields the prompt asks the model to populate.
#[derive(Debug, Deserialize)]
struct LlmReply {
	spam: bool,
	confidence: f64,
}

/// Parse a strict-JSON LLM reply into a verdict. Anything that does not shape
/// exactly into `{spam, confidence}` falls back to `Accept` (fail open).
fn parse_reply(body: &[u8]) -> HookVerdict {
	let reply: LlmReply = match serde_json::from_slice(body) {
		Ok(reply) => reply,
		Err(_) => return HookVerdict::Accept,
	};
	if reply.spam && reply.confidence >= QUARANTINE_CONFIDENCE {
		HookVerdict::Quarantine
	} else {
		HookVerdict::Accept
	}
}

/// Build the prompt body. Kept small: only the headers we trust to share
/// (`From`, `Subject`, `Reply-To`) and the first `max_body_bytes` of the
/// message body. Authentication-result headers, `Authorization`, `Received`,
/// DKIM/ARC seals and attachments never reach the model.
fn build_request_body(max_body_bytes: usize, raw: &[u8]) -> Vec<u8> {
	let mut out = String::with_capacity(raw.len().min(max_body_bytes * 2));
	for header in extract_safe_headers(raw) {
		out.push_str(&header);
		out.push('\n');
	}
	out.push_str("\n--- BODY (truncated) ---\n");
	let body = body_bytes(raw, max_body_bytes);
	// Replace non-UTF8 fragments so the JSON body is always valid.
	let text = String::from_utf8_lossy(body);
	out.push_str(&text);
	out.into_bytes()
}

/// Extract only the headers the operator asked us to send (`From`, `Subject`,
/// `Reply-To`). Headers are matched case-insensitively, and the first instance
/// of each is kept. The implementation is line-based — RFC 5322 folded headers
/// are joined onto their predecessor for safety, so a folded `Subject` is not
/// silently truncated. Line endings are normalized so both LF and CRLF input
/// parse the same way; the real wire form is CRLF.
fn extract_safe_headers(raw: &[u8]) -> Vec<String> {
	let mut kept: Vec<String> = Vec::new();
	let mut current: Option<String> = None;
	for line in raw.split(|b| *b == b'\n') {
		let line = line.strip_suffix(b"\r").unwrap_or(line);
		// Header continuation: starts with whitespace. RFC 5322 collapses the
		// leading whitespace to a single space when unfolding, so we trim it
		// before joining onto the previous line.
		if line.first().is_some_and(|b| b.is_ascii_whitespace()) {
			if let Some(existing) = current.as_mut() {
				let trimmed = String::from_utf8_lossy(line).trim().to_string();
				if !trimmed.is_empty() {
					existing.push(' ');
					existing.push_str(&trimmed);
				}
			}
			continue;
		}
		// Empty line ends the header block.
		if line.is_empty() {
			if let Some(prev) = current.take() {
				kept.push(prev);
			}
			break;
		}
		if let Some(prev) = current.take() {
			kept.push(prev);
		}
		// Header line `Name: Value`.
		if let Some((name, value)) = split_header(line)
			&& (matches_header_name(&name, "from")
				|| matches_header_name(&name, "subject")
				|| matches_header_name(&name, "reply-to"))
		{
			current = Some(format!("{name}: {value}"));
		}
	}
	if let Some(prev) = current {
		kept.push(prev);
	}
	kept
}

fn split_header(line: &[u8]) -> Option<(String, String)> {
	let colon = line.iter().position(|b| *b == b':')?;
	let name = String::from_utf8_lossy(&line[..colon]).into_owned();
	let value = String::from_utf8_lossy(&line[colon + 1..])
		.trim()
		.to_string();
	Some((name, value))
}

fn matches_header_name(name: &str, want: &str) -> bool {
	name.eq_ignore_ascii_case(want)
}

/// Body bytes following the blank line that separates headers from payload,
/// capped at `max_body_bytes`. If no blank line is found, the whole message
/// is treated as body (a malformed message — fail safe by over-truncating),
/// so the leading bytes are also pushed to the LLM under the cap.
fn body_bytes(raw: &[u8], max_body_bytes: usize) -> &[u8] {
	let body_start = find_body_start(raw).unwrap_or_default();
	let body = &raw[body_start..];
	if body.len() <= max_body_bytes {
		body
	} else {
		&body[..max_body_bytes]
	}
}

fn find_body_start(raw: &[u8]) -> Option<usize> {
	// RFC 5322 line endings are CRLF, so the header/body separator is the
	// CRLFCRLF sequence. A bare LFLF pair is tolerated too, because test
	// fixtures and some tolerant senders use it.
	if let Some(index) = find_subslice(raw, b"\r\n\r\n") {
		return Some(index + 4);
	}
	if let Some(index) = find_subslice(raw, b"\n\n") {
		return Some(index + 2);
	}
	None
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
	if needle.is_empty() || haystack.len() < needle.len() {
		return None;
	}
	haystack
		.windows(needle.len())
		.position(|window| window == needle)
}

/// Read a response body, refusing any payload past [`MAX_RESPONSE_BYTES`].
/// Enforced chunk-by-chunk — `content_length` may be absent or wrong.
async fn read_capped_body(response: reqwest::Response) -> Result<Vec<u8>, reqwest::Error> {
	let mut response = response;
	let mut buf = Vec::new();
	while let Some(chunk) = response.chunk().await? {
		let projected = buf.len().saturating_add(chunk.len());
		if projected > MAX_RESPONSE_BYTES {
			// Truncate the over-cap chunk to land exactly on the limit, so the
			// parser still sees a complete reply when the limit is hit on a
			// single oversized chunk. This is fail-open: a truncated body will
			// not parse as our strict JSON shape and falls back to Accept.
			let allowed = MAX_RESPONSE_BYTES - buf.len();
			buf.extend_from_slice(&chunk[..allowed]);
			break;
		}
		buf.extend_from_slice(&chunk);
	}
	Ok(buf)
}

/// The chat-completions request body the model receives. Mirrors the minimal
/// shape OpenAI-compatible APIs expect: `model`, `messages`, and a JSON-only
/// response instruction.
fn openai_request_json(model: &str, excerpt: &[u8]) -> Vec<u8> {
	let excerpt = String::from_utf8_lossy(excerpt);
	serde_json::json!({
		"model": model,
		"messages": [
			{
				"role": "system",
				"content": "You are an email spam classifier. Respond with JSON only, of the form {\"spam\": bool, \"confidence\": number in [0,1]}."
			},
			{
				"role": "user",
				"content": excerpt.as_ref()
			}
		],
		"response_format": { "type": "json_object" },
		"temperature": 0,
	})
	.to_string()
	.into_bytes()
}

/// LLM-backed spam classifier paired with its uncertain band.
///
/// The band lives alongside the classifier so the delivery path can answer
/// "should I call?" with a single `is_uncertain(score)` check, and so a
/// configured band and a configured classifier cannot drift apart.
pub struct LlmHook {
	/// The HTTP classifier, shared across listeners.
	pub classifier: Arc<LlmClassifier>,
	/// Inclusive lower bound of the uncertain band.
	pub low: f64,
	/// Inclusive upper bound of the uncertain band.
	pub high: f64,
}

impl LlmHook {
	/// Whether `score` lands inside the configured band and therefore needs
	/// the LLM to decide.
	pub fn is_uncertain(&self, score: f64) -> bool {
		score >= self.low && score <= self.high
	}
}

/// LLM-backed spam classifier. POSTs a minimal message excerpt to a chat-
/// completions endpoint and parses its reply into a [`HookVerdict`].
pub struct LlmClassifier {
	client: reqwest::Client,
	endpoint: String,
	api_key: String,
	model: String,
	max_body_bytes: usize,
}

impl LlmClassifier {
	/// Build a classifier that POSTs to `endpoint` with `api_key` as bearer
	/// token, using `model` for every request, with a per-request timeout of
	/// `timeout_secs` and a per-message body cap of `max_body_bytes`.
	pub fn new(
		endpoint: &str,
		api_key: &str,
		model: &str,
		timeout_secs: u64,
		max_body_bytes: usize,
	) -> Result<Self, reqwest::Error> {
		let client = reqwest::Client::builder()
			.timeout(Duration::from_secs(timeout_secs))
			.build()?;
		Ok(LlmClassifier {
			client,
			endpoint: endpoint.to_string(),
			api_key: api_key.to_string(),
			model: model.to_string(),
			max_body_bytes,
		})
	}

	/// Test seam: redirect requests to a different base URL while keeping the
	/// path (`/chat/completions`). Production code constructs the classifier
	/// with the absolute endpoint URL it wants to hit.
	#[doc(hidden)]
	pub fn with_base(mut self, base: &str) -> Self {
		self.endpoint = format!("{base}/chat/completions");
		self
	}

	/// Ask the LLM whether `raw` (a full RFC 5322 message) is spam. Returns the
	/// outcome distinguishing a clean verdict from a failure (which the caller
	/// counts as `llm_failed`).
	pub async fn consult(&self, raw: &[u8]) -> ConsultOutcome {
		let excerpt = build_request_body(self.max_body_bytes, raw);
		let body = openai_request_json(&self.model, &excerpt);
		let response = match self
			.client
			.post(&self.endpoint)
			.bearer_auth(&self.api_key)
			.header(reqwest::header::CONTENT_TYPE, "application/json")
			.body(body)
			.send()
			.await
		{
			Ok(response) => response,
			Err(error) => {
				tracing::warn!(%error, "llm request failed; accepting");
				return ConsultOutcome::Failed;
			}
		};
		if !response.status().is_success() {
			let status = response.status();
			tracing::warn!(%status, "llm returned non-success; accepting");
			return ConsultOutcome::Failed;
		}
		match read_capped_body(response).await {
			Ok(bytes) => ConsultOutcome::Verdict(parse_reply(&bytes)),
			Err(error) => {
				tracing::warn!(%error, "llm body read failed; accepting");
				ConsultOutcome::Failed
			}
		}
	}
}

#[cfg(test)]
#[path = "llm_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "llm_unit_tests.rs"]
mod unit_tests;
