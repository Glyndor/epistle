//! ARC (RFC 8617) chain extraction and structural validation.
//!
//! This layer is pure: it parses the ARC header set out of a raw message,
//! groups the three header types by instance number, and checks the structural
//! rules (contiguous instances 1..N, one of each header per instance, the
//! chain not over the 50-instance cap). Cryptographic validation of the
//! ARC-Message-Signature and ARC-Seal is layered on top separately.

/// RFC 8617 §5.1.1 caps a chain at 50 instances.
pub const MAX_INSTANCE: u32 = 50;

/// The three header types that make up one ARC instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArcKind {
	/// `ARC-Authentication-Results` (AAR).
	AuthResults,
	/// `ARC-Message-Signature` (AMS).
	MessageSignature,
	/// `ARC-Seal` (AS).
	Seal,
}

impl ArcKind {
	fn from_name(name: &str) -> Option<ArcKind> {
		match name.to_ascii_lowercase().as_str() {
			"arc-authentication-results" => Some(ArcKind::AuthResults),
			"arc-message-signature" => Some(ArcKind::MessageSignature),
			"arc-seal" => Some(ArcKind::Seal),
			_ => None,
		}
	}
}

/// The `cv=` chain-validation status carried in an ARC-Seal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainValidation {
	/// `cv=none` — only valid on the first instance (a fresh chain).
	None,
	/// `cv=pass` — the prior chain validated.
	Pass,
	/// `cv=fail` — the chain is broken; no further sealing is meaningful.
	Fail,
}

impl ChainValidation {
	/// Parse a `cv=` value (case-insensitive).
	pub fn parse(value: &str) -> Option<ChainValidation> {
		match value.trim().to_ascii_lowercase().as_str() {
			"none" => Some(ChainValidation::None),
			"pass" => Some(ChainValidation::Pass),
			"fail" => Some(ChainValidation::Fail),
			_ => None,
		}
	}

	/// The wire keyword.
	pub fn as_str(self) -> &'static str {
		match self {
			ChainValidation::None => "none",
			ChainValidation::Pass => "pass",
			ChainValidation::Fail => "fail",
		}
	}
}

/// One ARC instance: the three headers sharing an `i=` value, in the raw
/// (unfolded) form needed for canonicalization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instance {
	/// The instance number `i=` (1-based).
	pub instance: u32,
	/// The `ARC-Authentication-Results` header value.
	pub auth_results: String,
	/// The `ARC-Message-Signature` header value.
	pub message_signature: String,
	/// The `ARC-Seal` header value.
	pub seal: String,
}

/// Why an ARC header set is structurally invalid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainError {
	/// A header was malformed or missing its `i=` tag.
	Malformed,
	/// An instance number was zero or above [`MAX_INSTANCE`].
	BadInstance,
	/// Two headers of the same type shared one instance number.
	Duplicate,
	/// Instances did not form a contiguous run `1..=N`.
	NonContiguous,
	/// An instance was missing one of its three headers.
	Incomplete,
}

/// A single ARC header as it appears in the message, with its parsed instance.
struct RawHeader {
	kind: ArcKind,
	instance: u32,
	value: String,
}

/// Extract and structurally validate the ARC chain.
///
/// Returns `Ok(None)` when the message carries no ARC headers, `Ok(Some(_))`
/// with instances ordered `1..=N` when well-formed, or `Err` otherwise.
pub fn extract(raw: &[u8]) -> Result<Option<Vec<Instance>>, ChainError> {
	let headers = arc_headers(raw)?;
	if headers.is_empty() {
		return Ok(None);
	}

	// Bucket each header into its instance slot. `slots[i]` holds instance i+1.
	let highest = headers.iter().map(|h| h.instance).max().unwrap_or(0);
	if highest == 0 || highest > MAX_INSTANCE {
		return Err(ChainError::BadInstance);
	}
	let mut slots: Vec<[Option<String>; 3]> = (0..highest).map(|_| [None, None, None]).collect();
	for header in headers {
		let slot = &mut slots[(header.instance - 1) as usize][header.kind as usize];
		if slot.is_some() {
			return Err(ChainError::Duplicate);
		}
		*slot = Some(header.value);
	}

	// Every instance 1..=N must be complete and present (contiguous).
	let mut instances = Vec::with_capacity(slots.len());
	for (index, slot) in slots.into_iter().enumerate() {
		let [aar, ams, seal] = slot;
		match (aar, ams, seal) {
			(Some(auth_results), Some(message_signature), Some(seal)) => {
				instances.push(Instance {
					instance: (index + 1) as u32,
					auth_results,
					message_signature,
					seal,
				});
			}
			// A wholly absent instance breaks contiguity; a partial one is
			// an incomplete instance.
			(None, None, None) => return Err(ChainError::NonContiguous),
			_ => return Err(ChainError::Incomplete),
		}
	}
	Ok(Some(instances))
}

/// The chain-validation status of the most recent instance's seal, if the
/// chain is non-empty and the seal carries a parseable `cv=`.
pub fn chain_status(instances: &[Instance]) -> Option<ChainValidation> {
	let last = instances.last()?;
	ChainValidation::parse(tag(&last.seal, "cv")?)
}

/// Read a `key=value` tag from an ARC header value. Values may contain `=`
/// (base64 padding), so only the first `=` separates name from value.
pub fn tag<'a>(header: &'a str, key: &str) -> Option<&'a str> {
	header.split(';').find_map(|part| {
		let (name, value) = part.split_once('=')?;
		name.trim().eq_ignore_ascii_case(key).then(|| value.trim())
	})
}

/// Collect the ARC headers from a raw message in document order, parsing each
/// header's instance number. Returns `Err` on a malformed ARC header.
fn arc_headers(raw: &[u8]) -> Result<Vec<RawHeader>, ChainError> {
	let block_end = raw
		.windows(4)
		.position(|w| w == b"\r\n\r\n")
		.map(|p| p + 2)
		.unwrap_or(raw.len());
	let block = std::str::from_utf8(&raw[..block_end]).map_err(|_| ChainError::Malformed)?;

	let mut headers = Vec::new();
	let mut current: Option<String> = None;
	for line in block.split_inclusive("\r\n") {
		let content = line.strip_suffix("\r\n").unwrap_or(line);
		if content.starts_with(' ') || content.starts_with('\t') {
			// Folded continuation.
			if let Some(buffer) = &mut current {
				buffer.push_str(content);
			}
			continue;
		}
		if let Some(buffer) = current.take() {
			push_arc(&mut headers, &buffer)?;
		}
		if !content.is_empty() {
			current = Some(content.to_string());
		}
	}
	if let Some(buffer) = current.take() {
		push_arc(&mut headers, &buffer)?;
	}
	Ok(headers)
}

/// Parse one unfolded header line; push it if it is an ARC header.
fn push_arc(headers: &mut Vec<RawHeader>, line: &str) -> Result<(), ChainError> {
	let Some(colon) = line.find(':') else {
		return Ok(());
	};
	let name = line[..colon].trim_end();
	let Some(kind) = ArcKind::from_name(name) else {
		return Ok(());
	};
	let value = line[colon + 1..].trim_start();
	let instance = tag(value, "i")
		.and_then(|i| i.parse::<u32>().ok())
		.ok_or(ChainError::Malformed)?;
	headers.push(RawHeader {
		kind,
		instance,
		value: value.to_string(),
	});
	Ok(())
}
