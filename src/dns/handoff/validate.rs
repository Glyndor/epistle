//! What the serving side accepts from the asking side.
//!
//! The other container is not trusted. A request is a file another process
//! wrote, and it is checked before anything is written to DNS: it has to be
//! a DKIM key record of a domain this installation serves, in a zone the
//! `[dns]` configuration publishes, under a selector this installation uses
//! (one a rotation makes, or one the operator configured), with a value that
//! is a DKIM record and nothing else. Everything else is refused, with the
//! reason in the answer, so the asking side can report it and the operator
//! can read it.

use super::{MAX_NAME_BYTES, MAX_TTL, MAX_VALUE_BYTES, Operation, Request, valid_id};

/// The prefixes of the selectors a rotation makes.
const SELECTOR_PREFIXES: [&str; 4] = ["ed", "rsa", "own", "ownrsa"];

/// Check `request` against the zones and domains this installation has, at
/// `now`.
///
/// `selectors` are the ones this installation uses: the ones the operator
/// configured plus the ones a rotation makes. A request for any other
/// selector is refused.
///
/// `Err` is the reason the request was refused; the caller answers the
/// asking side with it and writes nothing.
pub fn check(
	request: &Request,
	zones: &[String],
	domains: &[String],
	selectors: &[String],
	now: u64,
) -> Result<(), String> {
	if !valid_id(&request.id) {
		return Err("the request has no usable id".to_string());
	}
	if request.kind != "TXT" {
		return Err(format!(
			"only a TXT record can be asked for, and this one is {}",
			request.kind
		));
	}
	if request.name.len() > MAX_NAME_BYTES || !crate::dns::names::is_valid_name(&request.name) {
		return Err(format!("{} is not a valid record name", request.name));
	}
	let (selector, domain) = request
		.name
		.split_once("._domainkey.")
		.ok_or_else(|| format!("{} is not a DKIM key record name", request.name))?;
	if !rotation_selector(selector) && !configured_selector(selectors, selector) {
		return Err(format!(
			"{selector} is not a selector this installation uses"
		));
	}
	let domain = domain.to_ascii_lowercase();
	if !domains
		.iter()
		.any(|known| known.eq_ignore_ascii_case(&domain))
	{
		return Err(format!("{domain} is not a domain this installation serves"));
	}
	if !zones
		.iter()
		.any(|zone| crate::dns::router::contains(&zone.to_ascii_lowercase(), &domain))
	{
		return Err(format!("{domain} is in none of the [dns] zones"));
	}
	if request.value.len() > MAX_VALUE_BYTES {
		return Err("the record value is longer than it may be".to_string());
	}
	match request.operation {
		Operation::Publish => {
			if crate::dns::provider::txt_purpose(&request.value) != Some("v=DKIM1") {
				return Err("the record is not a DKIM key record".to_string());
			}
			if crate::dkim::rotate::key_of(&request.value).is_none_or(|key| key.is_empty()) {
				return Err("the DKIM key record carries no public key".to_string());
			}
		}
		Operation::Withdraw => {
			if !request.value.is_empty() {
				return Err("a withdrawal takes the whole record set at the name away".to_string());
			}
		}
	}
	if request.ttl == 0 || request.ttl > MAX_TTL {
		return Err(format!("{} is not a time to live", request.ttl));
	}
	let age = now.saturating_sub(request.created_at);
	if age > super::MAX_REQUEST_AGE.as_secs() {
		return Err(format!(
			"the request is {age}s old and was not answered in time"
		));
	}
	if request.created_at > now.saturating_add(super::MAX_CLOCK_SKEW.as_secs()) {
		return Err("the request claims a time in the future".to_string());
	}
	Ok(())
}

/// Whether `selector` is one a rotation makes: `ed<day>`, `rsa<day>`,
/// `own<day>` or `ownrsa<day>`, each with the `x2`, `x3`… suffix a taken
/// name gets.
fn rotation_selector(selector: &str) -> bool {
	SELECTOR_PREFIXES.iter().any(|prefix| {
		let Some(rest) = selector.strip_prefix(prefix) else {
			return false;
		};
		let (day, suffix) = match rest.split_once('x') {
			Some((day, suffix)) => (day, Some(suffix)),
			None => (rest, None),
		};
		digits(day) && suffix.is_none_or(digits)
	})
}

/// Whether `selector` is one the operator configured: the ones in `[dkim]`
/// and in every `[[dkim.domain]]`. A rotation publishes and retires those,
/// so the side that writes DNS has to accept them.
fn configured_selector(selectors: &[String], selector: &str) -> bool {
	selectors
		.iter()
		.any(|known| known.eq_ignore_ascii_case(selector))
}

/// Whether `text` is one or more digits and nothing else.
fn digits(text: &str) -> bool {
	!text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit())
}
