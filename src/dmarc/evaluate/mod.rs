//! DMARC evaluation: alignment of SPF/DKIM results with the From domain.

use crate::dkim::{DkimOutcome, DkimResult};
use crate::spf::{DnsFailure, DnsLookup, SpfOutcome};

use super::record::{Alignment, Policy, Record};

/// DMARC outcome for `Authentication-Results` and policy enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmarcOutcome {
	/// Either SPF or DKIM passed and was aligned with the RFC5322.From
	/// domain under the record's alignment mode.
	Pass,
	/// Failed with the record requesting rejection (quarantine is treated
	/// as reject until a quarantine mailbox exists).
	Reject,
	/// Failed but the record requests no action.
	Fail,
	/// No DMARC record was found (or one was found but the strict
	/// single-record rule of RFC 7489 §6.6.3 forbade it): DMARC does not
	/// apply.
	None,
	/// A transient error prevented evaluation, typically a DNS lookup
	/// failure. The verifier should be retried later.
	TempError,
	/// A permanent error prevented evaluation: the published record is
	/// malformed or otherwise unusable.
	PermError,
}

impl DmarcOutcome {
	/// Keyword for `Authentication-Results`.
	pub fn as_str(self) -> &'static str {
		match self {
			DmarcOutcome::Pass => "pass",
			DmarcOutcome::Reject | DmarcOutcome::Fail => "fail",
			DmarcOutcome::None => "none",
			DmarcOutcome::TempError => "temperror",
			DmarcOutcome::PermError => "permerror",
		}
	}
}

/// Extract the domain of the RFC5322.From header from a raw message.
/// Multiple From headers, a From naming more than one domain, or no
/// parseable address yield `None` (see [`super::author::author_domain`]).
pub fn from_domain(raw: &[u8]) -> Option<String> {
	match super::author::author_domain(raw) {
		super::author::AuthorDomain::One(domain) => Some(domain),
		super::author::AuthorDomain::Missing | super::author::AuthorDomain::Multiple => None,
	}
}

/// Evaluate DMARC for a message: `from_domain` is the RFC5322.From domain,
/// `spf` the SPF result with the domain it was evaluated on.
pub async fn evaluate(
	dns: &dyn DnsLookup,
	from_domain: &str,
	spf: (SpfOutcome, Option<&str>),
	dkim: &[DkimResult],
) -> DmarcOutcome {
	evaluate_inner(dns, from_domain, spf, dkim, sample_pct()).await
}

/// Draws a random number in [1, 100] for pct= sampling.
fn sample_pct() -> u8 {
	use ring::rand::{SecureRandom, SystemRandom};
	let rng = SystemRandom::new();
	let mut buf = [0u8; 1];
	// Ignore fill errors — on failure the result is 0, which causes
	// non-sampled treatment (safe: slightly over-permissive, not under).
	let _ = rng.fill(&mut buf);
	(buf[0] % 100) + 1
}

/// Testable inner evaluator that accepts an explicit pct roll (1–100).
async fn evaluate_inner(
	dns: &dyn DnsLookup,
	from_domain: &str,
	spf: (SpfOutcome, Option<&str>),
	dkim: &[DkimResult],
	pct_roll: u8,
) -> DmarcOutcome {
	let (record, applied_policy) = match fetch_record(dns, from_domain).await {
		Ok(Some(found)) => found,
		Ok(None) => return DmarcOutcome::None,
		Err(outcome) => return outcome,
	};

	let dkim_aligned = dkim.iter().any(|result| {
		result.outcome == DkimOutcome::Pass
			&& result
				.domain
				.as_deref()
				.is_some_and(|d| aligned(record.dkim_alignment, d, from_domain))
	});
	let spf_aligned = spf.0 == SpfOutcome::Pass
		&& spf
			.1
			.is_some_and(|domain| aligned(record.spf_alignment, domain, from_domain));

	if dkim_aligned || spf_aligned {
		return DmarcOutcome::Pass;
	}
	match applied_policy {
		Policy::None => DmarcOutcome::Fail,
		// RFC 7489 §6.6.2: apply policy only to pct% of failing messages;
		// non-sampled messages are treated as if policy were "none".
		Policy::Quarantine | Policy::Reject => {
			if record.pct < 100 && pct_roll > record.pct {
				DmarcOutcome::Fail
			} else {
				DmarcOutcome::Reject
			}
		}
	}
}

/// Fetch `_dmarc.<domain>`, falling back to the organizational domain for
/// subdomains. Returns the record plus the policy that applies.
async fn fetch_record(
	dns: &dyn DnsLookup,
	domain: &str,
) -> Result<Option<(Record, Policy)>, DmarcOutcome> {
	if let Some(record) = lookup(dns, domain).await? {
		let policy = record.policy;
		return Ok(Some((record, policy)));
	}
	let organizational = organizational_domain(domain);
	if organizational != domain
		&& let Some(record) = lookup(dns, &organizational).await?
	{
		let policy = record.subdomain_policy;
		return Ok(Some((record, policy)));
	}
	Ok(None)
}

async fn lookup(dns: &dyn DnsLookup, domain: &str) -> Result<Option<Record>, DmarcOutcome> {
	let name = format!("_dmarc.{domain}");
	let texts = match dns.txt(&name).await {
		Ok(texts) => texts,
		Err(DnsFailure::Temporary) => return Err(DmarcOutcome::TempError),
	};
	let mut records = texts.iter().filter_map(|text| super::record::parse(text));
	match records.next() {
		None => Ok(None),
		Some(parsed) => {
			// Multiple DMARC records mean none applies (section 6.6.3).
			if records.next().is_some() {
				return Ok(None);
			}
			parsed.map(Some).map_err(|()| DmarcOutcome::PermError)
		}
	}
}

/// Identifier alignment (RFC 7489 section 3.1).
fn aligned(mode: Alignment, identifier: &str, from_domain: &str) -> bool {
	let identifier = identifier.to_ascii_lowercase();
	let from_domain = from_domain.to_ascii_lowercase();
	match mode {
		Alignment::Strict => identifier == from_domain,
		Alignment::Relaxed => {
			organizational_domain(&identifier) == organizational_domain(&from_domain)
		}
	}
}

/// Return the organizational (registrable) domain using the Mozilla PSL.
/// Falls back to the rightmost two labels when the PSL returns no result.
/// `pub(crate)` so the report sender can compare the `rua=` domain to the
/// policy domain for the external-destination check (RFC 7489 §7.1).
pub(crate) fn organizational_domain(domain: &str) -> String {
	use psl::Psl;
	if let Some(d) = psl::List.domain(domain.as_bytes())
		&& let Ok(s) = std::str::from_utf8(d.as_bytes())
	{
		return s.to_ascii_lowercase();
	}
	// Fallback: two-label heuristic (covers plain TLDs like .com, .org).
	let labels: Vec<&str> = domain.split('.').collect();
	if labels.len() <= 2 {
		return domain.to_string();
	}
	labels[labels.len() - 2..].join(".")
}

#[cfg(test)]
mod tests;
