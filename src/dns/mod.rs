//! DNS record verification: compare the records a domain has published against
//! what epistle expects, and report drift. Read-only — it never changes DNS,
//! so it is safe to run anytime and needs no provider credentials.

pub mod check_host;
pub mod detect;
pub mod lockdown;
pub mod names;
pub mod provider;
pub mod providers;
pub mod proxied_check;
pub mod publish;
pub mod records;
pub mod rrset;
pub mod service_records;
#[cfg(test)]
mod tests;
pub mod tlsa;
pub mod txt;
pub mod zone;

use crate::dns::provider::txt_purpose;
use crate::spf::DnsLookup;

/// The outcome of checking one expected record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
	/// The expected record is present.
	Ok,
	/// No matching record was found.
	Missing,
	/// A lookup error (treated as inconclusive, not a hard failure).
	LookupError,
}

/// One checked record and its outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
	/// Human label for the record kind (e.g. `MX`, `SPF`, `DKIM mail`).
	pub kind: String,
	/// The DNS name queried.
	pub name: String,
	/// Outcome of the check for this record.
	pub status: Status,
	/// What was found, for the report.
	pub detail: String,
}

impl Check {
	fn ok(kind: impl Into<String>, name: impl Into<String>, detail: impl Into<String>) -> Self {
		Check {
			kind: kind.into(),
			name: name.into(),
			status: Status::Ok,
			detail: detail.into(),
		}
	}

	fn missing(
		kind: impl Into<String>,
		name: impl Into<String>,
		detail: impl Into<String>,
	) -> Self {
		Check {
			kind: kind.into(),
			name: name.into(),
			status: Status::Missing,
			detail: detail.into(),
		}
	}

	fn error(kind: impl Into<String>, name: impl Into<String>) -> Self {
		Check {
			kind: kind.into(),
			name: name.into(),
			status: Status::LookupError,
			detail: "lookup failed (temporary)".to_string(),
		}
	}
}

/// Check the core records for one domain: MX to the mail hostname, SPF, DMARC,
/// MTA-STS, and a DKIM key per selector.
pub async fn check_domain(
	domain: &str,
	hostname: &str,
	dkim_selectors: &[String],
	dns: &dyn DnsLookup,
) -> Vec<Check> {
	let mut checks = Vec::new();

	// MX: at least one exchange should be the mail hostname.
	match dns.mx(domain).await {
		Ok(hosts) if hosts.iter().any(|h| h.eq_ignore_ascii_case(hostname)) => {
			checks.push(Check::ok("MX", domain, format!("→ {hostname}")));
		}
		Ok(hosts) if hosts.is_empty() => {
			checks.push(Check::missing("MX", domain, "no MX records".to_string()));
		}
		Ok(hosts) => checks.push(Check::missing(
			"MX",
			domain,
			format!("MX present but not {hostname}: {}", hosts.join(", ")),
		)),
		Err(_) => checks.push(Check::error("MX", domain)),
	}

	checks.push(txt_check("SPF", domain, "v=spf1", dns).await);
	checks.push(txt_check("DMARC", &format!("_dmarc.{domain}"), "v=DMARC1", dns).await);
	checks.push(txt_check("MTA-STS", &format!("_mta-sts.{domain}"), "v=STSv1", dns).await);

	for selector in dkim_selectors {
		let name = format!("{selector}._domainkey.{domain}");
		checks.push(txt_check(&format!("DKIM {selector}"), &name, "v=DKIM1", dns).await);
	}

	checks
}

/// Whether all checks passed (no missing records). Lookup errors are
/// inconclusive and do not count as drift.
pub fn all_ok(checks: &[Check]) -> bool {
	checks.iter().all(|c| c.status != Status::Missing)
}

/// Look up TXT records at `name` and report whether one carries the tag
/// `prefix` (e.g. `v=spf1`). Two records with the same tag at the same
/// name are a configuration mistake every receiver turns into a permanent
/// error: SPF returns `permerror` (RFC 7208 §4.5), DMARC is ignored (RFC
/// 7489 §6.6.3), MTA-STS / TLS-RPT clients treat the name as
/// unconfigured. The check flags the duplicate rather than silently
/// accepting the first match.
///
/// A single logical TXT record may arrive as several character-strings
/// (RFC 1035 §3.3.14, RFC 7489 §6.1: SPF, for instance, is one logical
/// record that some resolvers split). Join any split strings before
/// comparing, the way a verifier assembles the message header from the
/// wire. Long DKIM `p=` values (RSA) split into two strings on a typical
/// zone; the resolver currently concatenates them, so this is a guard
/// rather than the active path: if a future implementation returns the
/// strings separately, the check still produces the right answer.
///
/// Matching uses [`crate::dns::provider::txt_purpose`], so the tag is
/// recognised case-insensitively and tolerates the leading-whitespace
/// and quoted presentation forms a provider may hand back.
async fn txt_check(kind: &str, name: &str, prefix: &str, dns: &dyn DnsLookup) -> Check {
	match dns.txt(name).await {
		Ok(records) => {
			let mut matches = records.iter().filter(|r| txt_purpose(r) == Some(prefix));
			let first = matches.next();
			match (first, matches.next()) {
				(Some(record), None) => Check::ok(kind, name, record.clone()),
				(Some(_), Some(_)) => {
					// Count again from the front so the message names
					// the actual number, not "more than one". The
					// first iterator includes nulls.
					let count = records
						.iter()
						.filter(|r| txt_purpose(r) == Some(prefix))
						.count();
					Check::missing(
						kind,
						name,
						format!(
							"{count} {kind} records at {name}: receivers treat that as an \
							 error and every message fails; keep one"
						),
					)
				}
				(None, _) => Check::missing(kind, name, format!("no {prefix} record")),
			}
		}
		Err(_) => Check::error(kind, name),
	}
}

pub use check_host::check_host;
pub use detect::{LocalGlobals, PtrReport, detect, local_global_addresses, ptr_report};
