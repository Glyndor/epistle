//! DNS record verification: compare the records a domain has published against
//! what epistle expects, and report drift. Read-only — it never changes DNS,
//! so it is safe to run anytime and needs no provider credentials.

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

/// Look up TXT records at `name` and report whether one begins with `prefix`.
async fn txt_check(kind: &str, name: &str, prefix: &str, dns: &dyn DnsLookup) -> Check {
	match dns.txt(name).await {
		Ok(records) => {
			match records.iter().find(|r| {
				r.trim_start()
					.to_ascii_uppercase()
					.starts_with(&prefix.to_ascii_uppercase())
			}) {
				Some(record) => Check::ok(kind, name, record.clone()),
				None => Check::missing(kind, name, format!("no {prefix} record")),
			}
		}
		Err(_) => Check::error(kind, name),
	}
}

#[cfg(test)]
#[path = "drift_tests.rs"]
mod tests;
