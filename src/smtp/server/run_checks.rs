//! The strict checks of a scope: DKIM, ARC and the reverse DNS of the
//! connecting address, each of which annotates or refuses as the recipients'
//! scopes say. Split from `run_auth.rs` to keep both under the code-line
//! limit.
//!
//! Nothing here refuses on a failed lookup: a DNS error is `4xx`, so the
//! sender retries, and only an answer that says the check failed is `5xx`.

use std::net::IpAddr;

use crate::antispam::scopes::Checks;
use crate::config::CheckPolicy;
use crate::dkim::{DkimOutcome, DkimResult};
use crate::smtp::reply::Reply;
use crate::spf::{DnsFailure, DnsLookup};

use super::{Server, refusal_checks};

/// How the reverse DNS of an address came out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Iprev {
	/// A name of the PTR resolves back to the address.
	Pass,
	/// There is a PTR and none of its names resolves back to the address.
	Fail,
	/// No PTR at all.
	None,
	/// The resolver did not answer.
	Temp,
}

impl Iprev {
	pub(super) fn as_str(self) -> &'static str {
		match self {
			Iprev::Pass => "pass",
			Iprev::Fail => "fail",
			Iprev::None => "none",
			Iprev::Temp => "temperror",
		}
	}
}

/// Forward-confirmed reverse DNS of `ip` (RFC 8601 `iprev`).
pub(super) async fn iprev(dns: &dyn DnsLookup, ip: IpAddr) -> Iprev {
	// A client of an IPv4 address on a dual-stack listener arrives as an
	// IPv4-mapped IPv6 one: its PTR is the IPv4 one, and its name resolves
	// to the IPv4 address.
	let ip = ip.to_canonical();
	let names = match dns.ptr(ip).await {
		Ok(names) if names.is_empty() => return Iprev::None,
		Ok(names) => names,
		Err(DnsFailure::Temporary) => return Iprev::Temp,
	};
	let mut temporary = false;
	// A hostile zone can publish many names: five are resolved back.
	for name in names.iter().take(5) {
		match dns.addresses(name).await {
			Ok(addresses) if addresses.iter().any(|found| found.to_canonical() == ip) => {
				return Iprev::Pass;
			}
			Ok(_) => {}
			Err(DnsFailure::Temporary) => temporary = true,
		}
	}
	if temporary { Iprev::Temp } else { Iprev::Fail }
}

impl Server {
	/// Run the checks `checks` turns on for a message from `peer` whose DKIM
	/// results are `dkim`, and `from` the domain of its author. Returns the
	/// `Authentication-Results` entries to add, or the reply that refuses
	/// the message.
	pub(super) async fn strict_checks(
		&self,
		dns: &dyn DnsLookup,
		data: &[u8],
		peer: IpAddr,
		from: Option<&str>,
		dkim: &[DkimResult],
		checks: Checks,
	) -> Result<Vec<String>, Reply> {
		let detail = self.refusal_detail;
		let mut methods = Vec::new();
		if checks.dkim == CheckPolicy::Reject {
			let domain = dkim
				.iter()
				.find_map(|result| result.domain.as_deref())
				.or(from)
				.unwrap_or("the sender");
			let passed = dkim.iter().any(|r| r.outcome == DkimOutcome::Pass);
			let has = |wanted| dkim.iter().any(|r| r.outcome == wanted);
			if !passed {
				if has(DkimOutcome::TempError) {
					return Err(refusal_checks::dkim_unavailable(detail, domain));
				}
				if has(DkimOutcome::Fail) {
					return Err(refusal_checks::dkim_failed(detail, domain));
				}
				// No signature, or one whose key the domain does not
				// publish: refused only when the scope says so.
				if checks.dkim_require_signature {
					return Err(refusal_checks::dkim_missing(detail, domain));
				}
			}
		}
		if checks.arc != CheckPolicy::Off {
			let chain = crate::arc::validate::validate_checked(dns, data).await;
			match chain {
				Ok(chain) => methods.push(format!("arc={}", chain.as_str())),
				Err(DnsFailure::Temporary) => methods.push("arc=temperror".to_string()),
			}
			if checks.arc == CheckPolicy::Reject {
				match chain {
					Ok(crate::arc::chain::ChainValidation::Fail) => {
						return Err(refusal_checks::arc_failed(detail));
					}
					Err(_) => return Err(refusal_checks::arc_unavailable(detail)),
					Ok(_) => {}
				}
			}
		}
		if checks.reverse_dns != CheckPolicy::Off {
			let result = iprev(dns, peer).await;
			methods.push(format!(
				"iprev={} policy.iprev={}",
				result.as_str(),
				peer.to_canonical()
			));
			if checks.reverse_dns == CheckPolicy::Reject {
				match result {
					Iprev::Fail | Iprev::None => {
						return Err(refusal_checks::reverse_dns_failed(detail, peer));
					}
					Iprev::Temp => {
						return Err(refusal_checks::reverse_dns_unavailable(detail, peer));
					}
					Iprev::Pass => {}
				}
			}
		}
		Ok(methods)
	}
}
