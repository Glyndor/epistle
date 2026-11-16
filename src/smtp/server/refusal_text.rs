//! What an inbound refusal says: the address, the domain and the result
//! that were evaluated, so the sender of the refused mail has something to
//! act on. Only what the sender itself supplied or what its own check
//! produced goes in: the client address, its envelope and From domains, the
//! policy that domain published and the blocklist zone that listed it.
//! Nothing of another tenant or of this server's own setup is named.
//!
//! The class of each refusal (permanent or temporary) is the caller's; a
//! temporary SPF or DMARC error carries the specific `4.7.24` of RFC 7372,
//! not the directory-server failure `4.4.3` of RFC 3463.

use std::net::IpAddr;

use crate::config::RefusalDetail;
use crate::dmarc::PublishedPolicy;
use crate::smtp::reply::Reply;

/// `value` as it is quoted in a reply: printable ASCII only, so a name a
/// sender chose cannot carry anything else onto the wire.
pub(super) fn quoted(value: &str) -> String {
	value
		.chars()
		.map(|c| if c.is_ascii_graphic() { c } else { '?' })
		.collect()
}

/// The generic temporary answer a terse server gives for anything that
/// asks the sender to try again: it names no check, list, policy or limit.
const TRY_LATER: &str = "try again later";

/// The generic answer a terse server gives for a message it refuses.
const REFUSED: &str = "message refused";

/// `550 5.7.23`: `ip` is not authorized to send for `domain`.
pub(super) fn spf_failed(detail: RefusalDetail, ip: IpAddr, domain: &str) -> Reply {
	let text = match detail {
		RefusalDetail::Terse => REFUSED.to_string(),
		RefusalDetail::Standard => spf_fail_text(ip, domain),
		RefusalDetail::Verbose => format!(
			"{}; add {ip} to the SPF record of {} or send through a host it lists",
			spf_fail_text(ip, domain),
			quoted(domain)
		),
	};
	Reply::single(550, &format!("5.7.23 {text}"))
}

fn spf_fail_text(ip: IpAddr, domain: &str) -> String {
	format!(
		"SPF validation failed for {ip} as sender of {} (result: fail)",
		quoted(domain)
	)
}

/// `451 4.7.24`: SPF for `domain` could not be evaluated right now.
pub(super) fn spf_unavailable(detail: RefusalDetail, ip: IpAddr, domain: &str) -> Reply {
	let text = match detail {
		RefusalDetail::Terse => TRY_LATER.to_string(),
		RefusalDetail::Standard => spf_temp_text(ip, domain),
		RefusalDetail::Verbose => format!(
			"{}; the DNS of {} did not answer, retry later",
			spf_temp_text(ip, domain),
			quoted(domain)
		),
	};
	Reply::single(451, &format!("4.7.24 {text}"))
}

fn spf_temp_text(ip: IpAddr, domain: &str) -> String {
	format!(
		"SPF check temporarily failed for {ip} as sender of {} (result: temperror)",
		quoted(domain)
	)
}

/// `550 5.7.1`: the policy `from` published asks for the refusal of mail
/// that authenticates for neither SPF nor DKIM with its domain.
pub(super) fn dmarc_rejected(
	detail: RefusalDetail,
	from: &str,
	policy: Option<PublishedPolicy>,
) -> Reply {
	let published = policy.map_or(String::new(), |policy| format!("p={}, ", policy.policy));
	let standard = format!(
		"rejected by DMARC policy of {} ({published}result: fail)",
		quoted(from)
	);
	let text = match detail {
		RefusalDetail::Terse => REFUSED.to_string(),
		RefusalDetail::Standard => standard,
		RefusalDetail::Verbose => format!(
			"{standard}; make SPF or DKIM pass for a domain aligned with {}",
			quoted(from)
		),
	};
	Reply::single(550, &format!("5.7.1 {text}"))
}

/// `451 4.7.24`: DMARC for `from` could not be evaluated right now.
pub(super) fn dmarc_unavailable(detail: RefusalDetail, from: Option<&str>) -> Reply {
	let from = quoted(from.unwrap_or("the From domain"));
	let standard = format!("DMARC check temporarily failed for {from} (result: temperror)");
	let text = match detail {
		RefusalDetail::Terse => TRY_LATER.to_string(),
		RefusalDetail::Standard => standard,
		RefusalDetail::Verbose => {
			format!("{standard}; the DNS of {from} did not answer, retry later")
		}
	};
	Reply::single(451, &format!("4.7.24 {text}"))
}

/// `451 4.7.1`: an unseen triplet is deferred once; a retry after
/// `retry_after` is accepted.
pub(super) fn greylisted(detail: RefusalDetail, retry_after: u64) -> Reply {
	let text = match detail {
		RefusalDetail::Terse => TRY_LATER.to_string(),
		RefusalDetail::Standard => "greylisted, please retry shortly".to_string(),
		RefusalDetail::Verbose => format!(
			"greylisted, please retry after {}",
			crate::smtp::retry_time::clock_at(retry_after)
		),
	};
	Reply::single(451, &format!("4.7.1 {text}"))
}

/// `554 5.7.1` for the text of a listed client, sender domain or link:
/// `listed` is what the standard text says, `fix` what a verbose one adds.
pub(super) fn listed(detail: RefusalDetail, listed: String, fix: String) -> Reply {
	let text = match detail {
		RefusalDetail::Terse => REFUSED.to_string(),
		RefusalDetail::Standard => listed,
		RefusalDetail::Verbose => format!("{listed}; {fix}"),
	};
	Reply::single(554, &format!("5.7.1 {text}"))
}

/// How a refusal names the blocklist that listed the sender. A zone can
/// carry the operator's key in a leading label (`<key>.zen.dq.example`),
/// so the reply gives the last two labels, the public name of the list
/// (`dq.example`), and never the zone as configured; a zone with no such
/// name (one label, or numbers only) is `a DNS blocklist`. The log keeps
/// the full zone.
pub(super) fn list_name(zone: &str) -> String {
	let labels: Vec<&str> = zone.split('.').filter(|label| !label.is_empty()).collect();
	let public = &labels[labels.len().saturating_sub(2)..];
	let numeric = public
		.iter()
		.all(|label| label.bytes().all(|b| b.is_ascii_digit()));
	if public.len() < 2 || numeric {
		return "a DNS blocklist".to_string();
	}
	format!("DNS blocklist {}", quoted(&public.join(".")))
}
