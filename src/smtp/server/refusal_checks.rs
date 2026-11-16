//! What an inbound refusal by DKIM, ARC or reverse DNS says, at each
//! level of `[smtp] reject_detail`. The same rules as `refusal_text`: only
//! what the sender supplied or its own check produced is named. A
//! temporary error is `4xx`, never a refusal.

use std::net::IpAddr;

use crate::config::RefusalDetail;
use crate::smtp::reply::Reply;

use super::refusal_text::{REFUSED, TRY_LATER, quoted};

/// `text` at `detail`: the generic answer when terse, `standard` as it is,
/// and `standard; fix` when verbose.
fn leveled(detail: RefusalDetail, generic: &str, standard: String, fix: String) -> String {
	match detail {
		RefusalDetail::Terse => generic.to_string(),
		RefusalDetail::Standard => standard,
		RefusalDetail::Verbose => format!("{standard}; {fix}"),
	}
}

/// `550 5.7.21`: every DKIM signature of the message failed.
pub(super) fn dkim_failed(detail: RefusalDetail, domain: &str) -> Reply {
	let domain = quoted(domain);
	let text = leveled(
		detail,
		REFUSED,
		format!("DKIM validation failed for {domain}: no acceptable signature (result: fail)"),
		format!("sign the message with the key {domain} publishes, and do not alter it afterwards"),
	);
	Reply::single(550, &format!("5.7.21 {text}"))
}

/// `550 5.7.20`: no DKIM signature of the message passed, and this
/// recipient's domain asks for one.
pub(super) fn dkim_missing(detail: RefusalDetail, domain: &str) -> Reply {
	let domain = quoted(domain);
	let text = leveled(
		detail,
		REFUSED,
		format!("no passing DKIM signature found for {domain} (result: none)"),
		format!("publish a DKIM key for {domain} and sign the message with it"),
	);
	Reply::single(550, &format!("5.7.20 {text}"))
}

/// `451 4.7.20`: DKIM could not be evaluated right now.
pub(super) fn dkim_unavailable(detail: RefusalDetail, domain: &str) -> Reply {
	let domain = quoted(domain);
	let text = leveled(
		detail,
		TRY_LATER,
		format!("DKIM check temporarily failed for {domain} (result: temperror)"),
		format!("the DNS of {domain} did not answer, retry later"),
	);
	Reply::single(451, &format!("4.7.20 {text}"))
}

/// `550 5.7.29`: the ARC chain of the message does not validate.
pub(super) fn arc_failed(detail: RefusalDetail) -> Reply {
	let text = leveled(
		detail,
		REFUSED,
		"ARC validation failed: the chain of the message is broken (result: fail)".to_string(),
		"send the message without ARC headers, or through hosts that seal them correctly"
			.to_string(),
	);
	Reply::single(550, &format!("5.7.29 {text}"))
}

/// `451 4.7.29`: the ARC chain could not be evaluated right now.
pub(super) fn arc_unavailable(detail: RefusalDetail) -> Reply {
	let text = leveled(
		detail,
		TRY_LATER,
		"ARC check temporarily failed (result: temperror)".to_string(),
		"the DNS of a signer did not answer, retry later".to_string(),
	);
	Reply::single(451, &format!("4.7.29 {text}"))
}

/// `550 5.7.25`: the address has no reverse DNS that resolves back to it.
pub(super) fn reverse_dns_failed(detail: RefusalDetail, ip: IpAddr) -> Reply {
	let text = leveled(
		detail,
		REFUSED,
		format!("reverse DNS validation failed for {ip} (result: fail)"),
		format!("give {ip} a PTR record whose name resolves back to {ip}"),
	);
	Reply::single(550, &format!("5.7.25 {text}"))
}

/// `451 4.7.25`: the reverse DNS could not be looked up right now.
pub(super) fn reverse_dns_unavailable(detail: RefusalDetail, ip: IpAddr) -> Reply {
	let text = leveled(
		detail,
		TRY_LATER,
		format!("reverse DNS check temporarily failed for {ip} (result: temperror)"),
		"the DNS did not answer, retry later".to_string(),
	);
	Reply::single(451, &format!("4.7.25 {text}"))
}
