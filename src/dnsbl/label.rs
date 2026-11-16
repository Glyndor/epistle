//! How a blocklist zone is named in text that can leave the host.
//!
//! A zone can carry a secret in its leading labels (Spamhaus DQS is queried
//! as `<key>.zen.dq.spamhaus.net`), so the status output, the alert webhook
//! and an inbound refusal name the list by its last two labels only. The full
//! zone stays in the operator's log.

/// What stands for a zone with no public name.
const GENERIC: &str = "a DNS blocklist";

/// The public name of `zone`: its last two DNS labels (`spamhaus.net`), or
/// `None` when it has no such suffix (a single label, or two numeric ones).
pub(crate) fn public_name(zone: &str) -> Option<String> {
	let labels: Vec<&str> = zone.split('.').filter(|label| !label.is_empty()).collect();
	let public = &labels[labels.len().saturating_sub(2)..];
	let numeric = public
		.iter()
		.all(|label| label.bytes().all(|b| b.is_ascii_digit()));
	if public.len() < 2 || numeric {
		return None;
	}
	Some(public.join("."))
}

/// The label for `zone` in outward text: its public name, else `a DNS
/// blocklist`.
pub(crate) fn public_label(zone: &str) -> String {
	public_name(zone).unwrap_or_else(|| GENERIC.to_string())
}
