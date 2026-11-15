//! Provider diagnostics keyed by enhanced status, independent of prose.

use super::enhanced_for;

/// A specific provider failure within the existing generic failure class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderCause {
	/// Outlook's sending-domain authentication requirements.
	DomainAuthentication,
	/// Gmail's unauthenticated-message rejection.
	Unauthenticated,
	/// Gmail's sending rate limit.
	RateLimit,
	/// A 5.7.1 that identifies an IP or a blocklist.
	IpOrList,
	/// Yahoo's temporary TSS04 throttle.
	YahooThrottle,
}

impl ProviderCause {
	/// A fixed operator-facing cause and a diagnostic command.
	pub fn sentence(self) -> &'static str {
		match self {
			Self::DomainAuthentication => {
				"The sending domain does not meet the receiver's authentication requirements; run epistle verify-dns."
			}
			Self::Unauthenticated => {
				"The receiver rejected an unauthenticated message; run epistle verify-dns."
			}
			Self::RateLimit => "The receiver limited the sending rate; run epistle check queue.",
			Self::IpOrList => {
				"The receiver rejected the sending IP or a blocklist entry; run epistle check dns."
			}
			Self::YahooThrottle => {
				"Yahoo temporarily throttled the sender (TSS04); run epistle check queue."
			}
		}
	}

	/// Whether the receiver needs the configurable minimum pause.
	pub fn pauses(self) -> bool {
		matches!(self, Self::RateLimit | Self::YahooThrottle)
	}
}

/// Read a normalized queue reason, retaining basic/enhanced class agreement.
/// Yahoo's TSS04 is an explicit machine marker, never a prose match; it only
/// applies to a temporary reply, including Yahoo replies without enhanced status.
pub fn provider_cause(reason: &str) -> Option<ProviderCause> {
	let (code, text) = reason.split_once(' ')?;
	let code: u16 = code.parse().ok()?;
	if (400..500).contains(&code)
		&& text
			.split(|c: char| !c.is_ascii_alphanumeric())
			.any(|token| token.eq_ignore_ascii_case("TSS04"))
	{
		return Some(ProviderCause::YahooThrottle);
	}
	let enhanced = enhanced_for(code, text)?;
	match (enhanced.class, enhanced.subject, enhanced.detail) {
		(5, 7, 515) => Some(ProviderCause::DomainAuthentication),
		(5, 7, 26) => Some(ProviderCause::Unauthenticated),
		(4, 7, 28) => Some(ProviderCause::RateLimit),
		(5, 7, 1) if names_ip_or_list(text) => Some(ProviderCause::IpOrList),
		_ => None,
	}
}

fn names_ip_or_list(text: &str) -> bool {
	let lower = text.to_ascii_lowercase();
	let words: Vec<_> = lower.split(|c: char| !c.is_ascii_alphanumeric()).collect();
	if words.iter().any(|word| {
		matches!(
			*word,
			"ip" | "ips"
				| "list"
				| "listed"
				| "blocklist"
				| "blacklist"
				| "blocklisted"
				| "blacklisted"
				| "dnsbl"
				| "rbl"
				| "spamhaus"
				| "spamcop"
		)
	}) {
		return true;
	}
	text.split(|c: char| !(c.is_ascii_hexdigit() || c == '.' || c == ':'))
		.any(|token| token.trim_matches('.').parse::<std::net::IpAddr>().is_ok())
}
