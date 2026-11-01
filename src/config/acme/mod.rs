//! ACME configuration: automatic TLS certificate issuance settings.

use serde::Deserialize;

/// Default days before expiry to start renewing.
const fn default_renew_before_days() -> u32 {
	30
}

/// Which ACME challenge proves control of each domain (RFC 8555 §8).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
pub enum AcmeChallenge {
	/// HTTP-01: the CA fetches a token from the `acme` listener on port 80.
	#[default]
	#[serde(rename = "http-01")]
	Http01,
	/// TLS-ALPN-01 (RFC 8737): the CA connects to port 443 with the
	/// `acme-tls/1` ALPN and expects a challenge certificate.
	#[serde(rename = "tls-alpn-01")]
	TlsAlpn01,
	/// DNS-01: a `_acme-challenge` TXT record published through `[dns]`.
	#[serde(rename = "dns-01")]
	Dns01,
}

impl AcmeChallenge {
	/// The name the CA and the configuration use for this challenge.
	pub fn as_str(self) -> &'static str {
		match self {
			AcmeChallenge::Http01 => "http-01",
			AcmeChallenge::TlsAlpn01 => "tls-alpn-01",
			AcmeChallenge::Dns01 => "dns-01",
		}
	}
}

/// Refuse a challenge the rest of the configuration cannot answer, so a
/// misconfiguration stops the start instead of failing at the first renewal
/// weeks later. HTTP-01 needs nothing beyond the `acme` listener.
pub(super) fn validate_challenge(
	acme: &Acme,
	dns: &super::DnsProviders,
	listeners: &[super::Listener],
) -> Result<(), String> {
	use super::ListenerKind;
	match acme.challenge {
		AcmeChallenge::Http01 => Ok(()),
		AcmeChallenge::Dns01 => {
			let publishes = dns
				.iter()
				.any(|dns| !dns.provider.eq_ignore_ascii_case("manual"));
			if !publishes {
				return Err("[acme] challenge = \"dns-01\" needs a [dns] provider that can publish records (any provider other than \"manual\")".into());
			}
			// Each certificate name is answered through the entry of its own
			// zone; a name outside every entry (or inside a manual one) would
			// fail at the first renewal.
			match acme.domains.iter().find(|name| !dns.publishes(name)) {
				None => Ok(()),
				Some(name) => Err(format!(
					"[acme] challenge = \"dns-01\": {name} is not in the zone of any [dns] entry that can publish records"
				)),
			}
		}
		AcmeChallenge::TlsAlpn01 => {
			// The CA always connects to port 443, and only a listener that
			// terminates TLS itself can answer the `acme-tls/1` handshake.
			let answers = listeners.iter().any(|listener| {
				listener.socket_addr().port() == 443
					&& matches!(
						listener.kind,
						ListenerKind::Submissions | ListenerKind::Imaps | ListenerKind::Pop3s
					)
			});
			if answers {
				Ok(())
			} else {
				Err("[acme] challenge = \"tls-alpn-01\" needs a listener that terminates TLS on port 443 (kind submissions, imaps or pop3s with port = 443)".into())
			}
		}
	}
}

/// Automatic-TLS (ACME) settings. Present enables auto issuance/renewal.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Acme {
	/// The CA's ACME directory URL (e.g. Let's Encrypt).
	pub directory_url: String,
	/// Account contact email addresses.
	#[serde(default)]
	pub contacts: Vec<String>,
	/// Domains to obtain certificates for.
	pub domains: Vec<String>,
	/// Days before expiry to begin renewal.
	#[serde(default = "default_renew_before_days")]
	pub renew_before_days: u32,
	/// The challenge used to validate every domain. Defaults to HTTP-01.
	#[serde(default)]
	pub challenge: AcmeChallenge,
}

#[cfg(test)]
mod tests;
