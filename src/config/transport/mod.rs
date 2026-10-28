//! Outbound transport routing: how mail leaves the server.
//!
//! Each `[[transport]]` rule matches by sender account, recipient domain, or
//! (when neither is set) everything, and selects how to deliver: `direct` (MX
//! lookup, the default), `relay` to a fixed smarthost (optionally over STARTTLS,
//! with SMTP AUTH, and/or through a SOCKS5 proxy — covering submission and
//! plain relay), or `fail` (refuse). Most-specific match wins: account, then
//! domain, then catch-all.

use serde::Deserialize;

/// How a matched transport delivers mail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportKind {
	/// Resolve the recipient's MX and connect directly (the default).
	#[default]
	Direct,
	/// Hand off to a fixed smarthost.
	Relay,
	/// Refuse to send (fail closed).
	Fail,
}

/// One outbound transport rule.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Transport {
	/// Match mail sent by this local account (the envelope sender's local part).
	#[serde(default)]
	pub account: Option<String>,
	/// Match mail to this recipient domain.
	#[serde(default)]
	pub domain: Option<String>,
	/// How to deliver matched mail.
	#[serde(default)]
	pub kind: TransportKind,
	/// Smarthost host (required for `relay`).
	#[serde(default)]
	pub host: Option<String>,
	/// Smarthost port (required for `relay`).
	#[serde(default)]
	pub port: Option<u16>,
	/// Upgrade to TLS via STARTTLS before AUTH/mail on a relay.
	#[serde(default)]
	pub starttls: bool,
	/// SMTP AUTH username for the relay (submission). Requires `starttls`.
	#[serde(default)]
	pub username: Option<String>,
	/// SMTP AUTH password for the relay.
	#[serde(default)]
	pub password: Option<String>,
	/// `host:port` of a SOCKS5 proxy to reach the smarthost through.
	#[serde(default)]
	pub socks_proxy: Option<String>,
	/// With `false` the rule stays in the file but is never selected, so mail
	/// goes by the next rule that matches, or direct. Only a `relay` rule may
	/// be switched off: `fail` is a refusal that must not lapse quietly.
	#[serde(default = "default_enabled")]
	pub enabled: bool,
}

const fn default_enabled() -> bool {
	true
}

impl std::fmt::Debug for Transport {
	// Every other field is not a secret, so it is printed verbatim; only the
	// relay's SMTP AUTH password is redacted. A relaying server prints its
	// rules to the log on startup and on reload, and a literal password is
	// the obvious thing that should not reach that sink.
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("Transport")
			.field("account", &self.account)
			.field("domain", &self.domain)
			.field("kind", &self.kind)
			.field("host", &self.host)
			.field("port", &self.port)
			.field("starttls", &self.starttls)
			.field("username", &self.username)
			.field("password", &self.password.as_ref().map(|_| "***"))
			.field("socks_proxy", &self.socks_proxy)
			.field("enabled", &self.enabled)
			.finish()
	}
}

/// Match specificity, most specific first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Specificity {
	/// Catch-all (neither account nor domain set).
	Any,
	/// Matched the recipient domain.
	Domain,
	/// Matched the sender account.
	Account,
}

impl Transport {
	/// How specifically this rule matches the given sender account and
	/// recipient domain, or `None` if it does not match.
	fn specificity(
		&self,
		sender_account: Option<&str>,
		recipient_domain: &str,
	) -> Option<Specificity> {
		if let Some(account) = &self.account {
			return match sender_account {
				Some(sender) if sender.eq_ignore_ascii_case(account) => Some(Specificity::Account),
				_ => None,
			};
		}
		if let Some(domain) = &self.domain {
			return recipient_domain
				.eq_ignore_ascii_case(domain)
				.then_some(Specificity::Domain);
		}
		Some(Specificity::Any)
	}

	/// Validate a `relay` rule has a host and port, and that AUTH is only used
	/// over STARTTLS (credentials never cross plaintext). Other kinds ignore the
	/// relay fields.
	pub fn validate(&self) -> Result<(), String> {
		if !self.enabled && self.kind != TransportKind::Relay {
			return Err(
				"only a relay transport can be switched off with enabled = false; \
				 remove a fail or direct rule instead"
					.into(),
			);
		}
		if self.kind == TransportKind::Relay {
			if self.host.is_none() || self.port.is_none() {
				return Err("relay transport needs host and port".into());
			}
			if self.username.is_some() && !self.starttls {
				return Err("relay AUTH requires starttls (no plaintext credentials)".into());
			}
		}
		Ok(())
	}
}

/// Select the transport rule for a delivery: most-specific match (account >
/// domain > catch-all), or `None` for the built-in direct default.
pub fn select<'a>(
	rules: &'a [Transport],
	sender_account: Option<&str>,
	recipient_domain: &str,
) -> Option<&'a Transport> {
	rules
		.iter()
		.filter(|rule| rule.enabled)
		.filter_map(|rule| {
			rule.specificity(sender_account, recipient_domain)
				.map(|spec| (spec, rule))
		})
		.max_by_key(|(spec, _)| *spec)
		.map(|(_, rule)| rule)
}

#[cfg(test)]
mod tests;
