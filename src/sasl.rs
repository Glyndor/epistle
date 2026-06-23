//! Shared SASL mechanism abstraction.
//!
//! SMTP and IMAP advertise and negotiate the same set of SASL mechanisms under
//! the same conditions (channel binding needs a bound certificate hash; the
//! OAuth mechanisms need a configured verifier). This module is the single
//! source of truth for which mechanisms are available, so the two protocols
//! cannot drift apart — each only formats the shared list in its own syntax.

/// A SASL authentication mechanism supported by the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mechanism {
	/// TLS client-certificate authentication (RFC 4422 EXTERNAL): the identity
	/// comes from the verified certificate, not a password.
	External,
	/// SCRAM-SHA-256 with channel binding (RFC 5802 + RFC 9266).
	ScramSha256Plus,
	/// SCRAM-SHA-256 without channel binding (RFC 5802).
	ScramSha256,
	/// SASL PLAIN (RFC 4616).
	Plain,
	/// The non-standard but widespread LOGIN mechanism.
	Login,
	/// OAUTHBEARER bearer token (RFC 7628).
	OauthBearer,
	/// Google's XOAUTH2 bearer token.
	Xoauth2,
}

impl Mechanism {
	/// The mechanism's SASL name as it appears on the wire.
	pub fn name(self) -> &'static str {
		match self {
			Mechanism::External => "EXTERNAL",
			Mechanism::ScramSha256Plus => "SCRAM-SHA-256-PLUS",
			Mechanism::ScramSha256 => "SCRAM-SHA-256",
			Mechanism::Plain => "PLAIN",
			Mechanism::Login => "LOGIN",
			Mechanism::OauthBearer => "OAUTHBEARER",
			Mechanism::Xoauth2 => "XOAUTH2",
		}
	}

	/// Parse a (case-insensitive) mechanism name.
	pub fn parse(name: &str) -> Option<Mechanism> {
		let upper = name.to_ascii_uppercase();
		[
			Mechanism::External,
			Mechanism::ScramSha256Plus,
			Mechanism::ScramSha256,
			Mechanism::Plain,
			Mechanism::Login,
			Mechanism::OauthBearer,
			Mechanism::Xoauth2,
		]
		.into_iter()
		.find(|mechanism| mechanism.name() == upper)
	}
}

/// The mechanisms the server offers, strongest first, given whether a verified
/// client certificate is present (EXTERNAL), channel binding is available (a
/// bound certificate hash, for `-PLUS`), and an OAuth verifier is configured.
/// Failing closed: a mechanism whose precondition is unmet is never advertised.
pub fn available(external: bool, channel_binding: bool, oauth: bool) -> Vec<Mechanism> {
	let mut mechanisms = Vec::with_capacity(7);
	if external {
		mechanisms.push(Mechanism::External);
	}
	if channel_binding {
		mechanisms.push(Mechanism::ScramSha256Plus);
	}
	mechanisms.extend([Mechanism::ScramSha256, Mechanism::Plain, Mechanism::Login]);
	if oauth {
		mechanisms.extend([Mechanism::OauthBearer, Mechanism::Xoauth2]);
	}
	mechanisms
}

/// `true` when the mechanism is currently offered (advertised) under the given
/// preconditions. The dispatch uses this to reject a mechanism a client tries
/// without it having been advertised (e.g. `-PLUS` with no channel binding).
pub fn is_available(
	mechanism: Mechanism,
	external: bool,
	channel_binding: bool,
	oauth: bool,
) -> bool {
	available(external, channel_binding, oauth).contains(&mechanism)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn parse_is_case_insensitive_and_total() {
		assert_eq!(Mechanism::parse("plain"), Some(Mechanism::Plain));
		assert_eq!(
			Mechanism::parse("Scram-Sha-256"),
			Some(Mechanism::ScramSha256)
		);
		assert_eq!(
			Mechanism::parse("SCRAM-SHA-256-PLUS"),
			Some(Mechanism::ScramSha256Plus)
		);
		assert_eq!(Mechanism::parse("XOAUTH2"), Some(Mechanism::Xoauth2));
		assert_eq!(Mechanism::parse("DIGEST-MD5"), None);
		assert_eq!(Mechanism::parse(""), None);
	}

	#[test]
	fn name_round_trips_through_parse() {
		for mechanism in available(true, true, true) {
			assert_eq!(Mechanism::parse(mechanism.name()), Some(mechanism));
		}
	}

	#[test]
	fn channel_binding_gates_plus() {
		assert!(available(false, false, false).contains(&Mechanism::ScramSha256));
		assert!(!available(false, false, false).contains(&Mechanism::ScramSha256Plus));
		assert!(available(false, true, false).contains(&Mechanism::ScramSha256Plus));
		// -PLUS is offered strongest-first (no EXTERNAL present).
		assert_eq!(available(false, true, false)[0], Mechanism::ScramSha256Plus);
	}

	#[test]
	fn external_gates_on_client_certificate() {
		assert!(!available(false, false, false).contains(&Mechanism::External));
		assert!(available(true, false, false).contains(&Mechanism::External));
		// EXTERNAL is the strongest, offered first.
		assert_eq!(available(true, true, false)[0], Mechanism::External);
		assert_eq!(Mechanism::parse("external"), Some(Mechanism::External));
	}

	#[test]
	fn oauth_gates_bearer_mechanisms() {
		assert!(!available(false, false, false).contains(&Mechanism::OauthBearer));
		assert!(available(false, false, true).contains(&Mechanism::OauthBearer));
		assert!(available(false, false, true).contains(&Mechanism::Xoauth2));
	}

	#[test]
	fn is_available_matches_advertised() {
		assert!(is_available(Mechanism::Plain, false, false, false));
		assert!(!is_available(Mechanism::External, false, false, false));
		assert!(is_available(Mechanism::External, true, false, false));
		assert!(!is_available(
			Mechanism::ScramSha256Plus,
			false,
			false,
			false
		));
		assert!(is_available(Mechanism::ScramSha256Plus, false, true, false));
		assert!(!is_available(Mechanism::OauthBearer, false, false, false));
		assert!(is_available(Mechanism::OauthBearer, false, false, true));
	}
}
