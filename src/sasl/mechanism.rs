//! The SASL mechanisms the server knows and their wire names.

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
