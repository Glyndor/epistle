//! IMAP authentication: the SASL mechanisms the session advertises and the
//! exchange each one runs.
//!
//! [`mechanisms`] holds the shared part (the advertised capabilities, the
//! `AUTHENTICATE` entry point and the password mechanisms), [`scram`] the
//! SCRAM-SHA-256 exchanges, [`oauth`] the bearer-token ones, and
//! [`completion`] the step that turns a verified credential into a session.

mod completion;
mod mechanisms;
mod oauth;
mod scram;

pub(crate) use oauth::parse_bearer;

/// In-flight SASL state between AUTHENTICATE continuation lines.
pub(super) enum PendingAuth {
	/// Tag stashed while awaiting the PLAIN response (`+ `).
	Plain { tag: String },
	/// Awaiting the SCRAM client-first message (with its channel-binding policy).
	ScramFirst {
		tag: String,
		binding: crate::smtp::scram::ChannelBinding,
	},
	/// Awaiting the SCRAM client-final message.
	ScramFinal {
		tag: String,
		server: Box<crate::smtp::scram::ScramServer>,
		credentials: Box<crate::smtp::scram::ScramCredentials>,
		account: String,
		/// `Some` when the server-first was built on decoy credentials: the
		/// exchange cannot succeed, and the refusal says whether it still
		/// counts as a failed attempt (see [`crate::smtp::directory::ScramRefusal`]). A banned
		/// subject who completes the exchange must not clear the ban with a
		/// valid proof nor extend it with a bad one.
		refusal: Option<crate::smtp::directory::ScramRefusal>,
	},
	/// AUTH=LOGIN: awaiting the base64 username.
	LoginUser { tag: String },
	/// AUTH=LOGIN: awaiting the base64 password for `user`.
	LoginPass { tag: String, user: String },
	/// AUTH=EXTERNAL: awaiting the (optional) authzid.
	External { tag: String },
	/// OAUTHBEARER/XOAUTH2 without an initial response: awaiting the bearer
	/// message after the empty `+ ` continuation (RFC 3501 6.2.2, RFC 4959).
	Bearer { tag: String },
	/// OAUTHBEARER/XOAUTH2: the error challenge was sent; awaiting the
	/// client's acknowledgement line before the final `NO` (RFC 7628 3.2.3).
	BearerError { tag: String },
}
