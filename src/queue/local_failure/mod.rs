//! A delivery that fails for a reason of this side of the conversation
//! (no server answered, TLS could not be had, a policy forbids the
//! exchanger) has no reply of a remote to quote. Its reason carries an
//! enhanced status code of its own (RFC 3463) followed by one short fixed
//! sentence that names the cause, so the delivery log, the report to the
//! sender and the operator read the same thing.
//!
//! The class digit in the stored reason is the class of the attempt (a
//! retried attempt is `4`); the report writes the class of its own action
//! (`5` once the message is given up), as it does for a remote's reply.

use super::client::DeliveryError;
use super::reply::{Enhanced, parse_enhanced};

/// What went wrong on this side of the conversation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LocalFailure {
	/// TLS is mandatory (MTA-STS enforce, DANE, REQUIRETLS) and the server
	/// does not offer STARTTLS: `X.7.10`, encryption required (RFC 5248).
	TlsRequired,
	/// The certificate matches none of the DANE TLSA records: `X.7.5`.
	TlsaMismatch,
	/// The TLSA lookup failed, so DANE cannot be decided: `X.7.5`.
	TlsaLookup,
	/// The TLS handshake failed, certificate checks included: `X.7.5`.
	Handshake,
	/// The MTA-STS policy of an enforce domain allows none of its mail
	/// servers: `X.7.5`.
	MtaStsNoServer,
	/// A DNSSEC validation failed for the mail server records: `X.7.5`.
	Dnssec,
	/// The mail server could not be reached: `X.4.1`.
	Unreachable,
	/// The mail servers could not be looked up: `X.4.3`.
	MxLookup,
}

impl LocalFailure {
	/// The subject and detail of the enhanced status code.
	pub(crate) fn status(self) -> (u16, u16) {
		match self {
			LocalFailure::TlsRequired => (7, 10),
			LocalFailure::TlsaMismatch
			| LocalFailure::TlsaLookup
			| LocalFailure::Handshake
			| LocalFailure::MtaStsNoServer
			| LocalFailure::Dnssec => (7, 5),
			LocalFailure::Unreachable => (4, 1),
			LocalFailure::MxLookup => (4, 3),
		}
	}

	/// The fixed sentence for `host` (a mail server) or, for the failures
	/// of a whole domain, that domain.
	fn sentence(self, host: &str) -> String {
		match self {
			LocalFailure::TlsRequired => {
				format!("TLS is required but {host} does not offer STARTTLS")
			}
			LocalFailure::TlsaMismatch => {
				format!("the certificate of {host} matches none of its DANE TLSA records")
			}
			LocalFailure::TlsaLookup => format!(
				"the DANE TLSA records of {host} could not be looked up, so its TLS \
				 cannot be verified"
			),
			LocalFailure::Handshake => format!("the TLS handshake with {host} failed"),
			LocalFailure::MtaStsNoServer => {
				format!("the MTA-STS policy of {host} allows none of its mail servers")
			}
			LocalFailure::Dnssec => {
				format!("DNSSEC validation of the mail server records of {host} failed")
			}
			LocalFailure::Unreachable => format!("the mail server {host} could not be reached"),
			LocalFailure::MxLookup => format!("the mail servers of {host} could not be looked up"),
		}
	}

	/// The reason of a retried attempt: `4.S.D sentence`. `detail` is the
	/// underlying error, kept in the log of the server and out of the
	/// reason, which the sender reads.
	pub(crate) fn transient(self, host: &str, detail: &str) -> DeliveryError {
		tracing::info!(cause = ?self, %host, %detail, "local delivery failure");
		let (subject, code) = self.status();
		DeliveryError::Transient(format!("4.{subject}.{code} {}", self.sentence(host)))
	}
}

/// The enhanced status and the sentence of a reason written by
/// [`LocalFailure`], or `None` for a remote's reply and for any other
/// local reason.
pub(crate) fn parse(reason: &str) -> Option<(Enhanced, &str)> {
	let (token, sentence) = reason.split_once(' ')?;
	let enhanced = parse_enhanced(token)?;
	(!sentence.is_empty()).then_some((enhanced, sentence))
}

#[cfg(test)]
mod tests;
