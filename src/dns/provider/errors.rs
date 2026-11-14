/// A provider operation failure. Its message never contains the secret token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderError {
	/// The provider does not support writes (e.g. manual mode).
	Unsupported,
	/// Authentication with the provider failed.
	Auth,
	/// The provider holds no zone with that name. It is the one failure a
	/// caller may read as "that zone is not there": every other failure
	/// says that the provider could not answer, and the caller must not
	/// read it as an absent zone.
	ZoneNotFound(String),
	/// A transport or provider-side error.
	Remote(String),
}

impl std::fmt::Display for ProviderError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			ProviderError::Unsupported => f.write_str("provider does not support writes"),
			ProviderError::Auth => f.write_str("provider authentication failed"),
			// The zone name comes from the caller, but it still reaches a
			// terminal, a log and a message: it is escaped like any other
			// text from outside.
			ProviderError::ZoneNotFound(zone) => {
				write!(
					f,
					"provider error: zone not found: {}",
					crate::cli::term::sanitize(zone)
				)
			}
			// What a provider answered is text from outside: control characters
			// and bidirectional marks in it are escaped before they can reach a
			// terminal, a log or a message.
			ProviderError::Remote(detail) => {
				write!(f, "provider error: {}", crate::cli::term::sanitize(detail))
			}
		}
	}
}

impl std::error::Error for ProviderError {}

impl From<crate::net::HttpsUrlError> for ProviderError {
	fn from(err: crate::net::HttpsUrlError) -> Self {
		ProviderError::Remote(format!("invalid request URL: {err}"))
	}
}
