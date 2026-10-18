//! What the IMAP, POP3 and ManageSieve listeners are held to, from the
//! configuration: absent keys keep the built-in values.

use std::time::Duration;

use crate::config::Config;
use crate::net::deadline::DEFAULT_PREAUTH_TIMEOUT;

/// The limits shared by the three mailbox-access listeners.
pub(super) struct MailboxLimits {
	/// How long a client gets, from the start of the connection, to sign in.
	pub preauth_timeout: Duration,
}

impl MailboxLimits {
	pub(super) fn from_config(config: &Config) -> Self {
		MailboxLimits {
			preauth_timeout: config
				.preauth_timeout
				.map_or(DEFAULT_PREAUTH_TIMEOUT, Duration::from_secs),
		}
	}
}

#[cfg(test)]
#[path = "serve_mailbox_limits_tests.rs"]
mod tests;
