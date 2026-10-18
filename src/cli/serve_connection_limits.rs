//! What the IMAP, POP3, ManageSieve and plain-HTTP listeners are held to,
//! from the configuration: absent (or zero) keys keep the built-in values.

use std::time::Duration;

use crate::config::Config;
use crate::net::conn_limit::{
	DEFAULT_HTTP_CONNECTIONS, DEFAULT_HTTP_CONNECTIONS_PER_IP, DEFAULT_MAILBOX_CONNECTIONS_PER_IP,
};
use crate::net::deadline::DEFAULT_PREAUTH_TIMEOUT;

/// The limits shared by the three mailbox-access listeners.
pub(super) struct MailboxLimits {
	/// How long a client gets, from the start of the connection, to sign in.
	pub preauth_timeout: Duration,
	/// Connections one client may hold on a listener.
	pub per_ip: usize,
}

impl MailboxLimits {
	pub(super) fn from_config(config: &Config) -> Self {
		MailboxLimits {
			preauth_timeout: config
				.preauth_timeout
				.map_or(DEFAULT_PREAUTH_TIMEOUT, Duration::from_secs),
			per_ip: nonzero(
				config.max_mailbox_connections_per_ip,
				DEFAULT_MAILBOX_CONNECTIONS_PER_IP,
			),
		}
	}
}

/// The limits of every plain-HTTP listener.
pub(super) fn http_limits(config: &Config) -> crate::net::http_serve::Limits {
	crate::net::http_serve::Limits {
		connections: nonzero(config.max_http_connections, DEFAULT_HTTP_CONNECTIONS),
		per_ip: nonzero(
			config.max_http_connections_per_ip,
			DEFAULT_HTTP_CONNECTIONS_PER_IP,
		),
	}
}

/// A configured cap, or `default` when it is absent or `0`.
fn nonzero(configured: Option<usize>, default: usize) -> usize {
	configured.filter(|value| *value != 0).unwrap_or(default)
}

#[cfg(test)]
#[path = "serve_connection_limits_tests.rs"]
mod tests;
