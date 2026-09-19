//! Settings for the Unix socket content scanner.

use std::path::PathBuf;

use serde::Deserialize;

use super::{Config, ConfigError};
use crate::antispam::clamd::{DEFAULT_MAX_BYTES, DEFAULT_TIMEOUT_SECS};
use crate::antispam::hook::HookVerdict;

/// Action to apply when clamd reports a signature.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ClamdOnFound {
	/// Accept into the Rejects mailbox.
	#[default]
	Quarantine,
	/// Reject the message during SMTP delivery.
	Reject,
}

impl From<ClamdOnFound> for HookVerdict {
	fn from(value: ClamdOnFound) -> Self {
		match value {
			ClamdOnFound::Quarantine => Self::Quarantine,
			ClamdOnFound::Reject => Self::Reject,
		}
	}
}

/// The `[antispam]` section, with clamd disabled unless a socket is set.
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Antispam {
	/// Unix socket shared with clamd, such as `/run/clamav/clamd.sock`.
	pub clamd_socket: Option<PathBuf>,
	/// Verdict on detection, defaulting to quarantine.
	pub clamd_on_found: ClamdOnFound,
	/// Deadline for the entire exchange, in seconds (default 30).
	pub clamd_timeout_secs: u64,
	/// Maximum message size to send, in bytes (default 25 MiB).
	pub clamd_max_bytes: usize,
}

impl Default for Antispam {
	fn default() -> Self {
		Self {
			clamd_socket: None,
			clamd_on_found: ClamdOnFound::Quarantine,
			clamd_timeout_secs: DEFAULT_TIMEOUT_SECS,
			clamd_max_bytes: DEFAULT_MAX_BYTES,
		}
	}
}

impl Config {
	pub(super) fn validate_scanner(&self) -> Result<(), ConfigError> {
		if self.scanner_hook_url.is_some() && self.antispam.clamd_socket.is_some() {
			return Err(ConfigError::Invalid(
				"clamd_socket and scanner_hook_url cannot be set together: only one scanner per server"
					.into(),
			));
		}
		Ok(())
	}
}

#[cfg(test)]
#[path = "scanner_tests.rs"]
mod tests;
