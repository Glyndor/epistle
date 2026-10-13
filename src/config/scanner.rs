//! Settings for the Unix socket content scanner, plus the Bayesian
//! thresholds that decide on their own without consulting the LLM hook.

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

/// Score above which unauthenticated inbound mail is delivered to the
/// recipient's Junk mailbox with `X-Spam-Status: Yes` and the score in
/// `X-Spam-Score`. The default (`0.95`) is high enough that a corpus only
/// modestly trained on spam cannot trip it: a token needs to be very
/// strongly correlated with spam across many training messages for the
/// Graham combiner to land that high.
pub const DEFAULT_BAYES_JUNK_AT: f64 = 0.95;

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
	/// Scan what this server's own accounts submit (SMTP after AUTH,
	/// `/api/v1/send`, JMAP `EmailSubmission/set`) and refuse a detection,
	/// whatever `clamd_on_found` says for inbound mail. Default `true`;
	/// it has an effect only when `clamd_socket` is set.
	pub scan_authenticated: bool,
	/// The probability in `[0.0, 1.0]` at or above which an
	/// unauthenticated message is delivered to the recipient's Junk
	/// mailbox with `X-Spam-Status: Yes` and the score in
	/// `X-Spam-Score`. Default `0.95`. A corpus below
	/// `MIN_TRUSTED_MESSAGES` on either side never decides anything
	/// (the historical "only score on trained data" guard), so an
	/// empty corpus cannot junk every message.
	pub bayes_junk_at: f64,
	/// The probability in `[0.0, 1.0]` at or above which an
	/// unauthenticated message is rejected with `550 5.7.1` during the
	/// DATA phase. Optional: when unset, the threshold is off (the
	/// default behaviour, which only delivers to Junk). When set, it
	/// must be at least `bayes_junk_at` so the rejected band is a
	/// subset of the junked one and the wiring does not have to pick
	/// between two disposals for the same score.
	pub bayes_reject_at: Option<f64>,
}

impl Default for Antispam {
	fn default() -> Self {
		Self {
			clamd_socket: None,
			clamd_on_found: ClamdOnFound::Quarantine,
			clamd_timeout_secs: DEFAULT_TIMEOUT_SECS,
			clamd_max_bytes: DEFAULT_MAX_BYTES,
			scan_authenticated: true,
			bayes_junk_at: DEFAULT_BAYES_JUNK_AT,
			bayes_reject_at: None,
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
		if !(0.0..=1.0).contains(&self.antispam.bayes_junk_at) {
			return Err(ConfigError::Invalid(format!(
				"[antispam] bayes_junk_at must be in [0.0, 1.0]: {}",
				self.antispam.bayes_junk_at
			)));
		}
		if let Some(reject) = self.antispam.bayes_reject_at {
			if !(0.0..=1.0).contains(&reject) {
				return Err(ConfigError::Invalid(format!(
					"[antispam] bayes_reject_at must be in [0.0, 1.0]: {reject}"
				)));
			}
			if reject < self.antispam.bayes_junk_at {
				return Err(ConfigError::Invalid(format!(
					"[antispam] bayes_reject_at ({reject}) must be at least bayes_junk_at ({}) so the rejected band is a subset of the junked one",
					self.antispam.bayes_junk_at
				)));
			}
		}
		Ok(())
	}
}

#[cfg(test)]
#[path = "scanner_tests.rs"]
mod tests;
