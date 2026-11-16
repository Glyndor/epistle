//! Load-time checks of the inbound settings of `[antispam]`: the HTTP
//! scanner hook, greylisting and the sender-domain reputation. Each setting
//! has a floor or a ceiling the server enforces, and an error names the key.

use super::{Config, ConfigError};

/// Default deadline of a scanner hook call, in seconds.
pub const DEFAULT_HOOK_TIMEOUT_SECS: u64 = 30;
/// Longest deadline a scanner hook call may be given: the sender's
/// connection waits it out.
const MAX_HOOK_TIMEOUT_SECS: u64 = 120;
/// Default time a greylist triplet is kept, in seconds (a day).
pub const DEFAULT_GREYLIST_LIFETIME_SECS: u64 = 86_400;
/// Shortest lifetime of a greylist triplet.
const MIN_GREYLIST_LIFETIME_SECS: u64 = 3_600;
/// Longest lifetime of a greylist triplet (thirty days).
const MAX_GREYLIST_LIFETIME_SECS: u64 = 30 * 86_400;
/// Default observations before a sender domain's reputation is judged.
pub const DEFAULT_REPUTATION_MIN_OBSERVATIONS: u32 = 3;
/// Most observations a domain may be required to have.
const MAX_REPUTATION_MIN_OBSERVATIONS: u32 = 1000;

fn invalid(message: String) -> ConfigError {
	ConfigError::Invalid(message)
}

impl Config {
	/// The longest greylist delay in force anywhere: the server's or a
	/// scope's. A scope delay past its own ceiling is refused with a
	/// message of its own, so it is not counted here.
	fn longest_greylist_delay(&self) -> u64 {
		self.antispam_scopes
			.iter()
			.filter_map(|scope| scope.greylist_delay_secs)
			.filter(|delay| *delay <= super::super::antispam_scope::MAX_GREYLIST_DELAY_SECS)
			.fold(self.greylist_delay_secs, u64::max)
	}

	pub(super) fn validate_inbound_antispam(&self) -> Result<(), ConfigError> {
		let antispam = &self.antispam;
		if !(1..=MAX_HOOK_TIMEOUT_SECS).contains(&antispam.scanner_hook_timeout_secs) {
			return Err(invalid(format!(
				"[antispam] scanner_hook_timeout_secs must be between 1 and {MAX_HOOK_TIMEOUT_SECS}: {}",
				antispam.scanner_hook_timeout_secs
			)));
		}
		if !(24..=32).contains(&antispam.greylist_mask_v4) {
			return Err(invalid(format!(
				"[antispam] greylist_mask_v4 must be between 24 and 32: a wider prefix lets a neighbour's retry release a stranger's message: {}",
				antispam.greylist_mask_v4
			)));
		}
		if !(48..=128).contains(&antispam.greylist_mask_v6) {
			return Err(invalid(format!(
				"[antispam] greylist_mask_v6 must be between 48 and 128: {}",
				antispam.greylist_mask_v6
			)));
		}
		if !(MIN_GREYLIST_LIFETIME_SECS..=MAX_GREYLIST_LIFETIME_SECS)
			.contains(&antispam.greylist_lifetime_secs)
		{
			return Err(invalid(format!(
				"[antispam] greylist_lifetime_secs must be between {MIN_GREYLIST_LIFETIME_SECS} and {MAX_GREYLIST_LIFETIME_SECS}: {}",
				antispam.greylist_lifetime_secs
			)));
		}
		let delay = self.longest_greylist_delay();
		if antispam.greylist_lifetime_secs < delay {
			return Err(invalid(format!(
				"[antispam] greylist_lifetime_secs ({}) must be at least the longest greylist delay ({delay}): a triplet would be forgotten before it could be accepted",
				antispam.greylist_lifetime_secs
			)));
		}
		if !(DEFAULT_REPUTATION_MIN_OBSERVATIONS..=MAX_REPUTATION_MIN_OBSERVATIONS)
			.contains(&antispam.reputation_min_observations)
		{
			return Err(invalid(format!(
				"[antispam] reputation_min_observations must be between {DEFAULT_REPUTATION_MIN_OBSERVATIONS} and {MAX_REPUTATION_MIN_OBSERVATIONS}: {}",
				antispam.reputation_min_observations
			)));
		}
		Ok(())
	}
}
