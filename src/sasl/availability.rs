//! Which mechanisms are offered under which preconditions.

use super::Mechanism;

/// The mechanisms the server offers, strongest first, given whether a verified
/// client certificate is present (EXTERNAL), channel binding is available (a
/// bound certificate hash, for `-PLUS`), SCRAM is enabled (`scram = true`
/// under `[auth]`), and an OAuth verifier is configured. Failing closed: a
/// mechanism whose precondition is unmet is never advertised.
pub fn available(
	external: bool,
	channel_binding: bool,
	scram_enabled: bool,
	oauth: bool,
) -> Vec<Mechanism> {
	let mut mechanisms = Vec::with_capacity(7);
	if external {
		mechanisms.push(Mechanism::External);
	}
	if scram_enabled && channel_binding {
		mechanisms.push(Mechanism::ScramSha256Plus);
	}
	if scram_enabled {
		mechanisms.push(Mechanism::ScramSha256);
	}
	mechanisms.extend([Mechanism::Plain, Mechanism::Login]);
	if oauth {
		mechanisms.extend([Mechanism::OauthBearer, Mechanism::Xoauth2]);
	}
	mechanisms
}

/// `true` when the mechanism is currently offered (advertised) under the given
/// preconditions. The dispatch uses this to reject a mechanism a client tries
/// without it having been advertised (e.g. `-PLUS` with no channel binding,
/// or any SCRAM mechanism when `scram = false`).
pub fn is_available(
	mechanism: Mechanism,
	external: bool,
	channel_binding: bool,
	scram_enabled: bool,
	oauth: bool,
) -> bool {
	available(external, channel_binding, scram_enabled, oauth).contains(&mechanism)
}
