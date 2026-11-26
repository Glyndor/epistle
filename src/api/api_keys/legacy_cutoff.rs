//! The end of `read` and `write`.
//!
//! The names 0.14.0 used open management and mail at once, so 0.15.0 keeps
//! their reach and says so. A later release refuses `stack update` while a key
//! still holds one: the release is [`LEGACY_SCOPES_REFUSED_FROM`], and the
//! refusal itself is one call of [`refused_at`] from that release's update.
//! Until then nothing is refused or revoked.

/// The first release whose `stack update` refuses a stack with a key that
/// opens both management and mail. Two minor releases after the one that
/// introduced the four scopes; change it here to move the date.
pub const LEGACY_SCOPES_REFUSED_FROM: &str = "0.17.0";

/// The warning for the key labelled `label`, which opens both management and
/// mail: what it does, the command that splits it and when the old names stop.
pub fn warning(label: &str) -> String {
	format!(
		"opens both management and mail; split it with `epistle api-key set {label} --scope \
		 manage:read --scope manage:write` or `--scope mail:read --scope mail:write` \
		 (`stack update` refuses a stack that still has one from {LEGACY_SCOPES_REFUSED_FROM})"
	)
}

/// Whether `current` is at or past [`LEGACY_SCOPES_REFUSED_FROM`], comparing
/// the numbers of `major.minor.patch`. A version this cannot read is not past
/// it: refusing an update on a guess would be worse than warning.
pub fn refused_at(current: &str) -> bool {
	match (numbers(current), numbers(LEGACY_SCOPES_REFUSED_FROM)) {
		(Some(current), Some(cutoff)) => current >= cutoff,
		_ => false,
	}
}

fn numbers(version: &str) -> Option<(u64, u64, u64)> {
	let core = version.split(['-', '+']).next()?;
	let mut parts = core.split('.').map(|part| part.parse::<u64>().ok());
	Some((parts.next()??, parts.next()??, parts.next()??))
}
