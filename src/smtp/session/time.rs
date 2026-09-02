//! Small free-function helpers shared by the SMTP session modules.
//!
//! Split into a sibling file so the production file stays under the
//! per-file code-line budget; both functions are tiny and have no
//! shared state, so the split is cosmetic.

/// Current time in epoch seconds (for rate-limit windows).
pub(super) fn unix_now() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0)
}
