//! Length-aware constant-time byte comparison.
//!
//! Always scans both inputs fully, so a mismatch leaks neither the
//! position of the first differing byte nor (beyond length) the expected
//! value. The length check short-circuits to `false` because the input
//! length is already public on the wire.
//!
//! Used wherever a caller holds a high-entropy expected value (an OAuth
//! PKCE challenge, a TOTP code, a SubjectPass token) and is asked
//! whether an attacker-supplied candidate matches.

/// Constant-time byte comparison for slices of equal length.
///
/// Returns `false` immediately for inputs of different length (the length
/// is not secret). For inputs of equal length, both slices are scanned
/// in full regardless of where the first mismatch sits.
pub fn eq(a: &[u8], b: &[u8]) -> bool {
	if a.len() != b.len() {
		return false;
	}
	let mut diff = 0u8;
	for (x, y) in a.iter().zip(b.iter()) {
		diff |= x ^ y;
	}
	diff == 0
}

#[cfg(test)]
#[path = "constant_time_tests.rs"]
mod tests;
