//! Length-aware constant-time byte comparison.
//!
//! Always scans both inputs fully, so a mismatch leaks neither the
//! position of the first differing byte nor (beyond length) the expected
//! value. The length check short-circuits to `false` because the input
//! length is already public on the wire.
//!
//! Used wherever a caller holds a high-entropy expected value (an OAuth
//! PKCE challenge, a TOTP code, a SubjectPass token, a SCRAM stored key,
//! an OAuth device user code, a bearer/API-key sha256 digest) and is
//! asked whether an attacker-supplied candidate matches.
//!
//! The comparison is delegated to ring's
//! [`verify_slices_are_equal`](ring::constant_time::verify_slices_are_equal),
//! which is the same primitive but with a constant-time guarantee that
//! is independently audited. ring deprecated the module on the way to a
//! future replacement; the call here is the canonical one today. A
//! mismatch of length returns `false` straight away (length is not
//! secret; the public wire input announces it), matching ring's
//! `Result::Err` semantics.

/// Constant-time byte comparison for slices of equal length.
///
/// Returns `false` immediately for inputs of different length (the length
/// is not secret). For inputs of equal length, both slices are scanned
/// in full regardless of where the first mismatch sits.
pub fn eq(a: &[u8], b: &[u8]) -> bool {
	if a.len() != b.len() {
		return false;
	}
	// ring's primitive: returns `Ok(())` on match, `Err(Unspecified)` on
	// mismatch. The deprecated warning is suppressed at the call site
	// rather than file-wide so the visibility is one line.
	#[allow(deprecated)]
	ring::constant_time::verify_slices_are_equal(a, b).is_ok()
}

#[cfg(test)]
mod tests;
