//! The host's global addresses, offered by `init` as the public IPv4 and
//! IPv6. The interface walk itself lives in [`crate::dns::detect`] and
//! applies the same "is global" rule the config validation enforces on
//! `public_ipv4` / `public_ipv6`, so a private, loopback, link-local, ULA,
//! CGNAT or documentation address is never proposed.
//!
//! The detector is a trait so the tests drive `init` with a scripted pair
//! (or one that panics when called) and never touch a real interface. A
//! detector that fails counts as "nothing found": detection is a
//! convenience, it never stops the run.

use std::io::Write;
use std::net::{Ipv4Addr, Ipv6Addr};

use super::Answers;

/// One global address per family, either of which may be absent.
pub(super) type Detected = (Option<Ipv4Addr>, Option<Ipv6Addr>);

/// Where `init` gets the host's global addresses from.
pub(super) trait Detector {
	/// The lowest global IPv4 and IPv6 on the host's interfaces.
	fn detect(&self) -> std::io::Result<Detected>;
}

/// The production detector: the kernel's interface list.
pub(super) struct LiveDetector;

impl Detector for LiveDetector {
	fn detect(&self) -> std::io::Result<Detected> {
		crate::dns::detect()
	}
}

/// Run the detector once, folding a failure into "nothing found".
pub(super) fn detect_or_none(detector: &dyn Detector) -> Detected {
	detector.detect().unwrap_or((None, None))
}

/// The one-line hint for the families that ended up without an address,
/// or `None` when nothing is missing. Behind NAT the host only carries a
/// private address, so the public one has to come from the operator.
pub(super) fn nat_hint(missing_v4: bool, missing_v6: bool) -> Option<String> {
	let families = match (missing_v4, missing_v6) {
		(true, true) => "IPv4 or IPv6",
		(true, false) => "IPv4",
		(false, true) => "IPv6",
		(false, false) => return None,
	};
	Some(format!(
		"no global {families} address on this host's interfaces (behind NAT the public one is not visible here; set it by hand if the server has one)"
	))
}

/// Fill the addresses an answers file leaves out from `detector`. An
/// address the file names is never second-guessed, and when the file
/// names both the detector is not called at all. Every filled address is
/// reported on `out`, and the families still empty get the NAT hint.
pub(super) fn fill_missing(answers: &mut Answers, detector: &dyn Detector, out: &mut dyn Write) {
	let want_v4 = answers.public_ipv4.is_none();
	let want_v6 = answers.public_ipv6.is_none();
	if !want_v4 && !want_v6 {
		return;
	}
	let (v4, v6) = detect_or_none(detector);
	if want_v4 && let Some(address) = v4 {
		answers.public_ipv4 = Some(address);
		let _ = writeln!(
			out,
			"detected public_ipv4 = {address} (not in the answers file)"
		);
	}
	if want_v6 && let Some(address) = v6 {
		answers.public_ipv6 = Some(address);
		let _ = writeln!(
			out,
			"detected public_ipv6 = {address} (not in the answers file)"
		);
	}
	if let Some(hint) = nat_hint(answers.public_ipv4.is_none(), answers.public_ipv6.is_none()) {
		let _ = writeln!(out, "{hint}");
	}
}

#[cfg(test)]
#[path = "detect_tests.rs"]
pub(super) mod tests;
