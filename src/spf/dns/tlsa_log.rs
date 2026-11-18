//! What the TLSA lookup writes to the log. The DNSSEC validator of the
//! resolver is silent by default (see `crate::cli::trace`), so the outcome of
//! each lookup is reported here, in one line with the name and the reason and
//! never with the response it came from.

use hickory_resolver::net::{DnsError, NetError};
use hickory_resolver::proto::dnssec::Proof;
use hickory_resolver::proto::rr::RecordType;

/// A zone that publishes no TLSA is normal, and an unsigned one cannot prove
/// anything either way: a debug line, not a failure. The answer carries the
/// NSEC or NSEC3 records of a zone that is signed.
pub(super) fn log_absent(name: &str, authorities: &[RecordType]) {
	let signed = authorities
		.iter()
		.any(|kind| matches!(kind, RecordType::NSEC | RecordType::NSEC3));
	if signed {
		tracing::debug!("no TLSA for {name}: the zone is signed and proves there is none (secure)");
	} else {
		tracing::debug!("no TLSA for {name}: zone is not signed (insecure)");
	}
}

/// The lookup failed. A failure of DNSSEC validation, which must not go
/// unseen, is a `warn` with the name, the record type and the reason; any
/// other failure (a timeout, a refused query) is the transient error the
/// caller defers on, and a debug line here.
pub(super) fn log_failure(name: &str, error: &NetError) {
	if is_validation_failure(error) {
		tracing::warn!(
			"DNSSEC validation of the TLSA lookup for {name} failed: {}",
			reason(error)
		);
	} else {
		tracing::debug!("TLSA lookup for {name} failed: {}", reason(error));
	}
}

/// The answer came back with a signature that does not verify.
pub(super) fn log_bogus(name: &str) {
	tracing::warn!(
		"DNSSEC validation of the TLSA lookup for {name} failed: the signature of the answer \
		 does not verify"
	);
}

fn is_validation_failure(error: &NetError) -> bool {
	match error {
		NetError::Dns(DnsError::DnssecBogus) => true,
		NetError::Dns(DnsError::Nsec { proof, .. }) => *proof == Proof::Bogus,
		_ => false,
	}
}

fn reason(error: &NetError) -> String {
	// A reason from the library is a short phrase; the cap keeps one that is
	// not from filling the log.
	const CUT_AT: usize = 160;
	let text = error.to_string();
	match text.char_indices().nth(CUT_AT) {
		Some((end, _)) => format!("{}...", &text[..end]),
		None => text,
	}
}

#[cfg(test)]
mod tests;
