//! The reasons an inbound message is rejected, each with its counter label.

/// Why an inbound message was rejected, for the per-reason counter label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
	/// Rejected because the client IP appeared in a configured DNSBL.
	Dnsbl,
	/// Rejected because SPF did not pass and the receiver's policy enforces.
	Spf,
	/// Rejected because DMARC alignment failed and the record's policy is
	/// `reject` (or `quarantine`, which the metrics treat as a rejection).
	Dmarc,
	/// Rejected because the sender's reputation crossed the suspect
	/// threshold.
	Reputation,
	/// Rejected by an external content scanner (ClamAV/Rspamd).
	Scanner,
	/// Rejected because the message was a loop (our own envelope sender on
	/// a received message, e.g. via SRS / an alias chain).
	Loop,
	/// Rejected at `MAIL FROM` because the unauthenticated client tripped
	/// the configured per-IP or per-sender rate limit. The reply is `450`,
	/// so the rejection is temporary and the peer is expected to retry.
	RateLimit,
	/// Rejected because the message has more header fields than a Sieve
	/// filter reads (`554 5.6.0`).
	HeaderFields,
}

impl RejectReason {
	pub(super) fn label(self) -> &'static str {
		match self {
			RejectReason::Dnsbl => "dnsbl",
			RejectReason::Spf => "spf",
			RejectReason::Dmarc => "dmarc",
			RejectReason::Reputation => "reputation",
			RejectReason::Scanner => "scanner",
			RejectReason::Loop => "loop",
			RejectReason::RateLimit => "rate_limit",
			RejectReason::HeaderFields => "header_fields",
		}
	}
}

pub(super) const REASONS: [RejectReason; 8] = [
	RejectReason::Dnsbl,
	RejectReason::Spf,
	RejectReason::Dmarc,
	RejectReason::Reputation,
	RejectReason::Scanner,
	RejectReason::Loop,
	RejectReason::RateLimit,
	RejectReason::HeaderFields,
];
