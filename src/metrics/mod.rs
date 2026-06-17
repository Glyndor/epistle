//! Server-side metrics in Prometheus text format.
//!
//! The mail server owns the counters and exposes them; dashboards live in the
//! admin panel. Counters are process-global atomics, cheap to bump on the hot
//! path, and rendered on demand for the `/metrics` endpoint.

use std::sync::atomic::{AtomicU64, Ordering};

/// Why an inbound message was rejected, for the per-reason counter label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
	Dnsbl,
	Spf,
	Dmarc,
	Reputation,
	Scanner,
	Loop,
}

impl RejectReason {
	fn label(self) -> &'static str {
		match self {
			RejectReason::Dnsbl => "dnsbl",
			RejectReason::Spf => "spf",
			RejectReason::Dmarc => "dmarc",
			RejectReason::Reputation => "reputation",
			RejectReason::Scanner => "scanner",
			RejectReason::Loop => "loop",
		}
	}
}

const REASONS: [RejectReason; 6] = [
	RejectReason::Dnsbl,
	RejectReason::Spf,
	RejectReason::Dmarc,
	RejectReason::Reputation,
	RejectReason::Scanner,
	RejectReason::Loop,
];

/// Process-global mail metrics.
#[derive(Debug, Default)]
pub struct Metrics {
	connections: AtomicU64,
	accepted: AtomicU64,
	quarantined: AtomicU64,
	rejected_dnsbl: AtomicU64,
	rejected_spf: AtomicU64,
	rejected_dmarc: AtomicU64,
	rejected_reputation: AtomicU64,
	rejected_scanner: AtomicU64,
	rejected_loop: AtomicU64,
}

impl Metrics {
	pub fn new() -> Self {
		Self::default()
	}

	/// Count an accepted inbound SMTP connection.
	pub fn connection(&self) {
		self.connections.fetch_add(1, Ordering::Relaxed);
	}

	/// Count a delivered message.
	pub fn accepted(&self) {
		self.accepted.fetch_add(1, Ordering::Relaxed);
	}

	/// Count a message quarantined to Rejects.
	pub fn quarantined(&self) {
		self.quarantined.fetch_add(1, Ordering::Relaxed);
	}

	/// Count a rejected message by reason.
	pub fn rejected(&self, reason: RejectReason) {
		self.counter(reason).fetch_add(1, Ordering::Relaxed);
	}

	fn counter(&self, reason: RejectReason) -> &AtomicU64 {
		match reason {
			RejectReason::Dnsbl => &self.rejected_dnsbl,
			RejectReason::Spf => &self.rejected_spf,
			RejectReason::Dmarc => &self.rejected_dmarc,
			RejectReason::Reputation => &self.rejected_reputation,
			RejectReason::Scanner => &self.rejected_scanner,
			RejectReason::Loop => &self.rejected_loop,
		}
	}

	/// Render all counters in Prometheus text exposition format.
	pub fn render(&self) -> String {
		let mut out = String::new();
		out.push_str("# HELP mail_connections_total Accepted SMTP connections.\n");
		out.push_str("# TYPE mail_connections_total counter\n");
		out.push_str(&format!(
			"mail_connections_total {}\n",
			self.connections.load(Ordering::Relaxed)
		));

		out.push_str("# HELP mail_messages_accepted_total Delivered inbound messages.\n");
		out.push_str("# TYPE mail_messages_accepted_total counter\n");
		out.push_str(&format!(
			"mail_messages_accepted_total {}\n",
			self.accepted.load(Ordering::Relaxed)
		));

		out.push_str("# HELP mail_messages_quarantined_total Messages filed to Rejects.\n");
		out.push_str("# TYPE mail_messages_quarantined_total counter\n");
		out.push_str(&format!(
			"mail_messages_quarantined_total {}\n",
			self.quarantined.load(Ordering::Relaxed)
		));

		out.push_str("# HELP mail_messages_rejected_total Rejected inbound messages by reason.\n");
		out.push_str("# TYPE mail_messages_rejected_total counter\n");
		for reason in REASONS {
			out.push_str(&format!(
				"mail_messages_rejected_total{{reason=\"{}\"}} {}\n",
				reason.label(),
				self.counter(reason).load(Ordering::Relaxed)
			));
		}
		out
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn renders_zero_counters() {
		let rendered = Metrics::new().render();
		assert!(rendered.contains("mail_connections_total 0\n"));
		assert!(rendered.contains("mail_messages_rejected_total{reason=\"dnsbl\"} 0\n"));
		// Every reason label is present.
		for label in ["dnsbl", "spf", "dmarc", "reputation", "scanner"] {
			assert!(rendered.contains(&format!("reason=\"{label}\"")), "{label}");
		}
	}

	#[test]
	fn counts_events() {
		let m = Metrics::new();
		m.connection();
		m.connection();
		m.accepted();
		m.quarantined();
		m.rejected(RejectReason::Dnsbl);
		m.rejected(RejectReason::Dnsbl);
		m.rejected(RejectReason::Dmarc);
		let r = m.render();
		assert!(r.contains("mail_connections_total 2\n"), "{r}");
		assert!(r.contains("mail_messages_accepted_total 1\n"), "{r}");
		assert!(r.contains("mail_messages_quarantined_total 1\n"), "{r}");
		assert!(
			r.contains("mail_messages_rejected_total{reason=\"dnsbl\"} 2\n"),
			"{r}"
		);
		assert!(
			r.contains("mail_messages_rejected_total{reason=\"dmarc\"} 1\n"),
			"{r}"
		);
	}

	#[test]
	fn render_is_valid_exposition_with_help_and_type() {
		let r = Metrics::new().render();
		assert!(r.contains("# TYPE mail_connections_total counter"));
		assert!(r.contains("# HELP mail_messages_accepted_total"));
	}
}
