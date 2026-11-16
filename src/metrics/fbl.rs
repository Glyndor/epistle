//! Spam complaints read from feedback-loop reports (RFC 5965), counted in
//! total for the alert engine and per sending account and traffic class for
//! the operator.

use std::sync::atomic::Ordering;

use super::Metrics;

/// Most account and class pairs kept apart. The pairs come from complaints
/// the server verified, so the number of accounts bounds them already; the
/// cap is the second line, so a lookalike flood cannot grow the map.
const MAX_KEYS: usize = 4096;

impl Metrics {
	/// Count one complaint about a message `account` sent in `class`.
	pub fn fbl_complaint(&self, account: &str, class: &str) {
		self.fbl_complaints.fetch_add(1, Ordering::Relaxed);
		let mut by_key = self
			.fbl_by_key
			.lock()
			.unwrap_or_else(|poisoned| poisoned.into_inner());
		let key = (account.to_string(), class.to_string());
		if by_key.contains_key(&key) || by_key.len() < MAX_KEYS {
			*by_key.entry(key).or_insert(0) += 1;
		}
	}

	/// The complaints counted for `account` in `class`.
	pub fn fbl_complaints_for(&self, account: &str, class: &str) -> u64 {
		self.fbl_by_key
			.lock()
			.unwrap_or_else(|poisoned| poisoned.into_inner())
			.get(&(account.to_string(), class.to_string()))
			.copied()
			.unwrap_or(0)
	}

	/// Add the per account and class series to the Prometheus text.
	pub(super) fn render_fbl(&self, out: &mut String) {
		let by_key = self
			.fbl_by_key
			.lock()
			.unwrap_or_else(|poisoned| poisoned.into_inner());
		out.push_str(
			"# HELP mail_fbl_complaints_total Spam complaints read from feedback-loop reports.\n",
		);
		out.push_str("# TYPE mail_fbl_complaints_total counter\n");
		out.push_str(&format!(
			"mail_fbl_complaints_total {}\n",
			self.fbl_complaints.load(Ordering::Relaxed)
		));
		out.push_str(
			"# HELP mail_fbl_complaints_by_sender_total Spam complaints by sending account and class.\n",
		);
		out.push_str("# TYPE mail_fbl_complaints_by_sender_total counter\n");
		for ((account, class), count) in by_key.iter() {
			out.push_str(&format!(
				"mail_fbl_complaints_by_sender_total{{account=\"{}\",class=\"{}\"}} {count}\n",
				escape(account),
				escape(class)
			));
		}
	}
}

/// A label value in the Prometheus text format: backslash, quote and line
/// feed escaped.
fn escape(value: &str) -> String {
	value
		.replace('\\', "\\\\")
		.replace('"', "\\\"")
		.replace('\n', "\\n")
}
