//! ARC sealing and SRS rewriting of forwarded mail.

use super::*;

/// How long an SRS-return address stays valid (RFC-less convention).
const SRS_MAX_AGE_DAYS: u64 = 14;

impl SplitDelivery {
	/// ARC headers to prepend to a forwarded copy of `data`, or `None` when no
	/// sealer is configured or the message cannot be sealed.
	///
	/// Forward sealing stays synchronous and never looks DNS up, so it cannot
	/// tell whether a chain it did not make still validates. It seals only a
	/// message with no ARC headers (`cv=none`, the first instance). A message
	/// that already carries a chain, ours from the accept hop included, or
	/// headers that do not form one, is forwarded as it is: a later instance
	/// has to carry `cv=pass` (RFC 8617 section 5.2) and that claim needs a
	/// validation.
	pub(super) fn arc_seal(&self, data: &[u8]) -> Option<String> {
		let (sealer, _) = self.arc.as_ref()?;
		if !matches!(crate::arc::chain::extract(data), Ok(None)) {
			return None;
		}
		// Reuse this message's Authentication-Results as our hop's summary, or a
		// minimal "none" when the message carries none.
		let auth_results =
			header_of(data, "authentication-results").unwrap_or_else(|| "none".to_string());
		sealer.seal(
			data,
			&auth_results,
			&[],
			crate::arc::chain::ChainValidation::None,
		)
	}

	/// The envelope sender to use for mail that an account of
	/// `forwarding_domain` forwards: an SRS rewrite of the original sender
	/// signed with that domain's secret when SRS is enabled, else the original.
	pub(super) fn forward_sender(&self, original: &str, forwarding_domain: &str) -> String {
		if original.is_empty() {
			return String::new();
		}
		let Some((srs, our_domain)) = &self.srs else {
			return original.to_string();
		};
		let Some((local, domain)) = original.rsplit_once('@') else {
			return original.to_string();
		};
		let now_days = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.map(|d| d.as_secs() / 86_400)
			.unwrap_or(0);
		srs.forward(forwarding_domain, (local, domain), our_domain, now_days)
			.unwrap_or_else(|| original.to_string())
	}

	/// If `recipient` is a valid SRS-return address at our domain, the original
	/// sender it should be forwarded back to and the hosted domain whose
	/// secret verified the address (`None` for the older shape); otherwise
	/// `None`.
	pub(super) fn srs_return(&self, recipient: &str) -> Option<(String, Option<String>)> {
		let (srs, our_domain) = self.srs.as_ref()?;
		let (local, domain) = recipient.rsplit_once('@')?;
		if !domain.eq_ignore_ascii_case(our_domain) {
			return None;
		}
		let now_days = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.map(|d| d.as_secs() / 86_400)
			.unwrap_or(0);
		let ((orig_local, orig_domain), hosted) =
			srs.reverse_owned(local, now_days, SRS_MAX_AGE_DAYS)?;
		Some((format!("{orig_local}@{orig_domain}"), hosted))
	}
}
