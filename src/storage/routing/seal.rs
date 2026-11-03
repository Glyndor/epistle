//! ARC sealing and SRS rewriting of forwarded mail.

use super::*;

/// How long an SRS-return address stays valid (RFC-less convention).
const SRS_MAX_AGE_DAYS: u64 = 14;

impl SplitDelivery {
	/// ARC headers to prepend to a forwarded copy of `data`, or `None` when no
	/// sealer is configured, when our domain already sealed the latest instance
	/// (skip the duplicate set), or when the message cannot be sealed.
	///
	/// Forward sealing stays synchronous: the chain-validation status comes from
	/// the pure [`crate::arc::chain::chain_status`] (the prior chain's recorded
	/// `cv`), never the async, DNS-backed `arc::validate::validate`. A message
	/// with no prior chain — the common case — yields `cv=none` with no lookup;
	/// a present chain reuses its own recorded status structurally rather than
	/// re-running cryptographic verification in this sync delivery path.
	pub(super) fn arc_seal(&self, data: &[u8]) -> Option<String> {
		let (sealer, our_domain) = self.arc.as_ref()?;
		let prior = crate::arc::chain::extract(data)
			.ok()
			.flatten()
			.unwrap_or_default();
		// No double seal: if our domain already authored the latest instance
		// (e.g. inbound mail we sealed at accept), do not add a second set.
		if let Some(top) = prior.last()
			&& crate::arc::chain::tag(&top.seal, "d")
				.is_some_and(|d| d.eq_ignore_ascii_case(our_domain))
		{
			return None;
		}
		// cv reflects the prior chain: none when fresh, else its recorded status
		// (a structurally broken chain extracts to empty, so seals as a fresh
		// chain — never an invalid set). This keeps sealing sync (no DNS).
		let cv = if prior.is_empty() {
			crate::arc::chain::ChainValidation::None
		} else {
			crate::arc::chain::chain_status(&prior)
				.unwrap_or(crate::arc::chain::ChainValidation::Fail)
		};
		// Reuse this message's Authentication-Results as our hop's summary, or a
		// minimal "none" when the message carries none.
		let auth_results =
			header_of(data, "authentication-results").unwrap_or_else(|| "none".to_string());
		sealer.seal(data, &auth_results, &prior, cv)
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
	/// sender it should be forwarded back to; otherwise `None`.
	pub(super) fn srs_return(&self, recipient: &str) -> Option<String> {
		let (srs, our_domain) = self.srs.as_ref()?;
		let (local, domain) = recipient.rsplit_once('@')?;
		if !domain.eq_ignore_ascii_case(our_domain) {
			return None;
		}
		let now_days = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.map(|d| d.as_secs() / 86_400)
			.unwrap_or(0);
		let (orig_local, orig_domain) = srs.reverse(local, now_days, SRS_MAX_AGE_DAYS)?;
		Some(format!("{orig_local}@{orig_domain}"))
	}
}
