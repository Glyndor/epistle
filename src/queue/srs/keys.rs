//! The secrets SRS signs with: one per hosted domain, and the server-wide
//! one an installation had before domains had their own.

use std::collections::HashMap;

use super::{Srs, split_hosted};

/// What one hosted domain signs with, and the secret it signed with before
/// its last rotation. The previous secret only verifies: an address made
/// just before the rotation is still good for its remaining lifetime.
struct DomainKeys {
	current: Srs,
	previous: Option<Srs>,
}

/// Every SRS secret the server holds.
///
/// A message forwarded for a domain with its own secret gets an address
/// signed with that secret and naming the domain (`SRS0.<domain>=...`). A
/// domain without one, or an installation with only the server-wide secret,
/// gets the address it always got (`SRS0=...`). The server-wide secret
/// keeps verifying that older shape for as long as it stays configured, so a
/// bounce for a message forwarded before the split is still returned.
#[derive(Default)]
pub struct SrsKeys {
	global: Option<Srs>,
	domains: HashMap<String, DomainKeys>,
}

impl SrsKeys {
	/// Only the server-wide secret: the installation as it was.
	pub fn global_only(global: Srs) -> Self {
		SrsKeys {
			global: Some(global),
			domains: HashMap::new(),
		}
	}

	/// Set the server-wide secret, the one for the older address shape.
	pub fn with_global(mut self, global: Srs) -> Self {
		self.global = Some(global);
		self
	}

	/// Give `domain` its own secret and, optionally, the one it replaced.
	pub fn with_domain(mut self, domain: &str, current: Srs, previous: Option<Srs>) -> Self {
		self.domains.insert(
			domain.to_ascii_lowercase(),
			DomainKeys { current, previous },
		);
		self
	}

	/// The envelope sender for mail that `forwarding_domain` forwards:
	/// `None` when neither the domain nor the server has a secret.
	pub fn forward(
		&self,
		forwarding_domain: &str,
		original: (&str, &str),
		our_domain: &str,
		now_days: u64,
	) -> Option<String> {
		let key = forwarding_domain.to_ascii_lowercase();
		if let Some(keys) = self.domains.get(&key) {
			return Some(
				keys.current
					.forward_for(&key, original, our_domain, now_days),
			);
		}
		let (local, domain) = original;
		Some(
			self.global
				.as_ref()?
				.forward(local, domain, our_domain, now_days),
		)
	}

	/// The original `(local, domain)` an SRS local-part returns to. An
	/// address that names a hosted domain verifies with that domain's
	/// secret, then with the one it replaced, and with nothing else: no
	/// other domain's secret and not the server-wide one. An address that
	/// names none verifies with the server-wide secret alone.
	pub fn reverse(
		&self,
		srs_local: &str,
		now_days: u64,
		max_age_days: u64,
	) -> Option<(String, String)> {
		self.reverse_owned(srs_local, now_days, max_age_days)
			.map(|(original, _)| original)
	}

	/// [`reverse`](Self::reverse), also naming the hosted domain whose secret
	/// verified the address (lowercase), or `None` for the older shape. The
	/// domain is what the HMAC proved, not what the address claims.
	pub fn reverse_owned(
		&self,
		srs_local: &str,
		now_days: u64,
		max_age_days: u64,
	) -> Option<((String, String), Option<String>)> {
		let Some((hosted, _)) = split_hosted(srs_local) else {
			let original = self
				.global
				.as_ref()?
				.reverse(srs_local, now_days, max_age_days)?;
			return Some((original, None));
		};
		let name = hosted.to_ascii_lowercase();
		let keys = self.domains.get(&name)?;
		std::iter::once(&keys.current)
			.chain(keys.previous.as_ref())
			.find_map(|srs| srs.reverse_for(hosted, srs_local, now_days, max_age_days))
			.map(|original| (original, Some(name)))
	}
}
