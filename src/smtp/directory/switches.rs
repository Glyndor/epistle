//! The per-account switches for sending and receiving, as the directory
//! holds them.

use super::Directory;

impl Directory {
	/// Attach the accounts whose sending is off and the accounts whose
	/// receiving is off (names, lowercased to match the rest of the
	/// directory). An account in neither list does both, which is the default.
	pub fn with_switches(
		mut self,
		send_off: impl IntoIterator<Item = String>,
		receive_off: impl IntoIterator<Item = String>,
	) -> Self {
		self.send_off = send_off
			.into_iter()
			.map(|name| name.to_ascii_lowercase())
			.collect();
		self.receive_off = receive_off
			.into_iter()
			.map(|name| name.to_ascii_lowercase())
			.collect();
		self
	}

	/// Attach the hosted domains that only receive (lowercased to match the
	/// rest of the directory). Nobody may send as an address in them.
	pub fn with_send_off_domains(mut self, domains: impl IntoIterator<Item = String>) -> Self {
		self.send_off_domains = domains
			.into_iter()
			.map(|domain| domain.to_ascii_lowercase())
			.collect();
		self
	}

	/// Whether nobody may send as an address in `domain`: it is hosted as
	/// `receive-only`, or is an alias of a domain that is.
	pub(super) fn domain_send_off(&self, domain: &str) -> bool {
		let domain = domain.to_ascii_lowercase();
		let target = self
			.domain_aliases
			.get(&domain)
			.map_or(domain.as_str(), String::as_str);
		self.send_off_domains.contains(&domain) || self.send_off_domains.contains(target)
	}

	/// Whether the mail that reached `address` (a recipient address, as the
	/// delivery layer holds it) may make the server send something on its
	/// own, such as a forward, a Sieve redirect or a vacation reply: the
	/// domain of the address must be one anybody may send as.
	pub fn address_may_send(&self, address: &str) -> bool {
		address
			.rsplit_once('@')
			.is_none_or(|(_, domain)| !self.domain_send_off(domain))
	}

	/// Whether `account` may send mail. Signing in and reading are not part of
	/// it: those follow `disabled` and the protocol allowlist.
	pub fn can_send(&self, account: &str) -> bool {
		!self.send_off.contains(&account.to_ascii_lowercase())
	}

	/// Whether mail addressed to `account` is accepted.
	pub fn receives(&self, account: &str) -> bool {
		!self.receive_off.contains(&account.to_ascii_lowercase())
	}
}
