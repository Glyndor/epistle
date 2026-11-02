//! Per-account and per-domain limits and preferences: storage quotas,
//! `save_sent` and submission rate limits.

use super::Directory;

impl Directory {
	/// Attach per-account storage quotas (account name → bytes).
	pub fn with_account_quotas(mut self, quotas: impl IntoIterator<Item = (String, u64)>) -> Self {
		self.account_quotas = quotas
			.into_iter()
			.map(|(name, bytes)| (name.to_ascii_lowercase(), bytes))
			.collect();
		self
	}

	/// Attach per-account `save_sent` preferences (account name →
	/// enabled). `Some(true)` and `Some(false)` are both stored; an
	/// account absent from the list keeps the default (`None`).
	pub fn with_save_sent(mut self, entries: impl IntoIterator<Item = (String, bool)>) -> Self {
		self.account_save_sent = entries
			.into_iter()
			.map(|(name, value)| (name.to_ascii_lowercase(), value))
			.collect();
		self
	}

	/// Attach per-domain default storage quotas (domain → bytes).
	pub fn with_domain_quotas(mut self, quotas: impl IntoIterator<Item = (String, u64)>) -> Self {
		self.domain_quotas = quotas
			.into_iter()
			.map(|(domain, bytes)| (domain.to_ascii_lowercase(), bytes))
			.collect();
		self
	}

	/// Attach per-domain submission rate limits (domain → messages/min). The
	/// lookup walks the account's own addresses — the same approach
	/// [`Directory::quota_for`] takes — so the resolved domain is the one the
	/// address actually lives under, not the first one configured.
	pub fn with_domain_submission_limits(
		mut self,
		limits: impl IntoIterator<Item = (String, u32)>,
	) -> Self {
		self.domain_submission_limits = limits
			.into_iter()
			.map(|(domain, per_min)| (domain.to_ascii_lowercase(), per_min))
			.collect();
		self
	}

	/// The storage quota for an account: its own quota, else the quota of a
	/// hosted domain it has an address in, else `None` (use the server default).
	pub fn quota_for(&self, account: &str) -> Option<u64> {
		let account = account.to_ascii_lowercase();
		if let Some(bytes) = self.account_quotas.get(&account) {
			return Some(*bytes);
		}
		if self.domain_quotas.is_empty() {
			return None;
		}
		self.accounts_by_address
			.iter()
			.filter(|(_, name)| name.eq_ignore_ascii_case(&account))
			.filter_map(|(addr, _)| addr.rsplit_once('@').map(|(_, domain)| domain))
			.find_map(|domain| self.domain_quotas.get(domain).copied())
	}

	/// The account-wide `save_sent` preference: `Some(true)`/`Some(false)`
	/// when the account carries an explicit override, `None` when the
	/// preference is absent (treated as "on" by default). Callers pick the
	/// default themselves because the per-request and per-app-password
	/// overrides interact with it; the saver resolves the precedence.
	pub fn save_sent_for(&self, account: &str) -> Option<bool> {
		self.account_save_sent
			.get(&account.to_ascii_lowercase())
			.copied()
	}

	/// Whether the SMTP session that authenticated as `account` via
	/// `app_password` (when the login was a secondary credential rather
	/// than the primary password) should save a copy of every message
	/// to Sent. `Some(false)` on the app password disables the save
	/// unconditionally; `Some(true)` enables it; `None` defers to the
	/// account-wide preference.
	pub fn app_password_save_sent(
		&self,
		account: &str,
		app_password: Option<&str>,
	) -> Option<bool> {
		let account = account.to_ascii_lowercase();
		let passwords = self.app_passwords.get(&account)?;
		let password = app_password?;
		passwords
			.iter()
			.find(|entry| entry.label == password)
			.and_then(|entry| entry.save_sent)
	}

	/// The per-domain submission rate limit (messages/minute) for an
	/// account, derived from the domain of one of the account's own
	/// addresses. `None` when no per-domain limit covers the account; the
	/// caller (the SMTP session) is responsible for falling back to the
	/// server-wide limit, or to no limit at all.
	///
	/// Iterates the account's addresses rather than reading `domains[0]`:
	/// taking the first configured domain would assign every account to
	/// whichever domain happened to be configured first, and drop all of
	/// them the day that domain is removed. The address walk matches the
	/// approach [`Directory::quota_for`] takes for the same reason. An
	/// account with addresses in several limited domains gets the strictest
	/// of their limits, whatever order the addresses are stored in.
	pub fn submission_limit_for(&self, account: &str) -> Option<u32> {
		if self.domain_submission_limits.is_empty() {
			return None;
		}
		self.accounts_by_address
			.iter()
			.filter(|(_, name)| name.eq_ignore_ascii_case(account))
			.filter_map(|(addr, _)| addr.rsplit_once('@').map(|(_, domain)| domain))
			.filter_map(|domain| self.domain_submission_limits.get(domain).copied())
			.min()
	}
}
