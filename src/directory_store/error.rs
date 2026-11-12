//! The error type of the account store.

/// Errors from the account store.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
	/// The supplied account data is invalid: malformed address, missing
	/// addresses, an address outside the configured domains, a bad account
	/// name, or a malformed `accounts.toml`. The string carries the
	/// underlying reason.
	#[error("invalid account: {0}")]
	Invalid(String),
	/// An account or address with this name already exists in the store.
	/// Carries the conflicting name or address.
	#[error("account {0} already exists")]
	Duplicate(String),
	/// No dynamic account with the requested name. Carries the missing name.
	#[error("no such dynamic account: {0}")]
	NotFound(String),
	/// The per-account cap on masked addresses would be exceeded. Carries
	/// the configured `max` so the API can render the limit to the operator.
	#[error("masked-address limit reached: {max}")]
	LimitReached {
		/// The configured cap.
		max: usize,
	},
	/// Reading or writing the `accounts.toml` / `app_passwords.toml` /
	/// `masked.json` sidecar files failed. The wrapped `std::io::Error`
	/// carries the cause.
	#[error("storage failure: {0}")]
	Io(#[from] std::io::Error),
	/// The per-account Bayesian purge could not be completed. The
	/// dynamic-account row is left on disk so a retry can drop the
	/// corpus rows and finish the removal; this prevents a recreated
	/// account from inheriting the previous user's training.
	#[error("bayes purge failed for {account}: {source}")]
	BayesPurge {
		/// The account whose per-scope rows could not be dropped.
		account: String,
		/// The underlying `sqlx::Error` returned by the corpus purge.
		source: sqlx::Error,
	},
}
