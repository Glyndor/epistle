//! How many outbound conversations run at once.
//!
//! The queue runs up to [`DEFAULT_CONCURRENCY`] conversations side by side
//! (`[queue] concurrency`) and at most [`DEFAULT_PER_DOMAIN_CONCURRENCY`]
//! of them with the exchangers of any one recipient domain
//! (`[queue] per_domain_concurrency`), so a slow destination holds its own
//! slots and no more, and a large receiver is not flooded with
//! connections.

/// Conversations running at once, all destinations together.
pub const DEFAULT_CONCURRENCY: usize = 8;
/// Conversations running at once with one recipient domain.
pub const DEFAULT_PER_DOMAIN_CONCURRENCY: usize = 2;
/// The highest `concurrency` the configuration accepts.
pub const MAX_CONCURRENCY: usize = 1024;
/// The most exchangers of one domain tried in one delivery attempt, the
/// way Postfix's `smtp_mx_address_limit` bounds it: a domain that
/// publishes hundreds of MX records cannot keep a conversation slot busy
/// trying each of them.
pub const MAX_EXCHANGERS: usize = 5;

/// The caps the scheduler works within.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
	/// Conversations at once in total.
	pub total: usize,
	/// Conversations at once per recipient domain.
	pub per_domain: usize,
}

impl Default for Limits {
	fn default() -> Self {
		Limits {
			total: DEFAULT_CONCURRENCY,
			per_domain: DEFAULT_PER_DOMAIN_CONCURRENCY,
		}
	}
}

impl Limits {
	/// The caps from configured values; zero keeps the default.
	pub fn new(total: usize, per_domain: usize) -> Self {
		let defaults = Limits::default();
		Limits {
			total: if total == 0 { defaults.total } else { total },
			per_domain: if per_domain == 0 {
				defaults.per_domain
			} else {
				per_domain
			},
		}
	}
}
