//! How many outbound conversations run at once.
//!
//! The queue runs up to [`DEFAULT_CONCURRENCY`] conversations side by side
//! (`[queue] concurrency`) and at most [`DEFAULT_PER_DOMAIN_CONCURRENCY`]
//! of them with the exchangers of any one recipient domain
//! (`[queue] per_domain_concurrency`), so a slow destination holds its own
//! slots and no more, and a large receiver is not flooded with
//! connections.
//!
//! A provider judges a sender by its own traffic, not by the recipient
//! domain: fifty domains hosted by one provider are fifty queues towards
//! it. The receiver group (see [`crate::queue::warmup::Group`]) is the queue
//! they share, and `[queue] per_group_concurrency` gives each group a limit
//! of its own.

use serde::Deserialize;
use serde::de::{self, Deserializer, MapAccess, Visitor};

/// Conversations running at once, all destinations together.
pub const DEFAULT_CONCURRENCY: usize = 8;
/// Conversations running at once with one recipient domain.
pub const DEFAULT_PER_DOMAIN_CONCURRENCY: usize = 2;
/// The highest `concurrency` the configuration accepts.
pub const MAX_CONCURRENCY: usize = 1024;
/// The longest wait between two connections to one receiver group, in
/// seconds.
pub const MAX_GROUP_WAIT_SECS: u64 = 3600;
/// The most exchangers of one domain tried in one delivery attempt, the
/// way Postfix's `smtp_mx_address_limit` bounds it: a domain that
/// publishes hundreds of MX records cannot keep a conversation slot busy
/// trying each of them.
pub const MAX_EXCHANGERS: usize = 5;
/// The most addresses of one exchanger tried in one delivery attempt
/// (Postfix tries two by default): a host with dozens of A and AAAA records
/// cannot multiply the time a slot spends connecting.
pub const MAX_ADDRESSES: usize = 2;

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
	/// The most conversations one sender (an account, or the domain of an
	/// unauthenticated reverse path) runs at once: three quarters of the
	/// total, at least one, so one sender queueing thousands of messages to
	/// slow destinations always leaves slots for everyone else.
	pub fn per_sender(&self) -> usize {
		(self.total * 3 / 4).max(1)
	}

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

/// The limit of one receiver group: how many conversations it may have at
/// once, and the minimum wait between two of them.
///
/// The configuration writes it as a number of conversations, or as a table
/// with `concurrency` and `min_wait_secs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupLimit {
	/// Conversations at once with the group.
	pub concurrency: usize,
	/// The minimum wait between two connections to the group, in seconds.
	pub min_wait_secs: u64,
}

impl GroupLimit {
	/// A limit of `concurrency` conversations at once, with no wait between
	/// them.
	pub const fn new(concurrency: usize) -> Self {
		GroupLimit {
			concurrency,
			min_wait_secs: 0,
		}
	}
}

/// The table form of a group limit: the conversations at once and the
/// minimum wait between two of them.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DetailedGroupLimit {
	concurrency: usize,
	#[serde(default)]
	min_wait_secs: u64,
}

impl<'de> Deserialize<'de> for GroupLimit {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		struct LimitVisitor;

		impl<'de> Visitor<'de> for LimitVisitor {
			type Value = GroupLimit;

			fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
				formatter.write_str(
					"a number of conversations or a table with `concurrency` and `min_wait_secs`",
				)
			}

			fn visit_u64<E: de::Error>(self, value: u64) -> Result<GroupLimit, E> {
				Ok(GroupLimit::new(
					usize::try_from(value).unwrap_or(usize::MAX),
				))
			}

			fn visit_i64<E: de::Error>(self, value: i64) -> Result<GroupLimit, E> {
				if value < 0 {
					return Err(E::custom("the number of conversations cannot be negative"));
				}
				self.visit_u64(value as u64)
			}

			fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<GroupLimit, A::Error> {
				let detailed =
					DetailedGroupLimit::deserialize(de::value::MapAccessDeserializer::new(map))?;
				Ok(GroupLimit {
					concurrency: detailed.concurrency,
					min_wait_secs: detailed.min_wait_secs,
				})
			}
		}

		deserializer.deserialize_any(LimitVisitor)
	}
}

/// The most `deferred` records the delivery log keeps for one recipient
/// of one message. A deferral is recorded when its reply differs from the
/// one before, and a remote controls the wording of its replies: without
/// a bound, one that varies each reply would add a record on every retry
/// for the days the message stays queued.
pub const MAX_DEFERRALS_LOGGED: u32 = 8;
