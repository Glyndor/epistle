//! What a notification names, and who may be told about it.

use crate::api::Principal;

/// The things a dashboard watches. An event names one and nothing else: the
/// client fetches the detail from the endpoint it already uses, which keeps
/// every authorization check where it is today.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum Topic {
	/// A message entered or left the outbound queue.
	Queue,
	/// The per-recipient delivery log moved.
	Deliveries,
	/// A suppression list changed.
	Suppression,
	/// The counters `GET /api/v1/status` reports changed.
	Status,
	/// An account was added, removed or changed.
	Accounts,
	/// A hosted domain was added, removed, switched or changed.
	Domains,
}

impl Topic {
	/// Every topic, in the order a resync names them.
	pub(crate) const ALL: [Topic; 6] = [
		Topic::Queue,
		Topic::Deliveries,
		Topic::Suppression,
		Topic::Status,
		Topic::Accounts,
		Topic::Domains,
	];

	/// The event name on the wire.
	pub(crate) fn name(self) -> &'static str {
		match self {
			Topic::Queue => "queue",
			Topic::Deliveries => "deliveries",
			Topic::Suppression => "suppression",
			Topic::Status => "status",
			Topic::Accounts => "accounts",
			Topic::Domains => "domains",
		}
	}

	/// Whether the data behind the topic is shared by every tenant, so only
	/// an unrestricted credential may be told about it. The routes that
	/// answer these (the queue, the shared suppression list) either refuse a
	/// confined key or need a per-entry filter that costs a read of each
	/// entry; a stream refuses the cost and stays silent for such a key.
	pub(crate) fn shared(self) -> bool {
		matches!(self, Topic::Queue | Topic::Deliveries | Topic::Suppression)
	}
}

/// Who a change concerns. A confined key is told about a change only when
/// it concerns something it reaches, decided the way the routes decide it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Reach {
	/// Server-wide state: unrestricted credentials only.
	Everyone,
	/// Domains and accounts (name and every address, before and after the
	/// change) a change touched.
	Tenants {
		domains: Vec<String>,
		accounts: Vec<(String, Vec<String>)>,
	},
}

impl Reach {
	/// Whether `principal` may be told about a change with this reach on
	/// `topic`.
	pub(super) fn admits(&self, topic: Topic, principal: &Principal) -> bool {
		if principal.is_unrestricted() {
			return true;
		}
		if topic.shared() {
			return false;
		}
		match self {
			Reach::Everyone => false,
			Reach::Tenants { domains, accounts } => {
				domains.iter().any(|domain| principal.admits_domain(domain))
					|| accounts
						.iter()
						.any(|(name, addresses)| principal.admits_account(name, addresses))
			}
		}
	}
}

/// Whether `principal` is told about `topic` when it cannot be known what
/// changed (a resync): everything it could be told about at all.
pub(super) fn visible_at_resync(topic: Topic, principal: &Principal) -> bool {
	principal.is_unrestricted() || !topic.shared()
}
