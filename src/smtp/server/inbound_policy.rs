//! The inbound decisions an operator can set: which peers are the
//! operator's own relays, how a full mailbox is refused, how greylisting
//! groups clients and how the sender-domain reputation is judged. Built
//! once from the configuration and handed to every listener.

use std::net::IpAddr;

use crate::antispam::greylist::Mask;
use crate::cidr::Cidr;
use crate::config::{Config, MailboxFull};

/// The settings of [`Server::with_inbound_policy`](super::Server).
#[derive(Clone, Debug)]
pub struct InboundPolicy {
	trusted: Vec<Cidr>,
	pub(super) mailbox_full: MailboxFull,
	pub(super) greylist_mask: Mask,
	pub(super) reputation_min_observations: i64,
}

impl Default for InboundPolicy {
	/// What the server did before these were settings.
	fn default() -> Self {
		Self {
			trusted: Vec::new(),
			mailbox_full: MailboxFull::Temporary,
			greylist_mask: Mask::default(),
			reputation_min_observations: 3,
		}
	}
}

impl InboundPolicy {
	/// The policy `config` sets.
	pub fn from_config(config: &Config) -> Self {
		Self {
			trusted: config.smtp.trusted_networks.clone(),
			mailbox_full: config.smtp.mailbox_full,
			greylist_mask: Mask {
				v4: config.antispam.greylist_mask_v4,
				v6: config.antispam.greylist_mask_v6,
			},
			reputation_min_observations: i64::from(config.antispam.reputation_min_observations),
		}
	}

	/// The networks of the operator's own relays.
	pub(super) fn trusted_networks(&self) -> &[Cidr] {
		&self.trusted
	}

	/// Whether `peer` is one of the operator's own relays.
	pub(super) fn trusts(&self, peer: Option<IpAddr>) -> bool {
		peer.is_some_and(|ip| self.trusted.iter().any(|network| network.contains(ip)))
	}
}
