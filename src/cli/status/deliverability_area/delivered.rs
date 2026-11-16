//! Which receiver groups the server has delivered mail to, read from the
//! delivery log it keeps. A sender panel is only worth a reminder when its
//! provider is among them.

use std::collections::BTreeSet;
use std::path::Path;

use crate::config::Portal;
use crate::queue::destination::Destination;
use crate::queue::warmup::Group;
use crate::storage::DeliveryLog;

/// The receiver group whose provider runs `portal`.
pub(super) const fn group_of(portal: Portal) -> Group {
	match portal {
		Portal::Postmaster => Group::Gmail,
		Portal::Snds | Portal::Jmrp => Group::Outlook,
		Portal::YahooCfl => Group::Yahoo,
		Portal::Apple => Group::Icloud,
	}
}

/// The groups of the exchangers that answered a message sent from this
/// address, over every day the log keeps. What a `[[transport]]` smarthost
/// answered is left out: that mail leaves from the smarthost's address, so
/// the provider has not seen ours.
pub(super) fn groups(
	data_dir: &Path,
	retention_days: u64,
	relays: &[String],
) -> std::io::Result<BTreeSet<Group>> {
	let relays: BTreeSet<String> = relays
		.iter()
		.map(|host| Destination::exchanger(host).as_str().to_string())
		.collect();
	let mut found = BTreeSet::new();
	DeliveryLog::open(data_dir, retention_days).list(None, |record| {
		if let Some(host) = record.remote.as_deref() {
			let host = Destination::exchanger(host);
			if !relays.contains(host.as_str()) {
				found.insert(Group::of_exchanger(host.as_str()));
			}
		}
		false
	})?;
	Ok(found)
}
