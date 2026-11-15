//! The server's own public addresses against the DNS blocklists, read from
//! the state the running server keeps (`dnsbl::own`). A listing or an
//! unknown result is a warning: nothing about sending mail changes.

use std::net::IpAddr;

use super::super::report::{Item, Level};
use crate::config::Config;
use crate::dnsbl::own::{self, Status};

/// One item per configured public address; nothing when the check is off.
pub(super) fn items(config: &Config) -> Vec<Item> {
	items_at(config, unix_now())
}

pub(super) fn items_at(config: &Config, now: u64) -> Vec<Item> {
	if !config.own_ip_blocklist.enabled || config.own_ip_blocklist_zones().is_empty() {
		return Vec::new();
	}
	let addresses: Vec<IpAddr> = config
		.public_ipv4
		.map(IpAddr::V4)
		.into_iter()
		.chain(config.public_ipv6.map(IpAddr::V6))
		.collect();
	if addresses.is_empty() {
		return Vec::new();
	}
	let state = match own::load(&config.data_dir) {
		Ok(state) => state.unwrap_or_default(),
		Err(error) => {
			return vec![Item::new(
				"own IP blocklist",
				Level::Warn,
				format!("the state of the check cannot be read: {error}"),
			)];
		}
	};
	let stale_after = config.own_ip_blocklist.period_secs.saturating_mul(3);
	addresses
		.into_iter()
		.map(|address| item(&state, address, now, stale_after))
		.collect()
}

fn item(state: &own::State, address: IpAddr, now: u64, stale_after: u64) -> Item {
	let name = format!("own IP blocklist {address}");
	let Some(check) = state.check(address) else {
		return Item::new(
			name,
			Level::Ok,
			"not checked yet; the running server checks it periodically",
		);
	};
	let age = now.saturating_sub(check.checked_at);
	let level_for = |level: Level| {
		if age > stale_after && level == Level::Ok {
			Level::Warn
		} else {
			level
		}
	};
	let stale = if age > stale_after {
		format!(" (last checked {age} s ago; is the server running?)")
	} else {
		String::new()
	};
	match check.status {
		Status::NotListed => Item::new(
			name,
			level_for(Level::Ok),
			format!("not listed in any configured blocklist{stale}"),
		),
		Status::Listed { zone } => {
			let link = state
				.listing(address)
				.and_then(|listing| listing.delist_url)
				.map(|url| format!("; delisting: {url}"))
				.unwrap_or_default();
			Item::new(name, Level::Warn, format!("LISTED in {zone}{link}{stale}"))
		}
		Status::Unknown => {
			// The last answer was a failure or a timeout: say what was
			// remembered, because the listing may still stand.
			let remembered = state
				.listing(address)
				.map(|listing| format!("; last known listing: {}", listing.zone))
				.unwrap_or_default();
			Item::new(
				name,
				Level::Warn,
				format!("UNKNOWN: a blocklist lookup failed or timed out{remembered}{stale}"),
			)
		}
	}
}

fn unix_now() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map_or(0, |elapsed| elapsed.as_secs())
}
