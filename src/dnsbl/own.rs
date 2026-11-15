use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::{Dnsbl, DnsblOutcome};
use crate::spf::DnsLookup;

pub(crate) const STATE_FILE: &str = "own-ip-blocklist.json";
pub(crate) const LOOKUP_TIMEOUT_SECS: u64 = 10;

/// Provider domain to the provider's own delisting or lookup page. Only
/// zones whose page is known for certain are here; every other zone is
/// reported without a link.
const DELIST_PAGES: &[(&str, &str)] = &[
	("spamhaus.org", "https://check.spamhaus.org/listed/"),
	(
		"barracudacentral.org",
		"https://www.barracudacentral.org/lookups",
	),
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub(crate) enum Status {
	NotListed,
	Listed { zone: String },
	Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Check {
	pub(crate) address: IpAddr,
	pub(crate) status: Status,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub(crate) delist_url: Option<String>,
	pub(crate) checked_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Listing {
	pub(crate) address: IpAddr,
	pub(crate) zone: String,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub(crate) delist_url: Option<String>,
	pub(crate) first_seen: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct State {
	#[serde(default)]
	pub(crate) checks: Vec<Check>,
	#[serde(default)]
	pub(crate) listings: Vec<Listing>,
}

impl State {
	pub(crate) fn apply(&mut self, check: Check) -> Option<Listing> {
		let address = check.address;
		match &check.status {
			Status::Listed { zone } => {
				let previous = self.listing(address);
				let first_seen = previous
					.as_ref()
					.filter(|listing| &listing.zone == zone)
					.map_or(check.checked_at, |listing| listing.first_seen);
				let listing = Listing {
					address,
					zone: zone.clone(),
					delist_url: check.delist_url.clone(),
					first_seen,
				};
				// A change of zone for an address that stays listed is the same
				// listing: one zone failing for a round must not alert twice.
				let is_new = previous.is_none();
				self.remove_listing(address);
				self.listings.push(listing.clone());
				self.replace_check(check);
				is_new.then_some(listing)
			}
			Status::NotListed => {
				self.remove_listing(address);
				self.replace_check(check);
				None
			}
			Status::Unknown => {
				self.replace_check(check);
				None
			}
		}
	}

	pub(crate) fn listing(&self, address: IpAddr) -> Option<Listing> {
		self.listings
			.iter()
			.find(|listing| listing.address == address)
			.cloned()
	}

	pub(crate) fn check(&self, address: IpAddr) -> Option<Check> {
		self.checks
			.iter()
			.find(|check| check.address == address)
			.cloned()
	}

	pub(crate) fn retain_addresses(&mut self, addresses: &[IpAddr]) {
		self.checks
			.retain(|check| addresses.contains(&check.address));
		self.listings
			.retain(|listing| addresses.contains(&listing.address));
	}

	fn replace_check(&mut self, check: Check) {
		self.checks
			.retain(|existing| existing.address != check.address);
		self.checks.push(check);
	}

	fn remove_listing(&mut self, address: IpAddr) {
		self.listings.retain(|listing| listing.address != address);
	}
}

pub(crate) fn path(data_dir: &Path) -> PathBuf {
	data_dir.join(STATE_FILE)
}

pub(crate) fn load(data_dir: &Path) -> Result<Option<State>, String> {
	let path = path(data_dir);
	let bytes = match std::fs::read(&path) {
		Ok(bytes) => bytes,
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
		Err(error) => return Err(format!("{}: {error}", path.display())),
	};
	serde_json::from_slice(&bytes)
		.map(Some)
		.map_err(|error| format!("{} does not parse: {error}", path.display()))
}

pub(crate) fn save(data_dir: &Path, state: &State) -> std::io::Result<()> {
	let bytes = serde_json::to_vec_pretty(state).map_err(std::io::Error::other)?;
	crate::storage::write_secret(&path(data_dir), &bytes)
}

/// Look `address` up in every zone, one bounded query per zone. A listing
/// anywhere wins; otherwise any zone that failed or timed out makes the
/// address unknown, never clean.
pub(crate) async fn check_address(
	address: IpAddr,
	zones: &[String],
	dns: &dyn DnsLookup,
	checked_at: u64,
) -> Check {
	let mut status = Status::NotListed;
	for zone in zones {
		let checker = Dnsbl::new([zone.clone()]);
		let outcome = tokio::time::timeout(
			Duration::from_secs(LOOKUP_TIMEOUT_SECS),
			checker.check(address, dns),
		)
		.await;
		match outcome {
			Ok(DnsblOutcome::Listed { zone }) => {
				status = Status::Listed { zone };
				break;
			}
			Ok(DnsblOutcome::NotListed) => {}
			Ok(DnsblOutcome::Unavailable) | Err(_) => status = Status::Unknown,
		}
	}
	let delist_url = match &status {
		Status::Listed { zone } => delist_url(zone).map(str::to_string),
		_ => None,
	};
	Check {
		address,
		status,
		delist_url,
		checked_at,
	}
}

pub(crate) fn delist_url(zone: &str) -> Option<&'static str> {
	let zone = zone.trim_end_matches('.').to_ascii_lowercase();
	DELIST_PAGES
		.iter()
		.find(|(provider, _)| zone == *provider || zone.ends_with(&format!(".{provider}")))
		.map(|(_, url)| *url)
}

#[cfg(test)]
mod tests;
