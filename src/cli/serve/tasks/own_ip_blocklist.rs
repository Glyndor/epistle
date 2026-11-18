use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::config::Config;
use crate::dnsbl::own::{self, Check, State, Status};
use crate::metrics::Metrics;
use crate::spf::{DnsLookup, SystemDns};

pub(in crate::cli::serve) fn spawn_own_ip_blocklist(config: &Config, metrics: Arc<Metrics>) {
	if !config.own_ip_blocklist.enabled {
		return;
	}
	let zones = config.own_ip_blocklist_zones();
	if zones.is_empty() {
		return;
	}
	let addresses = public_addresses(config);
	if addresses.is_empty() {
		return;
	}
	let resolver = match SystemDns::uncached_from_system() {
		Ok(resolver) => resolver,
		Err(error) => {
			tracing::warn!(%error, "own IP blocklist check cannot start: no system resolver");
			record_unknown(&config.data_dir, &addresses);
			return;
		}
	};
	let data_dir = config.data_dir.clone();
	let period = Duration::from_secs(config.own_ip_blocklist.period_secs);
	tokio::spawn(async move {
		let mut state = load_state(&data_dir);
		state.retain_addresses(&addresses);
		let mut ticker = tokio::time::interval(period);
		ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
		loop {
			ticker.tick().await;
			round(
				&addresses, &zones, &resolver, &mut state, &metrics, &data_dir,
			)
			.await;
		}
	});
}

/// One pass over every address: look it up, remember the answer, count each
/// new listing once and drop the detail of one that is gone.
pub(super) async fn round(
	addresses: &[IpAddr],
	zones: &[String],
	resolver: &dyn DnsLookup,
	state: &mut State,
	metrics: &Metrics,
	data_dir: &std::path::Path,
) {
	let checked_at = unix_now();
	let mut new_listings = Vec::new();
	for address in addresses {
		let check = own::check_address(*address, zones, resolver, checked_at).await;
		match &check.status {
			Status::Unknown => tracing::warn!(
				%address,
				"own IP blocklist lookup failed or timed out; the address is unknown"
			),
			Status::Listed { zone } => tracing::warn!(
				%address,
				%zone,
				"server's own public address is listed in a DNS blocklist"
			),
			Status::NotListed => {}
		}
		if let Some(listing) = state.apply(check) {
			new_listings.push(listing);
		}
	}
	if let Err(error) = own::save(data_dir, state) {
		tracing::warn!(%error, "cannot save the own IP blocklist state");
	}
	for listing in new_listings {
		metrics.own_ip_blocklisted(listing);
	}
	for address in addresses {
		if state.listing(*address).is_none() {
			metrics.clear_own_ip_listing(*address);
		}
	}
}

fn public_addresses(config: &Config) -> Vec<IpAddr> {
	let mut addresses = Vec::with_capacity(2);
	if let Some(address) = config.public_ipv4 {
		addresses.push(IpAddr::V4(address));
	}
	if let Some(address) = config.public_ipv6 {
		addresses.push(IpAddr::V6(address));
	}
	addresses
}

fn load_state(data_dir: &std::path::Path) -> State {
	match own::load(data_dir) {
		Ok(Some(state)) => state,
		Ok(None) => State::default(),
		Err(error) => {
			tracing::warn!(%error, "cannot read the own IP blocklist state; starting with no remembered listing");
			State::default()
		}
	}
}

fn record_unknown(data_dir: &std::path::Path, addresses: &[IpAddr]) {
	let mut state = load_state(data_dir);
	let checked_at = unix_now();
	for address in addresses {
		state.apply(Check {
			address: *address,
			status: Status::Unknown,
			delist_url: None,
			checked_at,
		});
	}
	if let Err(error) = own::save(data_dir, &state) {
		tracing::warn!(%error, "cannot save the own IP blocklist state");
	}
}

fn unix_now() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|elapsed| elapsed.as_secs())
		.unwrap_or(0)
}

#[cfg(test)]
mod tests;
