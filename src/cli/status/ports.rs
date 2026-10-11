//! The `ports` check: every enabled listener answers with its greeting.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use super::report::{AreaReport, Item, Level};
use super::{Ctx, NET_TIMEOUT};
use crate::cli::listener_greeting::{expect_greeting, greeting_for};

/// Probe each configured listener. A listener bound to a wildcard address is
/// reached on loopback; one bound to a specific address is reached there,
/// since loopback would not answer.
pub(super) async fn check(ctx: &Ctx) -> AreaReport {
	let config = match ctx.loaded() {
		Ok(config) => config,
		Err(report) => return report,
	};
	if config.listeners.is_empty() {
		return AreaReport::single(Level::Warn, "no listeners are enabled");
	}
	let mut set = tokio::task::JoinSet::new();
	for (index, listener) in config.listeners.iter().enumerate() {
		let target = probe_address(listener.socket_addr());
		let kind = listener.kind;
		set.spawn(async move {
			let result = expect_greeting(target, greeting_for(kind), NET_TIMEOUT).await;
			(index, format!("{} {target}", kind.as_str()), result)
		});
	}
	let mut found = Vec::new();
	while let Some(joined) = set.join_next().await {
		match joined {
			Ok(entry) => found.push(entry),
			Err(error) => tracing::error!(%error, "listener probe task failed"),
		}
	}
	found.sort_by_key(|(index, _, _)| *index);
	let items: Vec<Item> = found
		.into_iter()
		.map(|(_, name, result)| match result {
			Ok(detail) => Item::new(name, Level::Ok, detail),
			Err(error) => Item::new(name, Level::Fail, error),
		})
		.collect();
	let answering = items.iter().filter(|item| item.status == Level::Ok).count();
	let summary = format!("{answering} of {} listeners answer", config.listeners.len());
	AreaReport::from_items(items, summary)
}

/// Where to connect for a listener bound to `bound`.
fn probe_address(bound: SocketAddr) -> SocketAddr {
	let ip = match bound.ip() {
		IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
		IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
		other => other,
	};
	SocketAddr::new(ip, bound.port())
}

#[cfg(test)]
#[path = "ports_tests.rs"]
mod tests;
