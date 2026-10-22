//! Resolve once and validate the entire answer before any clock connection.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use hickory_resolver::config::{LookupIpStrategy, ProtocolConfig};
use tokio::time::timeout_at;

use super::adapter::ProbeError;

const DNS_DEADLINE: Duration = Duration::from_millis(500);

pub(super) fn validate_host(
	host: &str,
	port: u16,
	expected_port: u16,
	allow_private: bool,
) -> Result<(), String> {
	if port == 0 || (!allow_private && port != expected_port) {
		return Err("clock destination port is not allowed".into());
	}
	if host.contains('%') {
		return Err("clock destination IPv6 zone identifiers are not supported; use a destination without a zone".into());
	}
	let name = host.trim_end_matches('.').to_ascii_lowercase();
	if !allow_private && (name == "localhost" || name.ends_with(".localhost")) {
		return Err("clock destination is local".into());
	}
	if let Ok(ip) = host.parse() {
		validate_ip(ip, allow_private)?;
	}
	Ok(())
}

fn validate_ip(ip: IpAddr, allow_private: bool) -> Result<(), String> {
	let ip = match ip {
		IpAddr::V6(ip) => {
			let segments = ip.segments();
			let embedded = ip.to_ipv4().or_else(|| match segments {
				[0x64, 0xff9b, 0, 0, 0, 0, a, b] | [0x2002, a, b, ..] => {
					Some(Ipv4Addr::from(((a as u32) << 16) | b as u32))
				}
				_ => None,
			});
			embedded.map(IpAddr::V4).unwrap_or(IpAddr::V6(ip))
		}
		ip => ip,
	};
	let forbidden = ip.is_multicast()
		|| ip.is_unspecified()
		|| matches!(ip, IpAddr::V4(ip) if ip.is_broadcast());
	let non_global = match ip {
		IpAddr::V4(ip) => crate::config::non_global_ipv4_reason(ip),
		IpAddr::V6(ip) => crate::config::non_global_ipv6_reason(ip),
	};
	if forbidden || (!allow_private && non_global.is_some()) {
		return Err("clock destination address is not allowed".into());
	}
	Ok(())
}

pub(super) async fn resolve(
	host: &str,
	port: u16,
	expected_port: u16,
	allow_private: bool,
	stop: Instant,
) -> Result<SocketAddr, ProbeError> {
	resolve_with(host, port, expected_port, allow_private, stop, async {
		if let Ok(ip) = host.parse::<IpAddr>() {
			return Ok(vec![ip]);
		}
		let (mut config, _) = hickory_resolver::system_conf::read_system_conf().map_err(dial)?;
		// Match the existing system resolver's TCP-only workaround for
		// truncated replies from the local systemd-resolved stub.
		for server in &mut config.name_servers {
			server
				.connections
				.retain(|connection| matches!(connection.protocol, ProtocolConfig::Tcp));
		}
		let mut builder = hickory_resolver::TokioResolver::builder_with_config(
			config,
			hickory_resolver::net::runtime::TokioRuntimeProvider::default(),
		);
		builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
		builder.options_mut().timeout = DNS_DEADLINE;
		builder.options_mut().attempts = 1;
		let resolver = builder.build().map_err(dial)?;
		let answer = resolver.lookup_ip(host).await.map_err(dial)?;
		Ok(answer.iter().collect())
	})
	.await
}

async fn resolve_with(
	host: &str,
	port: u16,
	expected_port: u16,
	allow_private: bool,
	stop: Instant,
	lookup: impl Future<Output = Result<Vec<IpAddr>, ProbeError>>,
) -> Result<SocketAddr, ProbeError> {
	validate_host(host, port, expected_port, allow_private).map_err(ProbeError::Dial)?;
	let dns_stop = stop.min(Instant::now() + DNS_DEADLINE);
	let addresses = timeout_at(dns_stop.into(), lookup)
		.await
		.map_err(|_| ProbeError::Timeout)??;
	for ip in &addresses {
		validate_ip(*ip, allow_private).map_err(ProbeError::Dial)?;
	}
	addresses
		.first()
		.copied()
		.map(|ip| SocketAddr::new(ip, port))
		.ok_or_else(|| ProbeError::Dial("clock destination has no addresses".into()))
}

pub(super) fn bind_address(remote: SocketAddr) -> SocketAddr {
	SocketAddr::new(
		if remote.is_ipv4() {
			IpAddr::V4(Ipv4Addr::UNSPECIFIED)
		} else {
			IpAddr::V6(Ipv6Addr::UNSPECIFIED)
		},
		0,
	)
}

fn dial(error: impl std::fmt::Display) -> ProbeError {
	ProbeError::Dial(error.to_string())
}

#[cfg(test)]
#[path = "tests/endpoint_tests.rs"]
mod tests;
