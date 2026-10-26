//! Resolve once and validate the entire answer before any clock connection.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use hickory_resolver::config::{LookupIpStrategy, ProtocolConfig};
use tokio::time::timeout_at;

use super::adapter::ProbeError;

const DNS_DEADLINE: Duration = Duration::from_millis(500);

/// UDP ports, besides 123, that a default NTS operator publishes in its
/// NTS-KE answer (RFC 8915 section 4.1.8). `nts.netnod.se` answers on 4123.
/// The list is closed on purpose: a hostile NTS-KE server can name any port
/// in that record, so accepting "any unprivileged port" would let it aim the
/// poll at 5432, 6379 or 11211. Only these exact numbers are accepted without
/// `allowed_ports`, and none belongs to another well-known service. They apply
/// only to the port an NTS-KE answer names, never to a configured source.
const PUBLISHED_NTP_PORTS: [u16; 1] = [4123];

/// What the operator allowed the probe to dial. The two permissions travel
/// together so no caller applies one without noticing the other: internal
/// addresses and custom ports are separate decisions in
/// `[clock_external]`, and each one stays refused unless its own option is set.
#[derive(Debug, Clone, Default)]
pub(super) struct Policy {
	/// Permit private, loopback and link-local addresses. Multicast,
	/// unspecified and limited broadcast destinations stay forbidden.
	pub allow_private: bool,
	/// Ports allowed besides the one the protocol standardises (NTS-KE
	/// 4460/tcp, NTP 123/udp). Owned so it can travel into a spawned probe.
	pub allowed_ports: Vec<u16>,
}

impl Policy {
	/// The policy a configuration block asks for.
	pub(super) fn from_config(allow_private: bool, allowed_ports: &[u16]) -> Self {
		Self {
			allow_private,
			allowed_ports: allowed_ports.to_vec(),
		}
	}

	/// Whether this port may be dialled for a protocol whose standard port is
	/// `expected_port`. Port zero is never a destination.
	fn allows_port(&self, port: u16, expected_port: u16) -> bool {
		port != 0 && (port == expected_port || self.allowed_ports.contains(&port))
	}

	/// This policy for the NTP port an NTS-KE answer names: the ports in
	/// [`PUBLISHED_NTP_PORTS`] are added. Only the exchange that follows a key
	/// exchange uses it; a configured source never gets them for free.
	pub(super) fn for_ke_answer(&self) -> Self {
		let mut policy = self.clone();
		for port in PUBLISHED_NTP_PORTS {
			if !policy.allowed_ports.contains(&port) {
				policy.allowed_ports.push(port);
			}
		}
		policy
	}
}

pub(super) fn validate_host(
	host: &str,
	port: u16,
	expected_port: u16,
	policy: &Policy,
) -> Result<(), String> {
	if !policy.allows_port(port, expected_port) {
		return Err("clock destination port is not allowed".into());
	}
	if host.contains('%') {
		return Err("clock destination IPv6 zone identifiers are not supported; use a destination without a zone".into());
	}
	let name = host.trim_end_matches('.').to_ascii_lowercase();
	if !policy.allow_private && (name == "localhost" || name.ends_with(".localhost")) {
		return Err("clock destination is local".into());
	}
	if let Ok(ip) = host.parse() {
		validate_ip(ip, policy)?;
	}
	Ok(())
}

fn validate_ip(ip: IpAddr, policy: &Policy) -> Result<(), String> {
	// One classification decides whether an address is allowed, the same one
	// the `public_ipv6` validation uses. `non_global_ipv6_reason` unwraps every
	// form that carries an IPv4 payload itself, so a transition address is
	// judged as the IPv6 address it is and the two policies cannot drift apart.
	let non_global = match ip {
		IpAddr::V4(ip) => crate::config::non_global_ipv4_reason(ip),
		IpAddr::V6(ip) => crate::config::non_global_ipv6_reason(ip),
	};
	// The three destinations no opt-in reaches are checked on the address and
	// on the payload it carries, so `::ffff:224.0.0.1` stays refused with the
	// opt-in set.
	let candidates = [Some(ip), carried_ipv4(ip)];
	let forbidden = candidates
		.iter()
		.any(|candidate| candidate.is_some_and(is_forbidden));
	if forbidden || (!policy.allow_private && non_global.is_some()) {
		return Err("clock destination address is not allowed".into());
	}
	Ok(())
}

/// The IPv4 payload an address carries, unwrapped for the destinations that
/// no opt-in reaches. A plain IPv4 address is its own payload.
fn carried_ipv4(ip: IpAddr) -> Option<IpAddr> {
	match ip {
		IpAddr::V6(ip) => crate::config::embedded_ipv4(ip).map(IpAddr::V4),
		ip => Some(ip),
	}
}

/// Multicast, unspecified and limited broadcast: never a valid destination.
fn is_forbidden(ip: IpAddr) -> bool {
	ip.is_multicast() || ip.is_unspecified() || matches!(ip, IpAddr::V4(ip) if ip.is_broadcast())
}

pub(super) async fn resolve(
	host: &str,
	port: u16,
	expected_port: u16,
	policy: &Policy,
	stop: Instant,
) -> Result<SocketAddr, ProbeError> {
	resolve_with(host, port, expected_port, policy, stop, async {
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
	policy: &Policy,
	stop: Instant,
	lookup: impl Future<Output = Result<Vec<IpAddr>, ProbeError>>,
) -> Result<SocketAddr, ProbeError> {
	validate_host(host, port, expected_port, policy).map_err(ProbeError::Dial)?;
	let dns_stop = stop.min(Instant::now() + DNS_DEADLINE);
	let addresses = timeout_at(dns_stop.into(), lookup)
		.await
		.map_err(|_| ProbeError::Timeout)??;
	for ip in &addresses {
		validate_ip(*ip, policy).map_err(ProbeError::Dial)?;
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
