//! Read-only detection of the machine's outward-facing addresses for the
//! `epistle init` flow. The flow needs two pieces:
//!
//! 1. the public IPv4 and IPv6 the host routes on, derived from the local
//!    interfaces (`local_global_addresses` and `detect`); and
//! 2. a single-IP reverse-DNS verdict (`ptr_report`) that tells the operator
//!    what to ask a third party for when the round-trip is not yet correct.
//!
//! The module does not touch the network on its own: `local_global_addresses`
//! is a pure classifier over an iterator of `IpAddr`; `detect` is the only
//! call that walks the kernel's interface list; `ptr_report` consumes a
//! `&dyn DnsLookup` and never opens a socket itself.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::config::{non_global_ipv4_reason, non_global_ipv6_reason};
use crate::spf::DnsLookup;

use super::check_host::{PtrOutcome, classify_ptr};

/// What `local_global_addresses` returns: the chosen IPv4 and IPv6 global
/// addresses (the deterministic pick) plus every other global address the
/// machine routes on, so the caller can show them to the operator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalGlobals {
	/// The lowest global IPv4 address on the host, if any.
	pub ipv4: Option<Ipv4Addr>,
	/// The lowest global IPv6 address on the host, if any.
	pub ipv6: Option<Ipv6Addr>,
	/// Every other global address the host carries, in ascending order.
	pub others: Vec<IpAddr>,
}

impl LocalGlobals {
	/// The tuple form expected by callers that only care about the chosen
	/// pair, matching the `(Option<Ipv4Addr>, Option<Ipv6Addr>)` shape of
	/// `Config::public_ipv4` / `Config::public_ipv6`.
	pub fn chosen(&self) -> (Option<Ipv4Addr>, Option<Ipv6Addr>) {
		(self.ipv4, self.ipv6)
	}
}

/// Split a stream of interface addresses into the global IPv4/IPv6 picks and
/// the rest. The "global" rule is the same one `validate_addresses` enforces
/// for `public_ipv4` / `public_ipv6`; the helper is `pub(crate)` for exactly
/// this reuse.
///
/// When several global addresses of the same family are present, the lowest
/// address wins (numeric, network-order) and the rest land in `others`. The
/// ordering makes the pick reproducible across runs: the same host with the
/// same interfaces always gets the same answer.
pub fn local_global_addresses(interfaces: impl Iterator<Item = IpAddr>) -> LocalGlobals {
	let mut v4: Vec<Ipv4Addr> = Vec::new();
	let mut v6: Vec<Ipv6Addr> = Vec::new();
	for ip in interfaces {
		match ip {
			IpAddr::V4(addr) if non_global_ipv4_reason(addr).is_none() => v4.push(addr),
			IpAddr::V6(addr) if non_global_ipv6_reason(addr).is_none() => v6.push(addr),
			_ => {}
		}
	}
	v4.sort();
	v6.sort();
	let ipv4 = (!v4.is_empty()).then(|| v4.remove(0));
	let ipv6 = (!v6.is_empty()).then(|| v6.remove(0));
	let mut others: Vec<IpAddr> = Vec::with_capacity(v4.len() + v6.len());
	others.extend(v4.into_iter().map(IpAddr::V4));
	others.extend(v6.into_iter().map(IpAddr::V6));
	others.sort();
	LocalGlobals { ipv4, ipv6, others }
}

/// Read the host's interfaces through `getifaddrs` and run the
/// addresses through `local_global_addresses`. Only the machine's own
/// interfaces are touched: no DNS, no HTTP, no external service.
///
/// On non-Unix targets this function compiles to a stub that returns
/// an empty list of addresses. Detection is not available there (no
/// portable interface-walking call exists for Windows), so
/// the `init` flow prompts the operator to type the addresses by hand.
pub fn detect() -> std::io::Result<(Option<Ipv4Addr>, Option<Ipv6Addr>)> {
	let LocalGlobals { ipv4, ipv6, .. } =
		local_global_addresses(read_interface_addresses()?.into_iter());
	Ok((ipv4, ipv6))
}

/// The verdict of a PTR check. Built on the shared `classify_ptr`, with the
/// transport-error variant collapsed to `None` so the operator-facing enum
/// stays at the four outcomes the `init` flow cares about: a missing PTR,
/// a PTR that points elsewhere, a broken round trip, or a clean match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PtrReport {
	/// Forward-confirmed: the PTR points at `hostname` and `hostname`
	/// resolves back to `ip`.
	Ok,
	/// No PTR exists for `ip`, or the DNS lookup itself failed transiently.
	/// Either way the operator's next move is to ask the IP provider to
	/// publish a PTR, so the two cases share a verdict.
	None,
	/// The PTR exists but points at a name other than the one the operator
	/// asked the server to verify against. Carries both halves so the
	/// diagnostic text names the requested hostname and the one currently
	/// published in DNS.
	PointsElsewhere {
		/// The hostname the operator asked to verify against `ip`.
		expected: String,
		/// The joined list of names the existing PTR records name.
		found: String,
	},
	/// The PTR points at `hostname`, but `hostname` does not resolve back to
	/// `ip`. The operator needs to ask the DNS provider (the one that hosts
	/// `hostname`'s zone) to add the matching A or AAAA record.
	DoesNotResolveBack,
}

impl From<PtrOutcome> for PtrReport {
	fn from(outcome: PtrOutcome) -> Self {
		match outcome {
			PtrOutcome::Ok => Self::Ok,
			PtrOutcome::None => Self::None,
			PtrOutcome::PointsElsewhere { expected, found } => {
				Self::PointsElsewhere { expected, found }
			}
			PtrOutcome::DoesNotResolveBack => Self::DoesNotResolveBack,
			// A transient DNS error is not a verdict about the PTR itself;
			// fold it into the "no reverse record" branch because the
			// operator's first move (ask the IP provider to publish one) is
			// the same. A subsequent retry that resolves the failure will
			// either keep the "None" verdict (PTR really absent) or move to
			// "PointsElsewhere"/"Ok" once the record exists.
			PtrOutcome::LookupError => Self::None,
		}
	}
}

/// Run the PTR check for `ip` against `hostname`. The verdict is one of the
/// four `PtrReport` variants; `Display` renders the operator-facing text.
pub async fn ptr_report(hostname: &str, ip: IpAddr, dns: &dyn DnsLookup) -> PtrReport {
	classify_ptr(hostname, ip, dns).await.into()
}

impl fmt::Display for PtrReport {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Ok => f.write_str("reverse DNS points at the hostname"),
			Self::None => f.write_str(
				"no reverse record; ask the owner of this IP (your VPS, host or \
				 ISP) to publish a record pointing it at the hostname",
			),
			Self::PointsElsewhere { expected, found } => write!(
				f,
				"reverse DNS currently points at {found}; ask the owner of this IP to \
				 change it to point at {expected}"
			),
			Self::DoesNotResolveBack => f.write_str(
				"the hostname does not resolve back to this IP; ask the DNS provider \
				 that hosts the hostname's zone to add the matching A or AAAA record",
			),
		}
	}
}

#[cfg(unix)]
fn read_interface_addresses() -> std::io::Result<Vec<IpAddr>> {
	let interfaces = nix::ifaddrs::getifaddrs().map_err(std::io::Error::from)?;
	Ok(interfaces
		.filter_map(|interface| interface.address.as_ref().and_then(socket_ip))
		.collect())
}

/// The IP address inside an interface's socket address. Non-IP families
/// (link-layer addresses) and IPv4-mapped IPv6 addresses yield `None`: the
/// mapped form duplicates the IPv4 address the same interface already lists.
#[cfg(unix)]
fn socket_ip(address: &nix::sys::socket::SockaddrStorage) -> Option<IpAddr> {
	if let Some(v4) = address.as_sockaddr_in() {
		return Some(IpAddr::V4(v4.ip()));
	}
	let v6 = address.as_sockaddr_in6()?.ip();
	v6.to_ipv4_mapped().is_none().then_some(IpAddr::V6(v6))
}

#[cfg(not(unix))]
fn read_interface_addresses() -> std::io::Result<Vec<IpAddr>> {
	// Detection is not available on this target: `getifaddrs` does not exist
	// on Windows, and there is no portable equivalent in the crate. Returning
	// an empty list keeps the `init` flow compiling and lets it prompt the
	// operator to type the addresses by hand.
	Ok(Vec::new())
}

#[cfg(test)]
mod tests;
