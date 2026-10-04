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

/// Read the host's interfaces through `libc::getifaddrs` and run the
/// addresses through `local_global_addresses`. Only the machine's own
/// interfaces are touched: no DNS, no HTTP, no external service.
///
/// On non-Unix targets this function compiles to a stub that returns
/// an empty list of addresses. Detection is not available there (no
/// portable interface-walking call exists in `libc` for Windows), so
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
	use std::io::Error;
	use std::os::raw::c_int;

	// RAII guard: `getifaddrs` returns a heap-allocated linked list that
	// the caller MUST release with `freeifaddrs` on every exit path, panic
	// included. Wrapping the head in a drop guard makes that unconditional.
	struct IfAddrsGuard {
		head: *mut libc::ifaddrs,
	}
	impl Drop for IfAddrsGuard {
		fn drop(&mut self) {
			// SAFETY: `self.head` was returned by `getifaddrs` on the success
			// path and has not yet been released.
			unsafe { libc::freeifaddrs(self.head) };
		}
	}

	let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
	// SAFETY: `head` is a writable out-parameter; `getifaddrs` returns 0 on
	// success and fills the head pointer with a valid linked list.
	let rc = unsafe { libc::getifaddrs(&mut head) };
	if rc != 0 {
		return Err(Error::last_os_error());
	}
	if head.is_null() {
		// `getifaddrs` returns 0 with a null head on systems with no
		// interfaces, which the kernel is free to do. Treat that as "no
		// addresses to walk" rather than an error.
		return Ok(Vec::new());
	}
	let guard = IfAddrsGuard { head };
	let mut addresses: Vec<IpAddr> = Vec::new();

	let mut cur: *mut libc::ifaddrs = guard.head;
	while !cur.is_null() {
		// SAFETY: `cur` is a node in the list returned by `getifaddrs`. The
		// loop walks `ifa_next` until the list is exhausted; each `cur` is
		// non-null until the terminal node. No reference into the list
		// escapes the loop body.
		unsafe {
			let ifa: &libc::ifaddrs = &*cur;
			let sa_ptr = ifa.ifa_addr;
			if !sa_ptr.is_null() {
				let family = (*sa_ptr).sa_family as c_int;
				if family == libc::AF_INET {
					// SAFETY: `sa_ptr` is the `AF_INET` sockaddr for this
					// interface, but the kernel does not promise that it
					// is aligned for `libc::sockaddr_in`. Reading the value
					// through a reference would require that alignment;
					// `read_unaligned` does not.
					let v4_sa: libc::sockaddr_in =
						std::ptr::read_unaligned(sa_ptr as *const libc::sockaddr_in);
					let host_order = u32::from_be(v4_sa.sin_addr.s_addr);
					addresses.push(IpAddr::V4(Ipv4Addr::from(host_order)));
				} else if family == libc::AF_INET6 {
					// SAFETY: same alignment caveat as the AF_INET branch.
					let v6_sa: libc::sockaddr_in6 =
						std::ptr::read_unaligned(sa_ptr as *const libc::sockaddr_in6);
					let addr = Ipv6Addr::from(v6_sa.sin6_addr.s6_addr);
					if addr.to_ipv4_mapped().is_none() {
						addresses.push(IpAddr::V6(addr));
					}
				}
			}
			cur = ifa.ifa_next;
		}
	}

	drop(guard);
	Ok(addresses)
}

#[cfg(not(unix))]
fn read_interface_addresses() -> std::io::Result<Vec<IpAddr>> {
	// Detection is not available on this target: `libc` does not expose
	// `getifaddrs` on Windows, and there is no portable equivalent in
	// the crate. Returning an empty list keeps the `init` flow compiling
	// and lets it prompt the operator to type the addresses by hand.
	Ok(Vec::new())
}

#[cfg(test)]
#[path = "detect_tests.rs"]
mod tests;
