//! `check_host`: the hostname's address and reverse-DNS checks, sibling of
//! [`super::check_domain`]. Pulled out so `mod.rs` stays under the per-file
//! code-line limit.
//!
//! The function returns the same [`Check`] enum as `check_domain` so the
//! verify-dns report can list both under their own header and feed the same
//! `all_ok` accumulator without special-casing.
//!
//! Two checks per address concern two different audiences: an `A`/`AAAA`
//! line under "hostname:" says the host is reachable on that protocol; a
//! `PTR` line under the same header says the IP identifies itself by the
//! same name. Receivers check both halves of the round trip: a hostname
//! without an address bounces, an IP without a forward-confirmed PTR
//! gets reputation-penalised.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::spf::DnsLookup;

use super::Check;

/// Check the hostname's A/AAAA and reverse DNS. `public_ipv4` / `public_ipv6`
/// come from the optional config fields; when both are `None`, the hostname
/// is resolved on the fly and whatever it says is treated as the truth.
///
/// Order of checks:
///  1. one `A` and/or `AAAA` line (depending on which addresses are
///     configured or resolved);
///  2. one `PTR` line per address.
///
/// The forward-confirmation check on `PTR` looks the hostname back up, so a
/// broken round trip is reported even when both halves exist independently.
pub async fn check_host(
	hostname: &str,
	public_ipv4: Option<Ipv4Addr>,
	public_ipv6: Option<Ipv6Addr>,
	dns: &dyn DnsLookup,
) -> Vec<Check> {
	let mut checks = Vec::new();

	let configured = [public_ipv4.map(IpAddr::V4), public_ipv6.map(IpAddr::V6)]
		.into_iter()
		.flatten()
		.collect::<Vec<_>>();
	let has_configured = !configured.is_empty();

	// Resolve the hostname when the operator did not pin the addresses,
	// so the PTR checks still have something to walk. A failed resolve
	// is an error line, not a fatal: the operator may be running the
	// check before the A/AAAA have propagated.
	let resolved = if has_configured {
		Vec::new()
	} else {
		match dns.addresses(hostname).await {
			Ok(addrs) => addrs,
			Err(_) => {
				checks.push(Check::error("A/AAAA", hostname));
				return checks;
			}
		}
	};

	checks.extend(address_checks(hostname, public_ipv4, public_ipv6, &resolved, dns).await);

	let addresses = if has_configured { configured } else { resolved };
	for ip in addresses {
		checks.push(ptr_check(hostname, ip, dns).await);
	}

	checks
}

/// Emit the `A` and `AAAA` lines under the hostname header. When the operator
/// configured an address, it must match what the hostname resolves to; when
/// not, the resolved addresses are reported as-is (or `Missing` when the
/// hostname does not resolve at all).
async fn address_checks(
	hostname: &str,
	public_ipv4: Option<Ipv4Addr>,
	public_ipv6: Option<Ipv6Addr>,
	resolved_already: &[IpAddr],
	dns: &dyn DnsLookup,
) -> Vec<Check> {
	let mut checks = Vec::new();

	if let Some(expected) = public_ipv4 {
		checks.push(address_check("A", hostname, IpAddr::V4(expected), dns).await);
	}
	if let Some(expected) = public_ipv6 {
		checks.push(address_check("AAAA", hostname, IpAddr::V6(expected), dns).await);
	}

	if public_ipv4.is_none() && public_ipv6.is_none() {
		if resolved_already.is_empty() {
			checks.push(Check::missing(
				"A/AAAA",
				hostname,
				"hostname does not resolve".to_string(),
			));
		} else {
			let listed = resolved_already
				.iter()
				.map(|ip| ip.to_string())
				.collect::<Vec<_>>()
				.join(", ");
			checks.push(Check::ok("A/AAAA", hostname, format!("resolved: {listed}")));
		}
	}

	checks
}

/// One `A` or `AAAA` check: the hostname must resolve to `expected`, and the
/// detail names every address the resolver returned (so an operator who set
/// the right value and a stale sibling at the same time sees the whole set).
async fn address_check(kind: &str, hostname: &str, expected: IpAddr, dns: &dyn DnsLookup) -> Check {
	match dns.addresses(hostname).await {
		Ok(addrs) if addrs.contains(&expected) => {
			if addrs.len() == 1 {
				Check::ok(kind, hostname, expected.to_string())
			} else {
				let listed = addrs
					.iter()
					.map(|ip| ip.to_string())
					.collect::<Vec<_>>()
					.join(", ");
				Check::ok(kind, hostname, format!("{listed} (configured: {expected})"))
			}
		}
		Ok(addrs) if addrs.is_empty() => Check::missing(
			kind,
			hostname,
			format!("no {kind} record; expected {expected}"),
		),
		Ok(addrs) => {
			let listed = addrs
				.iter()
				.map(|ip| ip.to_string())
				.collect::<Vec<_>>()
				.join(", ");
			Check::missing(
				kind,
				hostname,
				format!("resolves to {listed}, expected {expected}"),
			)
		}
		Err(_) => Check::error(kind, hostname),
	}
}

/// One `PTR` check for `ip`. The detail string is the user-facing error:
/// each failure mode gets its own wording because the fix is different in
/// each case (talk to the IP provider, talk to the DNS provider, talk to
/// neither: the round-trip is broken).
async fn ptr_check(hostname: &str, ip: IpAddr, dns: &dyn DnsLookup) -> Check {
	let kind = format!("PTR {ip}");
	let ip_str = ip.to_string();
	let kind_ref = &kind;
	match dns.ptr(ip).await {
		Err(_) => Check::error(kind_ref, ip_str.clone()),
		Ok(names) if names.is_empty() => Check::missing(
			kind_ref,
			ip_str.clone(),
			format!("no reverse record; ask the provider of this IP to point it at {hostname}"),
		),
		Ok(names) if !names.iter().any(|n| n.eq_ignore_ascii_case(hostname)) => {
			let other = names.join(", ");
			Check::missing(
				kind_ref,
				ip_str.clone(),
				format!("points at {other}, not {hostname}"),
			)
		}
		Ok(_) => match dns.addresses(hostname).await {
			Ok(addrs) if addrs.contains(&ip) => {
				Check::ok(kind_ref, ip_str.clone(), format!("→ {hostname}"))
			}
			Ok(_) => Check::missing(
				kind_ref,
				ip_str.clone(),
				format!("{hostname} does not resolve back to {ip}"),
			),
			Err(_) => Check::error(kind_ref, ip_str),
		},
	}
}
