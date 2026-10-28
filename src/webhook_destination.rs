//! Where a webhook may post: the destination policy of the webhook client.
//!
//! The endpoint of a webhook is chosen by the operator, but the address it
//! names may be one this host must not reach on its own: the loopback
//! interface, the private networks of the site, the link-local addresses
//! where the cloud metadata lives, or an address of a translation prefix
//! that carries the real destination inside it. A webhook that names one of
//! them posts message metadata inside the host, so the policy refuses those
//! addresses before the client is built and again after the host name is
//! resolved.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use reqwest::dns::{Addrs, Name, Resolve, Resolving};

use crate::config::embedded_ipv4;

/// Whether `ip` is a destination a webhook must not reach on its own.
///
/// The list covers the loopback interface, the private networks of the
/// site (RFC 1918 and RFC 4193), the link-local addresses where the cloud
/// metadata lives, the shared address space of a carrier, the addresses
/// that name no host at all, and the translation prefixes that carry the
/// destination they reach inside the address itself.
pub(crate) fn is_private(ip: IpAddr) -> bool {
	match ip {
		IpAddr::V4(ip) => is_private_v4(ip),
		IpAddr::V6(ip) => is_private_v6(ip),
	}
}

/// Whether an IPv4 address is one of those.
fn is_private_v4(ip: Ipv4Addr) -> bool {
	ip.is_loopback()
		|| ip.is_private()
		|| ip.is_link_local()
		|| ip.is_unspecified()
		|| ip.is_broadcast()
		|| is_shared(ip)
		// 0.0.0.0/8, "this network" on this host.
		|| ip.octets()[0] == 0
}

/// Whether an IPv4 address is in 100.64.0.0/10, the shared address space
/// of a carrier.
fn is_shared(ip: Ipv4Addr) -> bool {
	let octets = ip.octets();
	octets[0] == 100 && octets[1] & 0xc0 == 64
}

/// Whether an IPv6 address is one of those. An address that carries an
/// IPv4 one, mapped or in the older compatible form, is judged by the
/// address it carries.
///
/// A translation or transition prefix is refused by default: it carries the
/// IPv4 destination in the low bits of the address, so the literal names
/// one host and the translator reaches another, and the literal alone says
/// nothing about which.
fn is_private_v6(ip: Ipv6Addr) -> bool {
	if is_translation_v6(ip) {
		return true;
	}
	if let Some(ipv4) = embedded_ipv4(ip) {
		return is_private_v4(ipv4);
	}
	ip.is_loopback() || ip.is_unspecified() || ip.is_unique_local() || ip.is_unicast_link_local()
}

/// The prefixes that translate or transition between IPv4 and IPv6.
///
/// The NAT64 well-known prefix (RFC 6052), the local-use NAT64 prefix
/// (RFC 8215), 6to4 (RFC 3056) and Teredo (RFC 4380). Each of them names
/// the IPv4 destination inside the IPv6 address, so the address the
/// translator reaches is not the one the URL shows.
fn is_translation_v6(ip: Ipv6Addr) -> bool {
	matches!(
		ip.segments(),
		// NAT64, well-known prefix 64:ff9b::/96.
		[0x64, 0xff9b, 0, 0, 0, 0, ..]
			// NAT64, local-use prefix 64:ff9b:1::/48.
			| [0x64, 0xff9b, 0x0001, ..]
			// 6to4.
			| [0x2002, ..]
			// Teredo.
			| [0x2001, 0x0000, ..]
	)
}

/// Whether the URL names a destination the client must refuse, and why.
///
/// A URL the transport refuses on its own, because it is not a URL or
/// because it does not carry HTTP, is left to the transport: the client is
/// built and the refusal happens when the event is sent.
pub(crate) fn check_url(url: &str, allow_private: bool) -> Result<(), String> {
	if allow_private {
		return Ok(());
	}
	match private_address(url) {
		Some(ip) => Err(format!(
			"the destination {ip} is a private or a translated address; set allow_private_webhooks to reach it"
		)),
		None => Ok(()),
	}
}

/// Whether the URL names a private destination: an address of a private
/// network, the loopback interface, or the name `localhost`, which only
/// ever points at the loopback interface.
pub(crate) fn names_private(url: &str) -> bool {
	let Ok(parsed) = url::Url::parse(url) else {
		return false;
	};
	let loopback = match parsed.host() {
		Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
		Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
		Some(url::Host::Domain(name)) => name.eq_ignore_ascii_case("localhost"),
		None => false,
	};
	loopback || private_address(url).is_some()
}

/// The private address the URL names, if it names one.
///
/// A name is not an address: the addresses it resolves to are judged when
/// the client resolves it.
pub(crate) fn private_address(url: &str) -> Option<IpAddr> {
	let parsed = url::Url::parse(url).ok()?;
	if !matches!(parsed.scheme(), "http" | "https") {
		return None;
	}
	// The part before the host is never needed to reach the endpoint. A
	// value there that spells an address is an attempt to show one
	// destination and reach another.
	for part in [Some(parsed.username()), parsed.password()]
		.into_iter()
		.flatten()
	{
		if let Some(ip) = legacy_ipv4(part)
			&& is_private_v4(ip)
		{
			return Some(ip.into());
		}
	}
	match parsed.host()? {
		url::Host::Ipv4(ip) => is_private_v4(ip).then(|| ip.into()),
		url::Host::Ipv6(ip) => is_private_v6(ip).then(|| ip.into()),
		url::Host::Domain(name) => legacy_ipv4(name)
			.filter(|ip| is_private_v4(*ip))
			.map(|ip| ip.into()),
	}
}

/// The address a host name spells in the notations a resolver still
/// accepts: decimal (`2130706433`), octal (`0177.0.0.1`) and hexadecimal
/// (`0x7f000001`). The last part takes the octets the others leave, as
/// `inet_aton` reads them.
pub(crate) fn legacy_ipv4(host: &str) -> Option<Ipv4Addr> {
	let parts: Vec<&str> = host.split('.').collect();
	if parts.is_empty() || parts.len() > 4 {
		return None;
	}
	let numbers: Vec<u64> = parts
		.iter()
		.map(|part| number(part))
		.collect::<Option<_>>()?;
	let last = numbers.len() - 1;
	let mut bytes = [0u8; 4];
	for (index, number) in numbers.iter().take(last).enumerate() {
		if *number > 255 {
			return None;
		}
		bytes[index] = *number as u8;
	}
	let width = 4 - last;
	let mut tail = numbers[last];
	if tail >= 1u64 << (8 * width) {
		return None;
	}
	for index in (last..4).rev() {
		bytes[index] = (tail & 0xff) as u8;
		tail >>= 8;
	}
	Some(Ipv4Addr::from(bytes))
}

/// The number a part of a host name spells: hexadecimal with the `0x`
/// prefix, octal with a leading zero, decimal otherwise.
fn number(part: &str) -> Option<u64> {
	if part.is_empty() {
		return None;
	}
	let (radix, digits) = match part.strip_prefix("0x").or_else(|| part.strip_prefix("0X")) {
		Some(digits) => (16, digits),
		None if part.len() > 1 && part.starts_with('0') => (8, &part[1..]),
		None => (10, part),
	};
	if digits.is_empty() {
		return None;
	}
	u64::from_str_radix(digits, radix).ok()
}

/// The resolver the webhook client uses: it hands back the addresses of the
/// host name and none of them is a private one, unless the operator asked
/// for that.
pub(crate) struct DestinationResolver {
	/// Whether a private address is allowed.
	pub(crate) allow_private: bool,
}

impl Resolve for DestinationResolver {
	fn resolve(&self, name: Name) -> Resolving {
		let allow_private = self.allow_private;
		let host = name.as_str().to_string();
		Box::pin(async move {
			let addresses: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 0))
				.await
				.map_err(|error| Box::new(error) as BoxError)?
				.filter(|address| allow_private || !is_private(address.ip()))
				.collect();
			if addresses.is_empty() {
				return Err(Box::new(std::io::Error::other(format!(
					"{host} names no address a webhook may reach"
				))) as BoxError);
			}
			Ok(Box::new(addresses.into_iter()) as Addrs)
		})
	}
}

/// The error a resolver hands back: a boxed standard error.
type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[cfg(test)]
#[path = "webhook_destination_tests.rs"]
mod tests;
