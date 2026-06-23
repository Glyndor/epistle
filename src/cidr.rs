//! Minimal CIDR containment for credential IP allowlists.
//!
//! A scoped credential (an app password or an API key) may carry a single CIDR
//! — `203.0.113.0/24`, `2001:db8::/32`, or a bare address (`/32` for IPv4,
//! `/128` for IPv6) — restricting the client IPs that may use it. This module
//! parses such a spec once and tests an [`IpAddr`] for membership by comparing
//! the masked high bits. No external dependency: the matching is a few bitwise
//! operations over the address octets.

use std::net::IpAddr;

/// A parsed CIDR block (an address family plus a prefix length).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
	/// The network base address, already masked to `prefix` bits so a malformed
	/// spec with host bits set still matches consistently.
	base: IpAddr,
	/// Prefix length in bits: 0..=32 for IPv4, 0..=128 for IPv6.
	prefix: u8,
}

impl Cidr {
	/// Parse a CIDR spec: `addr/prefix`, or a bare address (treated as a full
	/// host route, `/32` for IPv4 or `/128` for IPv6). Returns `None` for any
	/// malformed input — callers fail closed on `None`.
	pub fn parse(spec: &str) -> Option<Self> {
		let spec = spec.trim();
		let (addr_part, prefix_part) = match spec.split_once('/') {
			Some((addr, prefix)) => (addr, Some(prefix)),
			None => (spec, None),
		};
		let addr: IpAddr = addr_part.parse().ok()?;
		let max = match addr {
			IpAddr::V4(_) => 32u8,
			IpAddr::V6(_) => 128u8,
		};
		let prefix = match prefix_part {
			Some(text) => {
				let value: u8 = text.parse().ok()?;
				if value > max {
					return None;
				}
				value
			}
			None => max,
		};
		Some(Cidr {
			base: mask(addr, prefix),
			prefix,
		})
	}

	/// Whether `ip` falls within this block. An address of a different family is
	/// never contained (an IPv4 client is not in an IPv6 block and vice versa).
	pub fn contains(&self, ip: IpAddr) -> bool {
		match (self.base, ip) {
			(IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => {
				mask(ip, self.prefix) == self.base
			}
			_ => false,
		}
	}
}

/// Zero every bit of `addr` below the top `prefix` bits.
fn mask(addr: IpAddr, prefix: u8) -> IpAddr {
	match addr {
		IpAddr::V4(v4) => {
			let bits = u32::from_be_bytes(v4.octets());
			let masked = apply_mask_u128(bits as u128, prefix, 32);
			IpAddr::V4(std::net::Ipv4Addr::from((masked as u32).to_be_bytes()))
		}
		IpAddr::V6(v6) => {
			let bits = u128::from_be_bytes(v6.octets());
			let masked = apply_mask_u128(bits, prefix, 128);
			IpAddr::V6(std::net::Ipv6Addr::from(masked.to_be_bytes()))
		}
	}
}

/// Keep the top `prefix` of `width` bits of `value`, zero the rest. A zero
/// prefix matches everything (mask is all-zero); a full prefix is the identity.
fn apply_mask_u128(value: u128, prefix: u8, width: u8) -> u128 {
	if prefix == 0 {
		return 0;
	}
	if prefix >= width {
		return value;
	}
	let host_bits = width - prefix;
	let netmask = u128::MAX << host_bits;
	value & netmask
}

#[cfg(test)]
#[path = "cidr_tests.rs"]
mod tests;
