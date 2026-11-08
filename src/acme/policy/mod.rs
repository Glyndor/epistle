//! Where the ACME client may send a signed request.
//!
//! The directory document, and every resource the CA names in it or in its
//! answers, are chosen by the CA and not by the operator. A hostile CA — or
//! whoever takes the CA's place in the path — can point `newOrder` at the
//! cloud metadata address or at a service on the operator's LAN, and the
//! client would POST there a JWS signed with the account key: proof of
//! possession of that key, handed to the destination the CA picked.
//!
//! So every URL the CA names is checked before it is used:
//!
//! - it must be `https`, unless the operator's own directory URL is plain
//!   `http` (a local test CA such as Pebble), in which case plain `http` is
//!   admitted as well;
//! - it must not name the loopback interface, a private network, a
//!   link-local address (where the cloud metadata lives) or any other
//!   address that is not global, unless the directory URL the operator
//!   configured already names an address of that same kind — that CA is
//!   there on purpose;
//! - it need not be the same origin as the directory: some CAs publish
//!   their resources under another host.
//!
//! The address is judged as the URL writes it, and the same ranges the rest
//! of the repository judges (`crate::config`, the classifier the TLS-RPT
//! target uses) are the ones named here, so an address reads the same in
//! every refusal. A host *name* is not resolved: a DNS lookup in the request
//! path would make every ACME request depend on the resolver, and the name
//! of the CA's own host is the one name the operator chose. What is caught
//! is every literal address, which is what an attacker aiming the client at
//! a fixed target writes down.

use std::net::{Ipv4Addr, Ipv6Addr};

use url::{Host, Url};

use crate::acme::client::AcmeError;
use crate::acme::directory::Directory;
use crate::config::{embedded_ipv4, non_global_ipv4_reason, non_global_ipv6_reason};

/// The kind of destination a host names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Destination {
	/// A global unicast address: the CA's own host.
	Public,
	/// The loopback interface (127.0.0.0/8, ::1).
	Loopback,
	/// A link-local address (169.254.0.0/16, fe80::/10), where the cloud
	/// metadata lives.
	LinkLocal,
	/// A private network address (RFC 1918, RFC 4193).
	Private,
	/// An address that is not global and is none of the above (multicast,
	/// shared, documentation).
	Other,
}

impl Destination {
	/// How the kind is named in a refusal.
	fn describe(self) -> &'static str {
		match self {
			Destination::Public => "public",
			Destination::Loopback => "loopback",
			Destination::LinkLocal => "link-local",
			Destination::Private => "private-network",
			Destination::Other => "non-global",
		}
	}
}

/// Where the ACME client may send its requests, derived from the directory
/// URL the operator configured.
#[derive(Debug)]
pub struct Policy {
	/// The operator's directory URL: the base a relative URL is resolved
	/// against, and the source of the scheme and the host the policy
	/// admits.
	base: Url,
	/// Whether plain `http` is admitted: only when the operator's own
	/// directory URL is plain `http`.
	allow_http: bool,
	/// The kind of address the operator's directory host names. A URL the
	/// CA names may point at an address of that same kind, and at a global
	/// one; nothing else.
	directory: Destination,
}

impl Policy {
	/// The policy of a client bound to `directory_url`, the directory the
	/// operator configured. The URL itself is the operator's choice and is
	/// not refused here; what it decides is what the CA may name.
	pub fn for_directory(directory_url: &str) -> Result<Self, AcmeError> {
		let base = Url::parse(directory_url).map_err(|error| {
			AcmeError::Protocol(format!(
				"the ACME directory URL {directory_url} is not a URL: {error}"
			))
		})?;
		if !matches!(base.scheme(), "http" | "https") {
			return Err(AcmeError::Protocol(format!(
				"the ACME directory URL {directory_url} must be http or https"
			)));
		}
		let directory = match base.host() {
			Some(Host::Ipv4(ip)) => destination_v4(ip),
			Some(Host::Ipv6(ip)) => destination_v6(ip),
			Some(Host::Domain(name)) => destination_name(name),
			None => {
				return Err(AcmeError::Protocol(format!(
					"the ACME directory URL {directory_url} names no host"
				)));
			}
		};
		Ok(Policy {
			allow_http: base.scheme() == "http",
			base,
			directory,
		})
	}

	/// Check a URL the CA named and return the URL the client must use.
	///
	/// A URL the CA writes in full is returned as it wrote it, so the
	/// signature the client puts over its requests covers exactly the URL
	/// the CA published. A relative one is resolved against the directory
	/// URL, which is the only base the client knows.
	pub fn check(&self, raw: &str) -> Result<String, AcmeError> {
		match Url::parse(raw) {
			Ok(url) => {
				self.check_url(&url)?;
				Ok(raw.to_string())
			}
			Err(_) => {
				let url = self
					.base
					.join(raw)
					.map_err(|error| refuse(raw, format!("it is not a URL: {error}")))?;
				self.check_url(&url)?;
				Ok(url.to_string())
			}
		}
	}

	/// Check every URL the directory document names and return the
	/// directory with the URLs the client will use.
	pub fn check_directory(&self, directory: &Directory) -> Result<Directory, AcmeError> {
		Ok(Directory {
			new_nonce: self.check(&directory.new_nonce)?,
			new_account: self.check(&directory.new_account)?,
			new_order: self.check(&directory.new_order)?,
			revoke_cert: directory
				.revoke_cert
				.as_deref()
				.map(|url| self.check(url))
				.transpose()?,
			key_change: directory
				.key_change
				.as_deref()
				.map(|url| self.check(url))
				.transpose()?,
		})
	}

	/// The checks a URL the CA named must pass.
	fn check_url(&self, url: &Url) -> Result<(), AcmeError> {
		let scheme = url.scheme();
		if scheme != "https" && !(scheme == "http" && self.allow_http) {
			let reason = if self.allow_http {
				format!(
					"it uses {scheme}, and only https or http (as the CA directory does) is admitted"
				)
			} else {
				format!("it uses {scheme}, and only https is admitted")
			};
			return Err(refuse(safe_name(url), reason));
		}
		if !url.username().is_empty() || url.password().is_some() {
			return Err(refuse(safe_name(url), "it embeds credentials in the URL"));
		}
		let Some(host) = url.host() else {
			return Err(refuse(safe_name(url), "it names no host"));
		};
		let (destination, why) = classify_host(&host);
		if destination != Destination::Public && destination != self.directory {
			return Err(refuse(
				safe_name(url),
				format!(
					"it names {why}, and the CA directory the operator configured is at a {} host",
					self.directory.describe()
				),
			));
		}
		Ok(())
	}
}

/// The URL as it may be named in an error: without the credentials it
/// embeds, which are a secret of their own and do not belong in a log.
fn safe_name(url: &Url) -> String {
	let mut url = url.clone();
	let _ = url.set_username("");
	let _ = url.set_password(None);
	url.to_string()
}

/// The error for a URL the policy refuses: it names the URL and the reason.
/// The request that would have carried the account key is never sent, so
/// there is nothing else to name.
fn refuse(url: impl Into<String>, reason: impl Into<String>) -> AcmeError {
	AcmeError::RefusedUrl {
		url: url.into(),
		reason: reason.into(),
	}
}

/// The kind of destination a host names, and why it is not a global one.
fn classify_host(host: &Host<&str>) -> (Destination, String) {
	match host {
		Host::Ipv4(ip) => (destination_v4(*ip), reason_v4(*ip)),
		Host::Ipv6(ip) => (destination_v6(*ip), reason_v6(*ip)),
		Host::Domain(name) => {
			if is_localhost(name) {
				(
					Destination::Loopback,
					"the loopback interface (localhost)".to_string(),
				)
			} else {
				(Destination::Public, String::new())
			}
		}
	}
}

/// The kind of destination an IPv4 address is.
fn destination_v4(ip: Ipv4Addr) -> Destination {
	if ip.is_loopback() {
		Destination::Loopback
	} else if ip.is_link_local() {
		Destination::LinkLocal
	} else if ip.is_private() {
		Destination::Private
	} else if non_global_ipv4_reason(ip).is_some() {
		Destination::Other
	} else {
		Destination::Public
	}
}

/// The kind of destination an IPv6 address is. An address that carries an
/// IPv4 one (mapped, compatible, NAT64, 6to4) is judged by the address it
/// carries, so a v6 URL cannot hide a v4 internal address.
fn destination_v6(ip: Ipv6Addr) -> Destination {
	if ip.is_loopback() {
		Destination::Loopback
	} else if ip.is_unicast_link_local() {
		Destination::LinkLocal
	} else if ip.is_unique_local() {
		Destination::Private
	} else if let Some(v4) = embedded_ipv4(ip) {
		destination_v4(v4)
	} else if non_global_ipv6_reason(ip).is_some() {
		Destination::Other
	} else {
		Destination::Public
	}
}

/// The kind of destination a host name is. Only `localhost` (and the names
/// under it) tells without a lookup that it names the loopback interface.
fn destination_name(name: &str) -> Destination {
	if is_localhost(name) {
		Destination::Loopback
	} else {
		Destination::Public
	}
}

/// Whether a host name is `localhost` or a name under it.
fn is_localhost(name: &str) -> bool {
	let name = name.to_ascii_lowercase();
	name == "localhost" || name.ends_with(".localhost")
}

/// Why an IPv4 address is not a global one, in the words of the shared
/// classifier, so every refusal of the repository names the same ranges the
/// same way.
fn reason_v4(ip: Ipv4Addr) -> String {
	match non_global_ipv4_reason(ip) {
		Some(reason) => reason.to_string(),
		None => "not a global address".to_string(),
	}
}

/// Why an IPv6 address is not a global one.
fn reason_v6(ip: Ipv6Addr) -> String {
	match non_global_ipv6_reason(ip) {
		Some(reason) => reason.to_string(),
		None => "not a global address".to_string(),
	}
}

#[cfg(test)]
mod tests;
