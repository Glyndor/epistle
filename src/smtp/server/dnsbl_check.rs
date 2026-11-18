//! DNSBL screen helpers for the SMTP delivery path.
//!
//! One method on `Server` that runs the IP, sender-domain and URL-host
//! screens in order and returns the first rejection. The three screens share
//! the same gating (unauthenticated mail only, fail open on `Unavailable`)
//! so the SMTP loop calls this once per `Deliver` action instead of repeating
//! the gating for each list.

use std::net::IpAddr;

use crate::config::RefusalDetail;
use crate::smtp::reply::Reply;
use crate::smtp::session::{AcceptedMessage, Session};

use super::Server;
use super::refusal_text::{self, list_name, quoted};

/// Outcome of [`Server::screen_dnsbl`]: one of the three blocklists fired.
/// Each carries what was listed and the zone that listed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum DnsblRejection {
	/// Client IP listed on an IP blocklist zone.
	ClientIp { ip: IpAddr, zone: String },
	/// Envelope sender's domain listed on an RHSBL zone.
	SenderDomain { domain: String, zone: String },
	/// Host of a URL in the body listed on a URIBL zone.
	UrlHost { zone: String },
}

impl DnsblRejection {
	/// The SMTP reply (code 554 + detail) sent on the wire: what was
	/// listed, when it is the sender's own, and the list that matched.
	pub(super) fn reply(&self, detail: RefusalDetail) -> Reply {
		let (listed, fix) = match self {
			Self::ClientIp { ip, zone } => (
				format!(
					"client host {ip} blocked by {} (result: listed)",
					list_name(zone)
				),
				format!("ask {} to delist {ip}", list_name(zone)),
			),
			Self::SenderDomain { domain, zone } => (
				format!(
					"sender domain {} blocked by {} (result: listed)",
					quoted(domain),
					list_name(zone)
				),
				format!("ask {} to delist {}", list_name(zone), quoted(domain)),
			),
			Self::UrlHost { zone } => (
				format!(
					"message body links blocked by {} (result: listed)",
					list_name(zone)
				),
				format!("remove the links {} lists", list_name(zone)),
			),
		};
		refusal_text::listed(detail, listed, fix)
	}
}

impl Server {
	/// Screen `message` against the configured DNSBL lists. Returns the first
	/// rejection (if any); the SMTP loop emits the matching 554 reply. All
	/// three screens are gated on unauthenticated mail and skip when no DNS
	/// resolver is configured, so the call is cheap in the common case.
	///
	/// On a rejection the corpus is trained as spam and the `Dnsbl` counter
	/// is incremented. `Unavailable` responses from any zone fail open.
	pub(super) async fn screen_dnsbl(
		&self,
		peer: Option<IpAddr>,
		message: &AcceptedMessage,
		session: &Session,
	) -> Option<DnsblRejection> {
		let dns = self.spf.as_deref()?;
		if session.authenticated().is_some() {
			return None;
		}
		// IP screen: client address against the IP blocklist zones.
		if let Some(ip) = peer
			&& !self.inbound.trusts(peer)
			&& self.dnsbl.has_ip_zones()
			&& let crate::dnsbl::DnsblOutcome::Listed { zone } = self.dnsbl.check(ip, dns).await
		{
			tracing::info!(%ip, %zone, "rejecting DNSBL-listed client");
			self.record_dnsbl_reject(message, peer);
			return Some(DnsblRejection::ClientIp { ip, zone });
		}
		// RHSBL: envelope sender's domain against the domain blocklist zones.
		if self.dnsbl.has_domain_zones()
			&& let Some(domain) = message
				.reverse_path
				.rsplit_once('@')
				.map(|(_, d)| d.to_ascii_lowercase())
			&& let crate::dnsbl::DnsblOutcome::Listed { zone } =
				self.dnsbl.check_domain(&domain, dns).await
		{
			tracing::info!(%domain, %zone, "rejecting DNSBL-listed sender domain");
			self.record_dnsbl_reject(message, peer);
			return Some(DnsblRejection::SenderDomain { domain, zone });
		}
		// URIBL: hosts of every URL found in the body.
		if self.dnsbl.has_url_zones() {
			let hosts = crate::antispam::urls::extract_hosts(
				&message.data,
				crate::antispam::urls::DEFAULT_HOST_CAP,
			);
			if let crate::dnsbl::DnsblOutcome::Listed { zone } =
				self.dnsbl.check_url_hosts(&hosts, dns).await
			{
				tracing::info!(
					zone = %zone,
					hosts = ?hosts,
					"rejecting DNSBL-listed URL host"
				);
				self.record_dnsbl_reject(message, peer);
				return Some(DnsblRejection::UrlHost { zone });
			}
		}
		None
	}
	/// Common reject side-effect: train the corpus as spam and bump the
	/// shared `Dnsbl` counter.
	fn record_dnsbl_reject(&self, message: &AcceptedMessage, peer: Option<IpAddr>) {
		self.train_corpus(message, peer, true);
		self.metrics.rejected(crate::metrics::RejectReason::Dnsbl);
	}
}
