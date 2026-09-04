//! DNSBL screen helpers for the SMTP delivery path.
//!
//! One method on `Server` that runs the IP, sender-domain and URL-host
//! screens in order and returns the first rejection. The three screens share
//! the same gating (unauthenticated mail only, fail open on `Unavailable`)
//! so the SMTP loop calls this once per `Deliver` action instead of repeating
//! the gating for each list.

use std::net::IpAddr;

use crate::smtp::reply::Reply;
use crate::smtp::session::{AcceptedMessage, Session};

use super::Server;

/// Outcome of [`Server::screen_dnsbl`]: one of the three blocklists fired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DnsblRejection {
	/// Client IP listed on an IP blocklist zone.
	ClientIp,
	/// Envelope sender's domain listed on an RHSBL zone.
	SenderDomain,
	/// Host of a URL in the body listed on a URIBL zone.
	UrlHost,
}

impl DnsblRejection {
	/// The SMTP reply (code 554 + detail) sent on the wire.
	pub(super) fn reply(self) -> Reply {
		let detail = match self {
			Self::ClientIp => "5.7.1 client host blocked by DNS blocklist",
			Self::SenderDomain => "5.7.1 sender domain blocked by DNS blocklist",
			Self::UrlHost => "5.7.1 message body links blocked by DNS blocklist",
		};
		Reply::single(554, detail)
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
			&& self.dnsbl.has_ip_zones()
			&& let crate::dnsbl::DnsblOutcome::Listed { zone } =
				self.dnsbl.check(ip, dns).await
		{
			tracing::info!(%ip, %zone, "rejecting DNSBL-listed client");
			self.record_dnsbl_reject(&message.data);
			return Some(DnsblRejection::ClientIp);
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
			self.record_dnsbl_reject(&message.data);
			return Some(DnsblRejection::SenderDomain);
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
				self.record_dnsbl_reject(&message.data);
				return Some(DnsblRejection::UrlHost);
			}
		}
		None
	}
	/// Common reject side-effect: train the corpus as spam and bump the
	/// shared `Dnsbl` counter.
	fn record_dnsbl_reject(&self, data: &[u8]) {
		self.train_corpus(data, true);
		self.metrics.rejected(crate::metrics::RejectReason::Dnsbl);
	}
}
