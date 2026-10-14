//! One SMTP session with one server (an exchanger of the recipient domain or
//! a smarthost), and the TLS-RPT record of how its TLS went.

use super::Worker;
use super::conversation::Conversation;
use crate::dane::rrset::TlsaRrset;
use crate::queue::client::{self, DeliveryError, Trace};
use crate::queue::resolver::{BoxedStream, Connection, MxSecurity};
use crate::queue::tls_outcome::{STS_POLICY_INVALID, TlsOutcome};
use crate::storage::SpoolEntry;

/// What every session of one conversation shares: the message, the
/// recipients, and the TLS policy that applies to them.
pub(super) struct Route<'a> {
	pub(super) entry: &'a SpoolEntry,
	pub(super) domain: &'a str,
	pub(super) recipients: &'a [String],
	/// The MTA-STS policy fetched for the domain, enforced or not, for
	/// TLS-RPT.
	pub(super) fetched: Option<&'a crate::mtasts::Policy>,
	/// The domain's MTA-STS policy could not be parsed.
	pub(super) sts_invalid: bool,
	/// The sender made TLS optional (`TLS-Required: No`).
	pub(super) tls_optional: bool,
	/// MTA-STS enforce or REQUIRETLS mandate verified TLS.
	pub(super) require_tls: bool,
	/// Set once a session has written the whole message (see
	/// [`Trace::sent`]).
	pub(super) sent: &'a std::sync::Arc<std::sync::atomic::AtomicBool>,
}

/// One open connection and how to speak on it.
pub(super) struct Session {
	pub(super) stream: BoxedStream,
	pub(super) server_name: String,
	pub(super) auth: Option<(String, String)>,
	pub(super) tls_required: bool,
	pub(super) dane: TlsaRrset,
	/// Our address and the server's, for TLS-RPT; `None` for a smarthost,
	/// which TLS-RPT does not cover.
	pub(super) endpoints: Option<(Option<std::net::IpAddr>, Option<std::net::IpAddr>)>,
}

impl Worker {
	/// Speak to one exchanger of the domain. Returns the conversation, and
	/// whether it ended before the mail transaction began in a way the next
	/// exchanger may not share (a 4xx or silent greeting, a failed TLS
	/// handshake, a transient TLSA lookup failure).
	pub(super) async fn attempt_direct(
		&self,
		route: &Route<'_>,
		connection: Connection,
	) -> (Conversation, bool) {
		let server_name = connection.host;
		// DANE: TLSA is published under the MX hostname. A transient TLSA
		// lookup failure defers delivery through this host rather than
		// downgrading to opportunistic TLS (RFC 7672 §2.1). Only a secure MX
		// answer can vouch for the host whose TLSA would authenticate it
		// (RFC 7672 section 2.2.1); otherwise MTA-STS or opportunistic TLS
		// decides.
		let tlsa = if connection.mx != MxSecurity::Secure {
			Ok(TlsaRrset::Absent)
		} else {
			self.tlsa_for(&server_name).await
		};
		let tlsa = match tlsa {
			Ok(records) if route.tls_optional && records != TlsaRrset::Absent => {
				tracing::info!(%server_name, "TLS-Required: No; not applying DANE");
				TlsaRrset::Absent
			}
			Ok(records) => records,
			Err(crate::spf::DnsFailure::Temporary) if route.tls_optional => TlsaRrset::Absent,
			Err(crate::spf::DnsFailure::Temporary) => {
				let reason = format!("transient TLSA lookup failure for {server_name}");
				let conversation = Conversation::all(
					route.recipients,
					Some(server_name),
					DeliveryError::Transient(reason),
				);
				return (conversation, true);
			}
		};
		let session = Session {
			stream: connection.stream,
			server_name,
			auth: None,
			tls_required: route.require_tls,
			dane: tlsa,
			endpoints: Some((connection.local_ip, connection.peer_ip)),
		};
		self.attempt(route, session).await
	}

	/// Run the SMTP session on `session` and record its TLS outcome.
	pub(super) async fn attempt(
		&self,
		route: &Route<'_>,
		session: Session,
	) -> (Conversation, bool) {
		let Session {
			stream,
			server_name,
			auth,
			tls_required,
			dane,
			endpoints,
		} = session;
		let mut trace = Trace {
			sent: std::sync::Arc::clone(route.sent),
			..Trace::default()
		};
		let result = client::deliver_each(
			stream,
			&server_name,
			&self.ehlo_hostname,
			&route.entry.envelope.reverse_path,
			route.recipients,
			&route.entry.data,
			tls_required,
			auth.as_ref().map(|(u, p)| (u.as_str(), p.as_str())),
			&dane,
			// Any certificate will do when the sender made TLS optional:
			// encrypted if the MX offers it, delivered either way.
			if route.tls_optional {
				crate::config::OutboundTls::Opportunistic
			} else {
				self.outbound_tls
			},
			&mut trace,
		)
		.await;
		// TLS-RPT covers the recipient's own MX only, not a smarthost.
		if let Some((local_ip, peer_ip)) = endpoints {
			let outcome = match route.sts_invalid {
				true => Some(TlsOutcome::Failure(STS_POLICY_INVALID)),
				false => trace.tls,
			};
			let attempt = crate::tlsrpt::sessions::Attempt {
				policy_domain: route.domain,
				mx_host: &server_name,
				sts: route.fetched,
				sts_invalid: route.sts_invalid,
				sts_fetch_failed: false,
				dane: !dane.records().is_empty(),
				local_ip,
				peer_ip,
			};
			if let (Some(dir), Some(outcome)) = (&self.tlsrpt_dir, outcome) {
				crate::tlsrpt::sessions::record(dir, self.now_epoch(), &attempt, outcome);
			}
		}
		match result {
			Ok(results) => (
				Conversation {
					remote: Some(server_name),
					results,
					slowed: None,
					held_until: None,
				},
				false,
			),
			Err(error) => {
				let next = !trace.transaction && matches!(error, DeliveryError::Transient(_));
				let conversation = Conversation::all(route.recipients, Some(server_name), error);
				(conversation, next)
			}
		}
	}
}
