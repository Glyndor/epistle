//! One SMTP conversation with the exchanger (or smarthost) of one recipient
//! domain, and the answer it gives for each recipient.

use super::Worker;
use crate::dane::rrset::TlsaRrset;
use crate::queue::client::{self, DeliveryError, RecipientResult};
use crate::queue::tls_outcome::{STS_POLICY_FETCH_ERROR, STS_POLICY_INVALID, TlsOutcome};
use crate::storage::SpoolEntry;
use crate::tlsrpt::sessions::Attempt;

/// What one conversation decided for the recipients it carried.
pub(super) struct Conversation {
	/// The host that answered, when a connection got that far.
	pub(super) remote: Option<String>,
	/// One answer per recipient.
	pub(super) results: Vec<RecipientResult>,
}

impl Conversation {
	/// Whether the remote accepted the message for any recipient.
	pub(super) fn delivered(&self) -> bool {
		self.results.iter().any(|(_, result)| result.is_ok())
	}

	/// The recipients a `452 4.5.3` left for another transaction, when the
	/// remote took others in this one: they go out again at once and are
	/// not failures. Without any recipient taken, a 452 is an ordinary
	/// deferral, so a remote that takes none cannot loop the queue.
	pub(super) fn retry_now(&self) -> Vec<String> {
		if !self.delivered() {
			return Vec::new();
		}
		self.results
			.iter()
			.filter(|(_, result)| {
				matches!(result, Err(DeliveryError::Transient(reason))
					if crate::queue::backoff::too_many_recipients(reason))
			})
			.map(|(recipient, _)| recipient.clone())
			.collect()
	}

	/// The reply that asked the queue to slow down, when one did.
	pub(super) fn throttle(&self) -> Option<&str> {
		self.results.iter().find_map(|(_, result)| match result {
			Err(DeliveryError::Transient(reason)) if crate::queue::backoff::throttled(reason) => {
				Some(reason.as_str())
			}
			_ => None,
		})
	}

	/// The same answer for every recipient: the conversation never reached
	/// the point where recipients are answered one by one.
	pub(super) fn all(recipients: &[String], remote: Option<String>, error: DeliveryError) -> Self {
		Conversation {
			remote,
			results: recipients
				.iter()
				.map(|recipient| (recipient.clone(), Err(error.clone())))
				.collect(),
		}
	}
}

impl Worker {
	/// Route and run the conversation for `recipients`, all in `domain`.
	pub(super) async fn converse(
		&self,
		entry: &SpoolEntry,
		domain: &str,
		recipients: &[String],
	) -> Conversation {
		let domain = domain.to_string();
		// MTA-STS: an enforce policy constrains MX choice and mandates TLS.
		// A testing-mode policy is kept for TLS-RPT, which reports on it.
		let mut sts_invalid = false;
		let mut sts_fetch_error: Option<&'static str> = None;
		let fetched = match &self.mta_sts {
			Some((store, dns)) => match store.policy(dns.as_ref(), &domain).await {
				Ok(policy) => policy,
				// No policy could be fetched and none is cached: deliver as
				// though the domain published none (RFC 8461 section 3.3).
				Err(crate::mtasts::PolicyError::Temporary(reason)) => {
					tracing::warn!(%domain, %reason, "MTA-STS policy unavailable; delivering without it");
					sts_fetch_error = Some(STS_POLICY_FETCH_ERROR);
					None
				}
				// Malformed/absent policies fall back to opportunistic.
				Err(error) => {
					sts_invalid = matches!(error, crate::mtasts::PolicyError::Malformed(_));
					None
				}
			},
			None => None,
		};
		// RFC 8460 §4.3: when the policy fetch fails, the receiving domain
		// must see the failure in the next aggregate report. We do not have
		// the connecting MX yet, so the journal line carries empty fields;
		// the report groups by result-type and is still actionable.
		if let (Some(reason), Some(dir)) = (sts_fetch_error, self.tlsrpt_dir.as_ref()) {
			let attempt = Attempt {
				policy_domain: &domain,
				mx_host: "",
				sts: None,
				sts_invalid: false,
				sts_fetch_failed: true,
				dane: false,
				local_ip: None,
				peer_ip: None,
			};
			crate::tlsrpt::sessions::record(
				dir,
				self.now_epoch(),
				&attempt,
				TlsOutcome::Failure(reason),
			);
		}
		let policy = fetched
			.clone()
			.filter(|policy| policy.mode == crate::mtasts::Mode::Enforce);
		// TLS-Required: No from one of our senders sets the recipient's
		// policy aside (RFC 8689 section 3), unless REQUIRETLS asks for the
		// opposite on the same message.
		let tls_optional =
			!entry.envelope.require_tls && crate::queue::tls_required::optional(&entry.data);
		let policy = match policy {
			Some(_) if tls_optional => {
				tracing::info!(%domain, "TLS-Required: No; not enforcing the MTA-STS policy");
				None
			}
			policy => policy,
		};
		// MTA-STS enforce or a sender's REQUIRETLS both mandate verified TLS.
		let require_tls = policy.is_some() || entry.envelope.require_tls;

		// Route this delivery: a configured transport (relay/fail) or direct.
		let sender_account = entry
			.envelope
			.reverse_path
			.rsplit_once('@')
			.map(|(local, _)| local)
			.filter(|local| !local.is_empty());
		let transport = crate::config::select_transport(&self.transports, sender_account, &domain);
		let (stream, server_name, auth, tls_required, dane, endpoints) = match transport {
			Some(rule) if rule.kind == crate::config::TransportKind::Fail => {
				return Conversation::all(
					recipients,
					None,
					DeliveryError::Permanent(format!("transport policy rejects {domain}")),
				);
			}
			Some(rule) if rule.kind == crate::config::TransportKind::Relay => {
				// host/port validated at config load.
				let host = rule.host.clone().unwrap_or_default();
				let port = rule.port.unwrap_or(0);
				let stream = match crate::queue::transport::relay_connect(
					&host,
					port,
					rule.socks_proxy.as_deref(),
				)
				.await
				{
					Ok(stream) => stream,
					Err(error) => return Conversation::all(recipients, None, error),
				};
				let auth = match (&rule.username, &rule.password) {
					(Some(user), Some(pass)) => Some((user.clone(), pass.clone())),
					_ => None,
				};
				// starttls (required whenever AUTH is configured) forces TLS.
				// DANE does not apply to a configured smarthost (RFC 7672 is
				// keyed on the recipient's MX), so no TLSA records here.
				(
					stream,
					host,
					auth,
					rule.starttls,
					crate::dane::rrset::TlsaRrset::Absent,
					None,
				)
			}
			_ => {
				// Direct (no rule, or kind = direct): MX delivery.
				match self.connector.connect(&domain, policy.as_ref()).await {
					Ok(connection) => {
						let server_name = connection.host;
						// DANE: TLSA is published under the MX hostname. A
						// transient TLSA lookup failure defers delivery rather
						// than downgrading to opportunistic TLS (RFC 7672 §2.1).
						// Only a secure MX answer can vouch for the host whose
						// TLSA would authenticate it (RFC 7672 section 2.2.1);
						// otherwise MTA-STS or opportunistic TLS decides.
						let tlsa = if connection.mx != crate::queue::resolver::MxSecurity::Secure {
							Ok(crate::dane::rrset::TlsaRrset::Absent)
						} else {
							self.tlsa_for(&server_name).await
						};
						let tlsa = match tlsa {
							Ok(records) if tls_optional && records != TlsaRrset::Absent => {
								tracing::info!(%server_name, "TLS-Required: No; not applying DANE");
								TlsaRrset::Absent
							}
							Ok(records) => records,
							Err(crate::spf::DnsFailure::Temporary) if tls_optional => {
								TlsaRrset::Absent
							}
							Err(crate::spf::DnsFailure::Temporary) => {
								let reason =
									format!("transient TLSA lookup failure for {server_name}");
								return Conversation::all(
									recipients,
									Some(server_name),
									DeliveryError::Transient(reason),
								);
							}
						};
						let endpoints = Some((connection.local_ip, connection.peer_ip));
						(
							connection.stream,
							server_name,
							None,
							require_tls,
							tlsa,
							endpoints,
						)
					}
					Err(error) => return Conversation::all(recipients, None, error),
				}
			}
		};
		let mut tls = None;
		let result = client::deliver_each(
			stream,
			&server_name,
			&self.ehlo_hostname,
			&entry.envelope.reverse_path,
			recipients,
			&entry.data,
			tls_required,
			auth.as_ref().map(|(u, p)| (u.as_str(), p.as_str())),
			&dane,
			// Any certificate will do when the sender made TLS optional:
			// encrypted if the MX offers it, delivered either way.
			if tls_optional {
				crate::config::OutboundTls::Opportunistic
			} else {
				self.outbound_tls
			},
			&mut tls,
		)
		.await;
		// TLS-RPT covers the recipient's own MX only, not a smarthost.
		if let Some((local_ip, peer_ip)) = endpoints {
			let outcome = match sts_invalid {
				true => Some(TlsOutcome::Failure(STS_POLICY_INVALID)),
				false => tls,
			};
			let attempt = crate::tlsrpt::sessions::Attempt {
				policy_domain: &domain,
				mx_host: &server_name,
				sts: fetched.as_ref(),
				sts_invalid,
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
			Ok(results) => Conversation {
				remote: Some(server_name),
				results,
			},
			Err(error) => Conversation::all(recipients, Some(server_name), error),
		}
	}
}
