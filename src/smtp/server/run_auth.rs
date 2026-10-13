//! Sender authentication for unauthenticated inbound mail: SPF, DKIM and
//! DMARC, the DMARC aggregate record, the `Authentication-Results` and
//! `Received-SPF` headers, and the ARC seal over them. Pulled out of the
//! connection loop in `run.rs`, which drives the session and decides what
//! to answer.

use std::net::IpAddr;

use crate::smtp::reply::Reply;
use crate::smtp::session::{AcceptedMessage, Session};
use crate::smtp::trace::{format_auth_results, spf_domain};

use super::Server;

impl Server {
	/// Authenticate `message` from `peer` when the session did not log in
	/// and a resolver is configured. Returns the trace headers to prepend
	/// (empty when nothing ran), or the reply that refuses the message: SPF
	/// or DMARC failed, or either could not be evaluated right now.
	pub(super) async fn authenticate_inbound(
		&self,
		message: &AcceptedMessage,
		session: &Session,
		peer: Option<IpAddr>,
	) -> Result<String, Reply> {
		let mut auth_headers = String::new();
		if let (Some(dns), Some(ip), None) = (&self.spf, peer, session.authenticated()) {
			let domain = spf_domain(&message.reverse_path, session.helo_domain());
			let outcome = match &domain {
				Some(domain) => {
					let helo = session.helo_domain().unwrap_or("");
					crate::spf::check_host(dns.as_ref(), ip, domain, &message.reverse_path, helo)
						.await
				}
				None => crate::spf::SpfOutcome::None,
			};
			match outcome {
				crate::spf::SpfOutcome::Fail => {
					self.metrics.rejected(crate::metrics::RejectReason::Spf);
					return Err(Reply::single(550, "5.7.23 SPF validation failed"));
				}
				crate::spf::SpfOutcome::TempError => {
					return Err(Reply::single(451, "4.4.3 SPF check temporarily failed"));
				}
				outcome => {
					auth_headers.push_str(&format!(
						"Received-SPF: {} (domain of {}) client-ip={ip}\r\n",
						outcome.as_str(),
						domain.as_deref().unwrap_or("unknown"),
					));

					// DKIM is recorded; DMARC decides policy.
					let dkim_results =
						crate::dkim::verify_message(dns.as_ref(), &message.data).await;

					let author = crate::dmarc::author::author_domain(&message.data);
					let from = match &author {
						crate::dmarc::author::AuthorDomain::One(domain) => Some(domain.clone()),
						_ => None,
					};
					let dmarc = match &author {
						crate::dmarc::author::AuthorDomain::One(from) => {
							crate::dmarc::evaluate(
								dns.as_ref(),
								from,
								(outcome, domain.as_deref()),
								&dkim_results,
							)
							.await
						}
						// RFC 7489 section 6.6.1: two From fields, or
						// one naming several domains, leave no single
						// owner to authenticate; RFC 5322 forbids the
						// first outright. It fails rather than errs.
						crate::dmarc::author::AuthorDomain::Multiple => {
							crate::dmarc::DmarcOutcome::Fail
						}
						// No usable From header: nothing to align.
						crate::dmarc::author::AuthorDomain::Missing => {
							crate::dmarc::DmarcOutcome::PermError
						}
					};
					// Record DMARC result for aggregate reporting.
					if let (Some(report_data_dir), Some(from_domain)) = (&self.report_dir, &from) {
						let disposition = match &dmarc {
							crate::dmarc::DmarcOutcome::Reject => "reject",
							_ => "none",
						};
						let ts = std::time::SystemTime::now()
							.duration_since(std::time::UNIX_EPOCH)
							.map(|d| d.as_secs())
							.unwrap_or(0);
						let best_dkim = dkim_results.first();
						let record = crate::dmarc::report::DeliveryRecord {
							timestamp: ts,
							source_ip: peer.map(|p| p.to_string()).unwrap_or_default(),
							envelope_from: domain.as_deref().unwrap_or("").to_owned(),
							header_from: from_domain.clone(),
							spf: outcome.as_str().to_owned(),
							dkim: best_dkim
								.map(|r| r.outcome.as_str())
								.unwrap_or("none")
								.to_owned(),
							dkim_domain: best_dkim
								.and_then(|r| r.domain.clone())
								.unwrap_or_default(),
							dmarc: dmarc.as_str().to_owned(),
							disposition: disposition.to_owned(),
							policy_domain: from_domain.clone(),
							published_policy: String::new(),
							pct: 100,
						};
						let today = crate::dmarc::aggregate::unix_to_day(record.timestamp);
						crate::dmarc::aggregate::record_delivery(report_data_dir, &today, &record);
					}

					match dmarc {
						crate::dmarc::DmarcOutcome::Reject => {
							self.metrics.rejected(crate::metrics::RejectReason::Dmarc);
							self.train_corpus(&message.data, true);
							return Err(Reply::single(550, "5.7.1 rejected by DMARC policy"));
						}
						crate::dmarc::DmarcOutcome::TempError => {
							return Err(Reply::single(451, "4.4.3 DMARC check temporarily failed"));
						}
						_ => {}
					}

					let mut methods: Vec<String> = Vec::new();

					let mut spf_result = format!("spf={}", outcome.as_str());
					if let Some(domain) = &domain {
						spf_result.push_str(&format!(" smtp.mailfrom={domain}"));
					}
					methods.push(spf_result);

					if dkim_results.is_empty() {
						methods.push("dkim=none".to_string());
					} else {
						for dkim in &dkim_results {
							let mut entry = format!("dkim={}", dkim.outcome.as_str());
							if let Some(d) = &dkim.domain {
								entry.push_str(&format!(" header.d={d}"));
							}
							methods.push(entry);
						}
					}

					let mut dmarc_result = format!("dmarc={}", dmarc.as_str());
					if let Some(from) = &from {
						dmarc_result.push_str(&format!(" header.from={from}"));
					}
					methods.push(dmarc_result);

					auth_headers.push_str(&format_auth_results(&self.hostname, &methods));

					// ARC: seal this hop so downstream forwarders can
					// trust our authentication results even if they
					// break SPF/DKIM. cv reflects any inbound chain.
					if let Some(sealer) = &self.arc_sealer {
						let cv = crate::arc::validate::validate(dns.as_ref(), &message.data).await;
						let prior = crate::arc::chain::extract(&message.data)
							.ok()
							.flatten()
							.unwrap_or_default();
						let summary = methods.join("; ");
						if let Some(arc_headers) = sealer.seal(&message.data, &summary, &prior, cv)
						{
							auth_headers.push_str(&arc_headers);
						}
					}
				}
			}
		}
		Ok(auth_headers)
	}
}
