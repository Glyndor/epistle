//! The SMTP connection loop: drives one session from greeting to close.

use std::net::IpAddr;

use tokio::io::AsyncReadExt;

use crate::smtp::line::LineDecoder;
use crate::smtp::reply::Reply;
use crate::smtp::session::{Action, Session};
use crate::smtp::trace::{format_auth_results, line_error_reply, received_header, spf_domain};

use super::{COMMAND_TIMEOUT, Connection, Mode, READ_BUFFER, Server, send};

impl Server {
	/// The protocol loop over an established (plain or TLS) stream.
	pub(super) async fn run(
		&self,
		mut stream: Box<dyn Connection>,
		mut session: Session,
		peer: Option<IpAddr>,
	) -> std::io::Result<()> {
		self.metrics.connection();
		send(&mut stream, &session.greeting()).await?;

		let mut decoder = LineDecoder::new();
		let mut mode = Mode::Commands;
		let mut buffer = [0u8; READ_BUFFER];

		loop {
			let line = match decoder.next_line() {
				Ok(Some(line)) => line,
				Ok(None) => {
					let read = match tokio::time::timeout(COMMAND_TIMEOUT, stream.read(&mut buffer))
						.await
					{
						Ok(Ok(n)) => n,
						Ok(Err(e)) => return Err(e),
						Err(_) => {
							tracing::debug!("SMTP command timeout, closing connection");
							return Ok(());
						}
					};
					if read == 0 {
						return Ok(());
					}
					decoder.feed(&buffer[..read]);
					continue;
				}
				Err(error) => {
					send(&mut stream, &line_error_reply(&error)).await?;
					return Ok(());
				}
			};

			// In Data mode, pass raw bytes to support 8BITMIME (RFC 6152).
			let action = if mode == Mode::Data {
				session.data_line(&line)
			} else {
				let Ok(line_str) = String::from_utf8(line) else {
					if mode == Mode::Commands {
						send(&mut stream, &Reply::syntax_error()).await?;
						continue;
					}
					// Auth responses must be ASCII; abort.
					send(
						&mut stream,
						&Reply::single(501, "5.5.2 non-ASCII in AUTH response"),
					)
					.await?;
					return Ok(());
				};
				match mode {
					Mode::Commands => Some(session.command_line(&line_str)),
					// Argon2 is CPU-bound; per-connection rate limiting keeps attempts scarce.
					Mode::Auth => Some(session.auth_line(&line_str)),
					Mode::Data => unreachable!(),
				}
			};
			let Some(action) = action else {
				continue;
			};

			mode = Mode::Commands;
			match action {
				Action::Continue(reply) => send(&mut stream, &reply).await?,
				Action::CollectData(reply) => {
					mode = Mode::Data;
					send(&mut stream, &reply).await?;
				}
				Action::CollectAuthResponse(reply) => {
					mode = Mode::Auth;
					send(&mut stream, &reply).await?;
				}
				Action::Deliver(reply, mut message) => {
					// SPF and DKIM apply to unauthenticated mail from a
					// known peer.
					let mut auth_headers = String::new();
					// DNSBL screening: reject unauthenticated clients listed on a
					// configured blocklist before any further processing.
					if let (Some(dns), Some(ip), None) = (&self.spf, peer, session.authenticated())
						&& !self.dnsbl.is_empty()
						&& let crate::dnsbl::DnsblOutcome::Listed { zone } =
							self.dnsbl.check(ip, dns.as_ref()).await
					{
						tracing::info!(%ip, %zone, "rejecting DNSBL-listed client");
						self.metrics.rejected(crate::metrics::RejectReason::Dnsbl);
						self.train_corpus(&message.data, true);
						send(
							&mut stream,
							&Reply::single(554, "5.7.1 client host blocked by DNS blocklist"),
						)
						.await?;
						continue;
					}
					if let (Some(dns), Some(ip), None) = (&self.spf, peer, session.authenticated())
					{
						let domain = spf_domain(&message.reverse_path, session.helo_domain());
						let outcome = match &domain {
							Some(domain) => {
								let helo = session.helo_domain().unwrap_or("");
								crate::spf::check_host(
									dns.as_ref(),
									ip,
									domain,
									&message.reverse_path,
									helo,
								)
								.await
							}
							None => crate::spf::SpfOutcome::None,
						};
						match outcome {
							crate::spf::SpfOutcome::Fail => {
								self.metrics.rejected(crate::metrics::RejectReason::Spf);
								send(
									&mut stream,
									&Reply::single(550, "5.7.23 SPF validation failed"),
								)
								.await?;
								continue;
							}
							crate::spf::SpfOutcome::TempError => {
								send(
									&mut stream,
									&Reply::single(451, "4.4.3 SPF check temporarily failed"),
								)
								.await?;
								continue;
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

								let from = crate::dmarc::from_domain(&message.data);
								let dmarc = match &from {
									Some(from) => {
										crate::dmarc::evaluate(
											dns.as_ref(),
											from,
											(outcome, domain.as_deref()),
											&dkim_results,
										)
										.await
									}
									// No usable From header: nothing to align.
									None => crate::dmarc::DmarcOutcome::PermError,
								};
								// Record DMARC result for aggregate reporting.
								if let (Some(report_data_dir), Some(from_domain)) =
									(&self.report_dir, &from)
								{
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
									let today =
										crate::dmarc::aggregate::unix_to_day(record.timestamp);
									crate::dmarc::aggregate::record_delivery(
										report_data_dir,
										&today,
										&record,
									);
								}

								match dmarc {
									crate::dmarc::DmarcOutcome::Reject => {
										self.metrics.rejected(crate::metrics::RejectReason::Dmarc);
										self.train_corpus(&message.data, true);
										send(
											&mut stream,
											&Reply::single(550, "5.7.1 rejected by DMARC policy"),
										)
										.await?;
										continue;
									}
									crate::dmarc::DmarcOutcome::TempError => {
										send(
											&mut stream,
											&Reply::single(
												451,
												"4.4.3 DMARC check temporarily failed",
											),
										)
										.await?;
										continue;
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

								auth_headers
									.push_str(&format_auth_results(&self.hostname, &methods));

								// ARC: seal this hop so downstream forwarders can
								// trust our authentication results even if they
								// break SPF/DKIM. cv reflects any inbound chain.
								if let Some(sealer) = &self.arc_sealer {
									let cv =
										crate::arc::validate::validate(dns.as_ref(), &message.data)
											.await;
									let prior = crate::arc::chain::extract(&message.data)
										.ok()
										.flatten()
										.unwrap_or_default();
									let summary = methods.join("; ");
									if let Some(arc_headers) =
										sealer.seal(&message.data, &summary, &prior, cv)
									{
										auth_headers.push_str(&arc_headers);
									}
								}
							}
						}
					}
					let header = received_header(
						session.helo_domain(),
						peer,
						&self.hostname,
						session.esmtp(),
						session.tls_active(),
						session.authenticated().is_some(),
						std::time::SystemTime::now(),
					);
					let mut stamped = header.into_bytes();
					stamped.extend_from_slice(auth_headers.as_bytes());
					stamped.append(&mut message.data);
					message.data = stamped;
					let rep_domain = message
						.reverse_path
						.rsplit_once('@')
						.map(|(_, d)| d.to_ascii_lowercase());
					// Reputation screen for unauthenticated senders: reject a
					// poor reputation, slow down a first-time sender.
					if let (Some(pool), Some(domain), None) = (
						&self.reputation,
						rep_domain.as_deref(),
						session.authenticated(),
					) {
						use crate::antispam::reputation::{Scope, Screen, screen};
						match screen(pool, Scope::Domain, domain).await {
							Screen::Reject => {
								// Quarantine rather than hard-reject: poor reputation
								// is a heuristic, so keep the mail recoverable in the
								// Rejects mailbox instead of losing it.
								tracing::info!(%domain, "quarantining poor-reputation sender to Rejects");
								self.train_corpus(&message.data, true);
								self.metrics.quarantined();
								message.mailbox = Some("Rejects".to_string());
							}
							Screen::FirstTime if !self.first_time_delay.is_zero() => {
								tokio::time::sleep(self.first_time_delay).await;
							}
							_ => {}
						}
					}
					// External scanner hook (unauthenticated mail only).
					if let (Some(hook), None) = (&self.hook, session.authenticated()) {
						match hook.scan(&message.data).await {
							crate::antispam::hook::HookVerdict::Reject => {
								self.metrics.rejected(crate::metrics::RejectReason::Scanner);
								self.train_corpus(&message.data, true);
								send(
									&mut stream,
									&Reply::single(550, "5.7.1 rejected by scanner"),
								)
								.await?;
								continue;
							}
							crate::antispam::hook::HookVerdict::Quarantine => {
								self.metrics.quarantined();
								self.train_corpus(&message.data, true);
								message.mailbox = Some("Rejects".to_string());
							}
							crate::antispam::hook::HookVerdict::Accept => {}
						}
					}
					// Accepted unauthenticated mail trains the ham corpus —
					// unless it was quarantined (already trained as spam).
					if session.authenticated().is_none() && message.mailbox.is_none() {
						self.train_corpus(&message.data, false);
					}
					let reply = match self.sink.deliver(message) {
						Ok(()) => {
							self.metrics.accepted();
							if let (Some(pool), Some(domain), None) =
								(&self.reputation, rep_domain, session.authenticated())
							{
								crate::antispam::reputation::record_in_background(
									pool.clone(),
									crate::antispam::reputation::Scope::Domain,
									domain,
									false,
								);
							}
							reply
						}
						Err(error) => {
							tracing::warn!(%error, "delivery failed");
							Reply::single(451, "4.3.0 temporary storage failure, try again")
						}
					};
					send(&mut stream, &reply).await?;
				}
				Action::UpgradeTls(reply) => {
					let Some(acceptor) = &self.tls else {
						// The session only emits UpgradeTls when TLS was
						// offered; reaching this is a programming error.
						send(&mut stream, &Reply::single(454, "4.7.0 TLS not available")).await?;
						return Ok(());
					};
					send(&mut stream, &reply).await?;
					// Bytes received before the handshake are discarded:
					// a pipelining client cannot smuggle plaintext commands
					// into the TLS session.
					let tls_stream = acceptor.current().accept(stream).await?;
					stream = Box::new(tls_stream);
					session.tls_started();
					decoder = LineDecoder::new();
					send(&mut stream, &session.greeting()).await?;
				}
				Action::Close(reply) => {
					send(&mut stream, &reply).await?;
					return Ok(());
				}
			}
		}
	}
}
