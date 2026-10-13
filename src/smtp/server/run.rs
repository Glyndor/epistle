//! The SMTP connection loop: drives one session from greeting to close.

use std::net::IpAddr;

use tokio::io::AsyncReadExt;

use crate::smtp::line::LineDecoder;
use crate::smtp::reply::Reply;
use crate::smtp::session::{Action, Session};
use crate::smtp::trace::{
	RECEIVED_HOP_LIMIT, ensure_submission_headers, line_error_reply, received_header,
	received_hop_count,
};

use super::{COMMAND_TIMEOUT, Connection, Mode, READ_BUFFER, Server, read_chunk, send};

/// Consecutive error replies before the connection is dropped (abuse guard,
/// akin to Postfix's `smtpd_hard_error_limit`).
const MAX_ERROR_STREAK: u32 = 20;

impl Server {
	/// The protocol loop over an established (plain or TLS) stream.
	pub(super) async fn run(
		&self,
		mut stream: Box<dyn Connection>,
		mut session: Session,
		peer: Option<IpAddr>,
	) -> std::io::Result<()> {
		// App-password CIDR allowlists are checked against the peer IP.
		session.set_peer_ip(peer);
		self.metrics.connection();
		send(&mut stream, &session.greeting()).await?;

		let mut decoder = LineDecoder::new();
		let mut mode = Mode::Commands;
		let mut buffer = [0u8; READ_BUFFER];
		// Consecutive error replies; too many means an abusive client.
		let mut error_streak = 0u32;

		loop {
			let line = match decoder.next_line() {
				Ok(Some(line)) => line,
				Ok(None) => {
					// A drain waits for an open transaction, DATA or AUTH to end.
					let idle = mode == Mode::Commands && !session.in_transaction();
					let drain = self.drain.as_deref().filter(|_| idle);
					let reading = stream.read(&mut buffer);
					let read = match crate::shutdown::or_drain(drain, COMMAND_TIMEOUT, reading)
						.await
					{
						None => {
							send(&mut stream, &Reply::single(421, "4.3.2 shutting down")).await?;
							return Ok(());
						}
						Some(Ok(Ok(n))) => n,
						Some(Ok(Err(e))) => return Err(e),
						Some(Err(_)) => {
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
			let Some(mut action) = action else {
				continue;
			};

			mode = Mode::Commands;
			// Resolve BDAT chunk reads (RFC 3030) into a terminal action that the
			// dispatch below already handles (Continue for a non-final chunk,
			// Deliver for the LAST chunk — so the full delivery path still runs).
			while let Action::CollectChunk { size, last } = action {
				let chunk = match read_chunk(&mut stream, &mut decoder, size).await {
					Ok(Some(chunk)) => chunk,
					Ok(None) => return Ok(()), // client closed mid-chunk
					Err(error) => return Err(error),
				};
				action = session.bdat_chunk(&chunk, last);
			}
			match action {
				Action::Continue(reply) => {
					// Abuse guard: disconnect a client that only produces errors.
					if reply.code() >= 400 {
						error_streak += 1;
						if error_streak >= MAX_ERROR_STREAK {
							self.metrics.abuse_dropped();
							send(
								&mut stream,
								&Reply::single(421, "4.7.0 too many errors, closing connection"),
							)
							.await?;
							return Ok(());
						}
					} else {
						error_streak = 0;
					}
					send(&mut stream, &reply).await?;
				}
				Action::CollectData(reply) => {
					mode = Mode::Data;
					send(&mut stream, &reply).await?;
				}
				// BDAT chunk reads are resolved into a terminal action above.
				Action::CollectChunk { .. } => unreachable!("BDAT chunk resolved before dispatch"),
				Action::CollectAuthResponse(reply) => {
					mode = Mode::Auth;
					send(&mut stream, &reply).await?;
				}
				Action::Deliver(reply, mut message) => {
					// DSNs for recipients this message did not fit for; sent
					// only if the message itself is delivered.
					let quota_reports = session.take_quota_reports();
					// Loop guard: reject mail that has already traversed too many
					// hops before adding our own Received header (RFC 5321 §6.3).
					if received_hop_count(&message.data) >= RECEIVED_HOP_LIMIT {
						tracing::warn!("rejecting message: too many Received hops (mail loop)");
						self.metrics.rejected(crate::metrics::RejectReason::Loop);
						send(
							&mut stream,
							&Reply::single(554, "5.4.6 too many hops, this message is looping"),
						)
						.await?;
						continue;
					}
					// DNSBL screening: reject an unauthenticated client whose
					// IP, envelope sender domain, or URL host in the body is
					// listed. All three lists fail open on `Unavailable`, so a
					// misconfigured resolver does not block delivery.
					if let Some(rejection) = self.screen_dnsbl(peer, &message, &session).await {
						send(&mut stream, &rejection.reply()).await?;
						continue;
					}
					// Trusted-reply fast path (plan 4.6): when the envelope
					// sender is known to any local recipient account, skip
					// greylisting and the reputation first-time delay. The
					// rest of the inbound stack still runs because a known
					// correspondent's account can itself be compromised:
					// DNSBL above, SPF/DKIM/DMARC below, the scanner and the
					// LLM band. Resolution reuses `Directory::resolve` so a
					// domain alias or a multi-target alias applies
					// identically to how the recipient was admitted.
					let known_correspondent = self.known_correspondent(&message);
					if let Some((account, sender)) = known_correspondent.as_ref() {
						tracing::debug!(
							account = %crate::log_id::account(account),
							sender = %sender,
							"trusted reply: skipping greylist and first-time delay"
						);
					}
					// Greylisting: defer an unseen triplet's first attempt. A real
					// MTA retries and is then accepted. The store is the
					// in-memory one by default and the PostgreSQL-backed one
					// when `[database]` is configured, so a restart does not
					// re-defer legitimate senders when persistence is enabled.
					if known_correspondent.is_none()
						&& let (Some((store, delay)), Some(ip), None) =
							(&self.greylist, peer, session.authenticated())
						&& let Some(recipient) = message.recipients.first()
					{
						let now = std::time::SystemTime::now()
							.duration_since(std::time::UNIX_EPOCH)
							.map(|d| d.as_secs())
							.unwrap_or(0);
						let triplet = crate::antispam::greylist::Triplet {
							client_ip: ip,
							sender: &message.reverse_path,
							recipient,
						};
						if crate::antispam::greylist::decide(store.as_ref(), &triplet, now, *delay)
							.await == crate::antispam::greylist::Decision::Defer
						{
							tracing::info!(%ip, "greylisting: deferring first attempt");
							send(
								&mut stream,
								&Reply::single(451, "4.7.1 greylisted, please retry shortly"),
							)
							.await?;
							continue;
						}
					}
					// SPF and DKIM apply to unauthenticated mail from a
					// known peer.
					let auth_headers =
						match self.authenticate_inbound(&message, &session, peer).await {
							Ok(headers) => headers,
							Err(reply) => {
								send(&mut stream, &reply).await?;
								continue;
							}
						};
					if let Some(dns) = &self.spf
						&& message.recipients.iter().any(|recipient| {
							recipient
								.split_once('@')
								.is_some_and(|(local, _)| local.eq_ignore_ascii_case("tlsrpt"))
						}) {
						message.tlsrpt_verified =
							crate::dkim::verify_tlsrpt(dns.as_ref(), &message.data).await;
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
					// Authenticated submission: stamp Message-ID and Date
					// when the client omitted them. Domain is the
					// reverse-path's domain (the authenticated account's own
					// domain), with the server hostname as a last resort.
					// Done before the Received block so the trace header
					// stays the outermost line.
					if session.authenticated().is_some() {
						let stamp_domain = message
							.reverse_path
							.rsplit_once('@')
							.map(|(_, d)| d.to_ascii_lowercase())
							.unwrap_or_else(|| self.hostname.to_ascii_lowercase());
						message.data = ensure_submission_headers(
							&message.data,
							&stamp_domain,
							std::time::SystemTime::now(),
						);
						// The MSA drops Bcc: those recipients are on the envelope.
						message.data = crate::smtp::trace::strip_bcc(&message.data);
					}
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
					// The slow path (`FirstTime` -> sleep) is skipped when
					// the sender is a known correspondent: a real reply
					// from a recipient account's history does not warrant
					// the reputation-system's first-attempt penalty. The
					// hard `Reject` branch is still honoured; a poor
					// reputation is independent of whether the sender is
					// known to a local account.
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
							Screen::FirstTime
								if !self.first_time_delay.is_zero()
									&& known_correspondent.is_none() =>
							{
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
					// Bayesian thresholds that decide on their own: a score at or above
					// `bayes_junk_at` routes to Junk with the spam-marking
					// headers stamped on it; a score at or above
					// `bayes_reject_at` (when configured) refuses the DATA
					// phase with `550 5.7.1`. Runs before the uncertain band
					// so a high-confidence verdict never burns an LLM call.
					match self
						.handle_bayes_thresholds(
							&mut message,
							session.authenticated().is_some(),
							&mut stream,
						)
						.await?
					{
						super::run_band::BayesOutcome::Rejected => continue,
						super::run_band::BayesOutcome::SendToJunk
						| super::run_band::BayesOutcome::Continue => {}
					}
					// Uncertain-band logic: SubjectPass (if enabled) accepts
					// the retry that carries a valid token in the subject,
					// otherwise the band consults the LLM hook if one is
					// configured, otherwise (no LLM verdict) it refuses with
					// a 550 5.7.1 challenge and a fresh token. The check runs
					// after DNSBL, SPF, DMARC and the scanner hook, so a
					// valid token never overrides a hard rejection. The
					// Bayes path has already set the message's mailbox when
					// it decided, so the band's "stay out of an upstream
					// decision" guard skips it naturally.
					if matches!(
						self.handle_uncertain_band(
							&mut message,
							session.authenticated().is_some(),
							&mut stream
						)
						.await?,
						super::run_band::BandOutcome::Challenged
					) {
						continue;
					}

					// Accepted unauthenticated mail trains the ham corpus —
					// unless it was quarantined (already trained as spam).
					if session.authenticated().is_none() && message.mailbox.is_none() {
						self.train_corpus(&message.data, false);
					}
					// Mail an account submits goes through the submission
					// path, which applies what holds for our own senders
					// (the antivirus on outbound mail among them).
					let handed = match session.authenticated() {
						Some(account) => {
							// Per-account settings may disable the save
							// (`save_sent: false` on the account, on the
							// app password that authenticated this
							// session, or both). The default for both
							// is "on"; the app password overrides the
							// account when it sets a value. The copy is
							// taken from `message.data` after the Bcc
							// strip, so it never names a blind-carbon
							// copy recipient (RFC 5322 §3.6.3).
							if self.save_sent_enabled_for(&session) {
								self.save_sent_copy(
									&session,
									account,
									&message.data,
								);
							}
							self.sink.submit(message, uuid::Uuid::now_v7(), account)
						}
						None => self.sink.deliver(message),
					};
					let reply = match handed {
						Ok(()) => {
							self.metrics.accepted();
							for report in quota_reports {
								if let Err(error) = self.sink.deliver(report) {
									tracing::warn!(%error, "mailbox-full report not delivered");
								}
							}
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
							if matches!(error, crate::smtp::sink::SinkError::Unavailable(_)) {
								tracing::warn!(%error, "delivery failed");
							}
							error.smtp_reply()
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
					let tls_stream = crate::tls::accept_within(&acceptor.current(), stream).await?;
					// A verified client certificate enables SASL EXTERNAL.
					let identity = tls_stream
						.get_ref()
						.1
						.peer_certificates()
						.and_then(|certs| certs.first())
						.and_then(|cert| crate::tls::identity_from_cert(cert.as_ref()));
					session.set_client_identity(identity);
					stream = Box::new(tls_stream);
					session.tls_started();
					decoder = LineDecoder::new();
					// No greeting inside TLS (RFC 3207 section 4.2): the
					// session is back in the state after the 220 banner and
					// the client speaks first with EHLO. A banner here is read
					// as the reply to that EHLO and shifts every later reply.
				}
				Action::Close(reply) => {
					send(&mut stream, &reply).await?;
					return Ok(());
				}
			}
		}
	}
}

impl Server {
	/// Whether a copy of the message this session is about to submit
	/// should be stored into the account's `Sent` folder. The
	/// precedence is the one the brief lays down: the app password
	/// that authenticated the session overrides the account-wide
	/// setting when it carries an explicit value, otherwise the
	/// account-wide setting decides (default "on" when absent).
	pub(super) fn save_sent_enabled_for(&self, session: &crate::smtp::session::Session) -> bool {
		let Some(account) = session.authenticated() else {
			return false;
		};
		let directory = self.directory.current();
		// App password override first: an explicit `Some(false)` here
		// disables the save even if the account has it on.
		if let Some(label) = session.auth_app_password_label()
			&& let Some(value) = directory.app_password_save_sent(account, Some(label))
		{
			return value;
		}
		directory.save_sent_for(account).unwrap_or(true)
	}

	/// Store one copy of `data` into the account's `Sent` folder. The
	/// copy carries the `\Seen` flag and never includes a `Bcc:`
	/// header (the SMTP path strips Bcc before this is called). A
	/// quota-exhausted mailbox or any other filesystem error is
	/// logged and ignored: the message the client sent must still
	/// leave the server. The duplicate-guard call uses the
	/// `Message-ID:` the server stamped on the message when the
	/// client omitted one.
	pub(super) fn save_sent_copy(
		&self,
		session: &crate::smtp::session::Session,
		account: &str,
		data: &[u8],
	) {
		let Some(data_dir) = self.data_dir.as_ref() else {
			return;
		};
		let message_id = match crate::storage::save_sent::first_message_id(data) {
			Some(id) => id,
			None => {
				tracing::warn!(
					account = %crate::log_id::account(account),
					"save_sent: message has no Message-ID after stamping; skipping copy"
				);
				return;
			}
		};
		// Reverse dedup: if the client appended first, a message with
		// this Message-ID already lives in Sent; the guard does not
		// know about it yet, but the on-disk scan does. Skip the save
		// so we do not produce a duplicate copy. The IMAP APPEND
		// fast path uses the same guard and skips its own copy when
		// the guard says the server already saved.
		if let Ok(Some(_existing)) = crate::storage::save_sent::lookup_sent_uid(data_dir, account, &message_id)
		{
			tracing::debug!(
				account = %crate::log_id::account(account),
				"save_sent: Message-ID already in Sent; skipping server-side copy"
			);
			return;
		}
		let crypto = self
			.crypto
			.as_deref()
			.cloned()
			.unwrap_or_else(crate::storage::MessageCrypto::disabled);
		match crate::storage::save_sent::store_copy(data_dir, account, data, &message_id, &crypto) {
			Ok(_uid) => {
				tracing::debug!(
					account = %crate::log_id::account(account),
					"save_sent: stored a copy in Sent"
				);
			}
			Err(error) => {
				tracing::warn!(
					account = %crate::log_id::account(account),
					%error,
					"save_sent: could not store the copy; the message is still sent"
				);
			}
		}
		// The session is unused now (the message ID was already extracted)
		// but keep the parameter so the call site documents who owns
		// the audit log line.
		let _ = session;
	}
}
