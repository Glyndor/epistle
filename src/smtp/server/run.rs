//! The SMTP connection loop: drives one session from greeting to close.

use std::net::IpAddr;

use tokio::io::AsyncReadExt;

use crate::smtp::line::LineDecoder;
use crate::smtp::reply::Reply;
use crate::smtp::session::{Action, Session};
use crate::smtp::submission_budget::PendingCharge;
use crate::smtp::trace::{
	MAX_HEADER_FIELDS, RECEIVED_HOP_LIMIT, header_field_count, line_error_reply, received_header,
	received_hop_count,
};

use super::data_rate::{Cut, RateWindow, send_within};
use super::session_time::{SessionClock, end_session};
use super::{
	COMMAND_TIMEOUT, Connection, Mode, READ_BUFFER, Server, discard_chunk, end_cut, read_chunk,
	send,
};

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
		// The rate window of the message being received: started at the
		// 354 or at the first BDAT chunk, and kept until the transaction
		// ends, so the time between chunks and the commands sent in it
		// count against the same clock.
		let mut body_window: Option<RateWindow> = None;
		// The lifetime of the session, checked at every command boundary.
		let mut clock = SessionClock::start(self.max_session_time);

		loop {
			let line = match decoder.next_line() {
				Ok(Some(line)) => line,
				Ok(None) => {
					// A drain waits for an open transaction, DATA or AUTH to end.
					let idle = mode == Mode::Commands && !session.in_transaction();
					let drain = self.drain.as_deref().filter(|_| idle);
					// A message being received is held to the rate floor.
					let off = RateWindow::off();
					let window = body_window.as_ref().unwrap_or(&off);
					let reading = window.guard(stream.read(&mut buffer));
					let reading = clock.guard(body_window.is_none(), reading);
					let read = match crate::shutdown::or_drain(drain, COMMAND_TIMEOUT, reading)
						.await
					{
						None => {
							send(&mut stream, &Reply::single(421, "4.3.2 shutting down")).await?;
							return Ok(());
						}
						Some(Ok(Some(Some(Ok(n))))) => n,
						Some(Ok(Some(Some(Err(e))))) => return Err(e),
						Some(Ok(Some(None))) => {
							return end_cut(&mut stream, Cut::TooSlow, session).await;
						}
						Some(Ok(None)) => return end_session(&mut stream, session).await,
						Some(Err(_)) => {
							tracing::debug!("SMTP command timeout, closing connection");
							return Ok(());
						}
					};
					if read == 0 {
						return Ok(());
					}
					if mode == Mode::Data
						&& let Some(window) = body_window.as_mut()
					{
						window.record(read);
					}
					decoder.feed(&buffer[..read]);
					continue;
				}
				Err(error) => {
					send(&mut stream, &line_error_reply(&error)).await?;
					return Ok(());
				}
			};

			// A command or AUTH line past the session's lifetime is not run
			// (QUIT still is: the client is leaving); a message body being
			// received is left to finish.
			if mode != Mode::Data
				&& body_window.is_none()
				&& clock.expired()
				&& !line.eq_ignore_ascii_case(b"QUIT")
			{
				return end_session(&mut stream, session).await;
			}
			// In Data mode, pass raw bytes to support 8BITMIME (RFC 6152).
			let action = 'line: {
				if mode == Mode::Data {
					break 'line session.data_line(&line);
				}
				let Ok(line_str) = String::from_utf8(line) else {
					// A command that is not UTF-8 is refused and counted like
					// any syntax error.
					if mode == Mode::Commands {
						break 'line Some(session.unreadable_command());
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
			let action = loop {
				action = match action {
					// The first chunk starts the window of the transaction.
					Action::CollectChunk { size, last } => {
						let window = body_window.get_or_insert_with(|| self.message_window());
						let read = (size, last);
						match read_chunk(&mut stream, &mut decoder, read, window, &mut session)
							.await?
						{
							Ok(action) => action,
							Err(cut) => return end_cut(&mut stream, cut, session).await,
						}
					}
					// A refused chunk is consumed without being kept.
					Action::DiscardChunk { size, reply } => {
						let window = body_window.get_or_insert_with(|| self.message_window());
						if let Err(cut) =
							discard_chunk(&mut stream, &mut decoder, size, window).await?
						{
							return end_cut(&mut stream, cut, session).await;
						}
						Action::Continue(reply)
					}
					resolved => break resolved,
				};
			};
			// The window ends with the transaction: the dot, the LAST
			// chunk, RSET, or any refusal that resets it.
			if !session.in_transaction() && body_window.take().is_some() {
				clock.body_ended();
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
					// Inside a transaction an unread reply counts as idle time.
					if !send_within(&mut stream, &reply, body_window.as_ref()).await? {
						return Ok(());
					}
				}
				Action::CollectData(reply) => {
					mode = Mode::Data;
					send(&mut stream, &reply).await?;
					body_window = Some(self.message_window());
				}
				// BDAT chunk reads are resolved into a terminal action above.
				Action::CollectChunk { .. } | Action::DiscardChunk { .. } => {
					unreachable!("BDAT chunk resolved before dispatch")
				}
				Action::CollectAuthResponse(reply) => {
					mode = Mode::Auth;
					send(&mut stream, &reply).await?;
				}
				Action::Deliver(reply, mut message) => {
					// The body stays on the memory budget until this arm is
					// over: it is still in memory while it is checked,
					// stamped and handed to the sink.
					let _held_body = session.take_delivery_reservation();
					// DSNs for recipients this message did not fit for; sent
					// only if the message itself is delivered.
					let quota_reports = session.take_quota_reports();
					// The submission-limit charge, refunded on drop by every
					// refusal below and kept only once the message is handed on.
					let mut charge = PendingCharge::new(session.take_submission_charge());
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
					// A message with thousands of header fields has fields a
					// Sieve filter would not read: refused, so none can be
					// hidden from the filters by padding.
					if header_field_count(&message.data) > MAX_HEADER_FIELDS {
						self.metrics
							.rejected(crate::metrics::RejectReason::HeaderFields);
						if crate::util::warn_limited::allow("smtp-header-fields") {
							tracing::warn!("rejecting message: too many header fields");
						}
						send(
							&mut stream,
							&Reply::single(554, "5.6.0 too many header fields in this message"),
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
					let (auth_headers, sender_passed) =
						match self.authenticate_inbound(&message, &session, peer).await {
							Ok(outcome) => outcome,
							Err(reply) => {
								send(&mut stream, &reply).await?;
								continue;
							}
						};
					// Who the server itself verified: a logged-in session, or
					// this hop's SPF or DKIM pass. Never read from the headers.
					message.sender_verified = session.authenticated().is_some() || sender_passed;
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
					// stays the outermost line. The stamp and the Bcc
					// strip work inside the body's own buffer, so the only
					// new body-sized allocation is the stamped one below.
					if session.authenticated().is_some() {
						let stamp_domain = message
							.reverse_path
							.rsplit_once('@')
							.map(|(_, d)| d.to_ascii_lowercase())
							.unwrap_or_else(|| self.hostname.to_ascii_lowercase());
						crate::smtp::trace::ensure_submission_headers_in_place(
							&mut message.data,
							&stamp_domain,
							std::time::SystemTime::now(),
						);
						// The MSA drops Bcc: those recipients are on the envelope.
						crate::smtp::trace::strip_bcc_in_place(&mut message.data);
					}
					// Build the final stamped buffer in one allocation of
					// the exact trace + auth + body length: the body is
					// copied once and its old buffer freed.
					let mut stamped =
						Vec::with_capacity(header.len() + auth_headers.len() + message.data.len());
					stamped.extend_from_slice(header.as_bytes());
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
								self.train_corpus(&message, peer, true);
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
								self.train_corpus(&message, peer, true);
								send(
									&mut stream,
									&Reply::single(550, "5.7.1 rejected by scanner"),
								)
								.await?;
								continue;
							}
							crate::antispam::hook::HookVerdict::Quarantine => {
								self.metrics.quarantined();
								self.train_corpus(&message, peer, true);
								message.mailbox = Some("Rejects".to_string());
							}
							crate::antispam::hook::HookVerdict::Defer => {
								send(
									&mut stream,
									&Reply::single(
										451,
										"4.7.1 content scan unavailable, try again later",
									),
								)
								.await?;
								continue;
							}
							crate::antispam::hook::HookVerdict::Refuse => {
								send(
									&mut stream,
									&crate::smtp::sink::SinkError::ScanTooLarge.smtp_reply(),
								)
								.await?;
								continue;
							}
							crate::antispam::hook::HookVerdict::Accept => {}
						}
					}
					// The attachment policy decides where the scanner does.
					if session.authenticated().is_none()
						&& self
							.screen_attachments(&mut message, &mut stream, peer)
							.await?
					{
						continue;
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
							peer,
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
						self.train_corpus(&message, peer, false);
					}
					// Mail an account submits goes through the submission
					// path, which applies what holds for our own senders
					// (the antivirus on outbound mail among them).
					let mut dropped = 0usize;
					let handed = match session.authenticated() {
						Some(account) => {
							// The class: from the credential and the
							// account, never from the message, and with
							// the marketing rules applied.
							let prepared =
								match self.prepare_submission(&session, account, &mut message) {
									Ok(prepared) => prepared,
									Err(refused) => {
										send(&mut stream, &refused).await?;
										continue;
									}
								};
							// Marketing mail to suppressed addresses only has
							// nowhere to go: say so, as the API does.
							if message.recipients.is_empty() {
								send(
									&mut stream,
									&Reply::single(
										550,
										"5.7.1 every recipient is on the suppression list",
									),
								)
								.await?;
								continue;
							}
							dropped = prepared.suppressed.len();
							// Per-account settings may disable the save
							// (`save_sent: false` on the account, on the
							// app password that authenticated this
							// session, or both). The default for both
							// is "on"; the app password overrides the
							// account when it sets a value. The copy is
							// taken from `message.data` after the Bcc
							// strip, so it never names a blind-carbon
							// copy recipient (RFC 5322 §3.6.3). It is stored
							// only once the sink accepted the message: one the
							// scan or the attachment policy refused, or asked
							// to retry, was never sent. Transactional mail is
							// never copied to Sent.
							let sent_copy = (prepared.class.allows_sent_copy()
								&& self.save_sent_enabled_for(&session))
							.then(|| message.data.clone());
							let submitted = self.sink.submit(
								message,
								uuid::Uuid::now_v7(),
								account,
								&crate::smtp::sink::Submission::of_class(prepared.class),
							);
							if let (Ok(()), Some(copy)) = (&submitted, sent_copy) {
								self.save_sent_copy(&session, account, &copy);
							}
							submitted
						}
						None => self.sink.deliver(message),
					};
					let reply = match handed {
						Ok(()) => {
							charge.accept();
							session.message_delivered();
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
							match dropped {
								0 => reply,
								n => Reply::single(
									250,
									&format!(
										"2.0.0 queued; {n} suppressed recipient{} dropped",
										if n == 1 { "" } else { "s" }
									),
								),
							}
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
