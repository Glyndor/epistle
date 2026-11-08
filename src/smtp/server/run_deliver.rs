//! The end of a message: everything between the final dot (or the last BDAT
//! chunk) and the reply that accepts or refuses it. Split from `run.rs` to
//! keep the connection loop under the code-line limit.

use std::net::IpAddr;

use crate::smtp::reply::Reply;
use crate::smtp::session::{AcceptedMessage, Session};
use crate::smtp::submission_budget::PendingCharge;
use crate::smtp::trace::{
	RECEIVED_HOP_LIMIT, received_header, received_hop_count, refuse_padded_headers,
};

use super::{Connection, Server, send};

impl Server {
	/// Screen, stamp and hand on one received message, then send the reply
	/// for it. Every refusal sends its own reply and returns `Ok(())`: the
	/// session goes on to the next command.
	pub(super) async fn deliver(
		&self,
		stream: &mut Box<dyn Connection>,
		session: &mut Session,
		peer: Option<IpAddr>,
		reply: Reply,
		mut message: AcceptedMessage,
	) -> std::io::Result<()> {
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
				stream,
				&Reply::single(554, "5.4.6 too many hops, this message is looping"),
			)
			.await?;
			return Ok(());
		}
		// A message with thousands of header fields has fields a
		// Sieve filter would not read: refused, so none can be
		// hidden from the filters by padding.
		if let Err(refused) = refuse_padded_headers(&message.data, Some(&self.metrics)) {
			send(stream, &refused.smtp_reply()).await?;
			return Ok(());
		}
		// DNSBL screening: reject an unauthenticated client whose
		// IP, envelope sender domain, or URL host in the body is
		// listed. All three lists fail open on `Unavailable`, so a
		// misconfigured resolver does not block delivery.
		if let Some(rejection) = self.screen_dnsbl(peer, &message, session).await {
			send(stream, &rejection.reply()).await?;
			return Ok(());
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
			if crate::antispam::greylist::decide(store.as_ref(), &triplet, now, *delay).await
				== crate::antispam::greylist::Decision::Defer
			{
				tracing::info!(%ip, "greylisting: deferring first attempt");
				send(
					stream,
					&Reply::single(451, "4.7.1 greylisted, please retry shortly"),
				)
				.await?;
				return Ok(());
			}
		}
		// SPF and DKIM apply to unauthenticated mail from a
		// known peer.
		let (auth_headers, sender_passed) =
			match self.authenticate_inbound(&message, session, peer).await {
				Ok(outcome) => outcome,
				Err(reply) => {
					send(stream, &reply).await?;
					return Ok(());
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
			message.tlsrpt_verified = crate::dkim::verify_tlsrpt(dns.as_ref(), &message.data).await;
		}
		// Verify signatures first, then remove outside authority before
		// adding our own fields or handing the message to filters.
		if session.authenticated().is_none() {
			self.strip_inbound(&mut message.data);
			// Defence in depth: re-parse the header section with
			// the same parser downstream readers use, and refuse
			// the message if any reserved field strip missed.
			// A line whose name mail-parser folds but the
			// stripper does not would otherwise survive as a
			// forged trust header; the safety net turns every
			// such leak into a permanent refusal. One extra
			// linear pass over the header section only.
			if let Some(leak) =
				crate::smtp::inbound_headers::reserved_remaining(&message.data, &self.hostname)
			{
				tracing::warn!(
					name = %leak,
					"refusing inbound: trust field survived strip"
				);
				send(
					stream,
					&Reply::single(
						550,
						"5.7.1 trust field could not be removed before delivery",
					),
				)
				.await?;
				return Ok(());
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
		// Authenticated submission: stamp Message-ID and Date
		// when the client omitted them. Domain is the
		// reverse-path's domain (the authenticated account's own
		// domain), with the server hostname as a last resort.
		// Done before the Received block so the trace header
		// stays the outermost line. The stamp and the Bcc
		// strip work inside the body's own buffer, so the only
		// new body-sized allocation is the stamped one below.
		if session.authenticated().is_some() {
			Self::stamp_submission(&mut message, &self.hostname);
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
					if !self.first_time_delay.is_zero() && known_correspondent.is_none() =>
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
					send(stream, &Reply::single(550, "5.7.1 rejected by scanner")).await?;
					return Ok(());
				}
				crate::antispam::hook::HookVerdict::Quarantine => {
					self.metrics.quarantined();
					self.train_corpus(&message, peer, true);
					message.mailbox = Some("Rejects".to_string());
				}
				crate::antispam::hook::HookVerdict::Defer => {
					send(
						stream,
						&Reply::single(451, "4.7.1 content scan unavailable, try again later"),
					)
					.await?;
					return Ok(());
				}
				crate::antispam::hook::HookVerdict::Refuse => {
					send(
						stream,
						&crate::smtp::sink::SinkError::ScanTooLarge.smtp_reply(),
					)
					.await?;
					return Ok(());
				}
				crate::antispam::hook::HookVerdict::Accept => {}
			}
		}
		// The attachment policy decides where the scanner does.
		if session.authenticated().is_none()
			&& self.screen_attachments(&mut message, stream, peer).await?
		{
			return Ok(());
		}
		// Bayesian thresholds that decide on their own: a score at or above
		// `bayes_junk_at` routes to Junk with the spam-marking
		// headers stamped on it; a score at or above
		// `bayes_reject_at` (when configured) refuses the DATA
		// phase with `550 5.7.1`. Runs before the uncertain band
		// so a high-confidence verdict never burns an LLM call.
		match self
			.handle_bayes_thresholds(&mut message, session.authenticated().is_some(), stream)
			.await?
		{
			super::run_band::BayesOutcome::Rejected => return Ok(()),
			super::run_band::BayesOutcome::SendToJunk | super::run_band::BayesOutcome::Continue => {
			}
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
				stream
			)
			.await?,
			super::run_band::BandOutcome::Challenged
		) {
			return Ok(());
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
		// What the line about the acceptance carries is taken
		// where the message is handed to the sink: the sink
		// takes it and it cannot be read again, and the
		// submission path may have changed it before that.
		let (handed, accepted) = match session.authenticated() {
			Some(account) => {
				// The class: from the credential and the
				// account, never from the message, and with
				// the marketing rules applied.
				let prepared = match self.prepare_submission(session, account, &mut message) {
					Ok(prepared) => prepared,
					Err(refused) => {
						send(stream, &refused).await?;
						return Ok(());
					}
				};
				// Marketing mail to suppressed addresses only has
				// nowhere to go: say so, as the API does.
				if message.recipients.is_empty() {
					send(
						stream,
						&Reply::single(550, "5.7.1 every recipient is on the suppression list"),
					)
					.await?;
					return Ok(());
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
					&& self.save_sent_enabled_for(session))
				.then(|| message.data.clone());
				let accepted = self.accepted_record(&message);
				let submitted = self.sink.submit(
					message,
					uuid::Uuid::now_v7(),
					account,
					&crate::smtp::sink::Submission::of_class(prepared.class),
				);
				if let (Ok(()), Some(copy)) = (&submitted, sent_copy) {
					self.save_sent_copy(session, account, &copy);
				}
				(submitted, accepted)
			}
			None => {
				let accepted = self.accepted_record(&message);
				(self.sink.deliver(message), accepted)
			}
		};
		let reply = match handed {
			Ok(()) => {
				charge.accept();
				session.message_delivered();
				self.metrics.accepted();
				// The message is accepted: the one line
				// that says so at the default level.
				crate::smtp::session_log::accepted(&accepted);
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
				if error.is_storage_fault() {
					tracing::warn!(%error, "delivery failed");
				}
				error.smtp_reply()
			}
		};
		send(stream, &reply).await?;
		Ok(())
	}
}
