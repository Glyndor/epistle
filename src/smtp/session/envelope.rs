//! Greeting, STARTTLS and the mail envelope: `HELO`/`EHLO`, `MAIL FROM`,
//! `RCPT TO` and `RSET`.

use super::types::State;
use super::{Action, Address, Reply, Reservation, Resolution, Session, finalise, unix_now};

impl Session {
	/// The greeting sent when the connection opens.
	pub fn greeting(&self) -> Reply {
		Reply::single(220, &format!("{} ESMTP ready", self.hostname))
	}

	pub(super) fn greet(&mut self, domain: String, esmtp: bool) -> Action {
		self.state = State::Greeted;
		self.helo_domain = Some(domain);
		self.esmtp = esmtp;
		// Plain HELO (RFC 5321 §4.1.1.1) gets a single-line greeting with no
		// ESMTP extensions; only EHLO advertises capabilities.
		if !esmtp {
			return Action::Continue(Reply::single(250, &self.hostname));
		}
		let size = self.max_message_size;
		let mut lines = vec![
			self.hostname.clone(),
			"PIPELINING".to_string(),
			"ENHANCEDSTATUSCODES".to_string(),
			"8BITMIME".to_string(),
			"SMTPUTF8".to_string(), // RFC 6531: internationalized addresses.
			"CHUNKING".to_string(), // RFC 3030: BDAT length-prefixed message data.
			// RFC 3461: we parse RET/ENVID and NOTIFY/ORCPT parameters.
			"DSN".to_string(),
			format!("SIZE {size}"),
			// RFC 9422: advertise the per-message recipient ceiling we enforce.
			format!("LIMITS RCPTMAX={cap}", cap = self.max_recipients),
		];
		if self.tls_available {
			lines.push("STARTTLS".to_string());
		}
		if self.tls_active && self.authenticated.is_none() {
			lines.push(self.auth_capability());
		}
		// RFC 8689 §3: only advertise REQUIRETLS on a TLS-protected session.
		if self.tls_active {
			lines.push("REQUIRETLS".to_string());
		}
		Action::Continue(Reply::new(250, lines))
	}

	pub(super) fn start_tls(&mut self) -> Action {
		if !self.tls_available {
			return Action::Continue(Reply::single(454, "4.7.0 TLS not available"));
		}
		match self.state {
			// RFC 3207: STARTTLS requires EHLO first and no open transaction.
			State::Greeted => Action::UpgradeTls(Reply::single(220, "ready to start TLS")),
			_ => Action::Continue(Reply::bad_sequence()),
		}
	}

	pub(super) fn mail_from(
		&mut self,
		reverse_path: String,
		size: Option<u64>,
		require_tls: bool,
	) -> Action {
		match self.state {
			State::Greeted => {
				// RFC 8689 §4.2: REQUIRETLS is only valid once the current
				// hop is already TLS-protected; otherwise the requirement is
				// already violated. Fail closed.
				if require_tls && !self.tls_active {
					return Action::Continue(Reply::single(
						530,
						"5.7.4 REQUIRETLS requires the session to use TLS",
					));
				}
				match (&self.authenticated, Address::parse(&reverse_path)) {
					// Authenticated senders must use one of their own
					// addresses — no spoofing, no null path.
					(Some(account), Ok(address))
						if !self.directory.owns_address(account, &address) =>
					{
						return Action::Continue(Reply::single(
							553,
							"5.7.1 sender address not owned by authenticated user",
						));
					}
					(Some(_), Err(_)) => {
						return Action::Continue(Reply::single(553, "5.1.7 invalid reverse-path"));
					}
					// The null reverse-path (bounces) is legal when
					// unauthenticated; anything else must parse.
					(None, Err(_)) if !reverse_path.is_empty() => {
						return Action::Continue(Reply::single(553, "5.1.7 invalid reverse-path"));
					}
					_ => {}
				}
				// Submission rate limits for authenticated senders: the
				// per-account limit (its domain's override, else the
				// server-wide default) and the tenant aggregate. Nothing is
				// charged here: a sender with no room left is refused before
				// it sends the message, and the message is charged one unit
				// per recipient once it is accepted (`finalise`), so a
				// transaction that ends in RSET or a refusal costs nothing.
				if let Some(account) = self.authenticated.as_deref()
					&& !self
						.policy
						.submission_budget(account, &self.directory)
						.has_room(unix_now())
				{
					return Action::Continue(finalise::rate_limited());
				}
				// Per-IP and per-sender rate limits for unauthenticated sessions.
				// Authenticated sessions are charged against the per-account limiter
				// instead; mixing both for the same envelope would double-charge the
				// authenticated sender's budget.
				if self.authenticated.is_none()
					&& let Some(reply) =
						self.policy
							.check_inbound(&reverse_path, self.peer_ip, unix_now())
				{
					if let Some(metrics) = &self.metrics {
						metrics.rejected(crate::metrics::RejectReason::RateLimit);
					}
					return Action::Continue(reply);
				}
				// SIZE is declared up front: reject oversize without DATA.
				if size.is_some_and(|s| s > self.max_message_size as u64) {
					return Action::Continue(Reply::single(
						552,
						"5.3.4 message exceeds maximum size",
					));
				}
				// Filesystem holding `data_dir` is too full to accept another
				// message. Reject before `DATA` so the remote retries instead
				// of receiving `250 OK` for a payload the spool cannot hold.
				if !self.policy.spool_has_room(self.max_message_size as u64) {
					return Action::Continue(Reply::single(
						452,
						"4.3.1 insufficient system storage; retry later",
					));
				}
				self.state = State::ReceivingRecipients {
					reverse_path,
					require_tls,
				};
				Action::Continue(Reply::ok())
			}
			_ => Action::Continue(Reply::bad_sequence()),
		}
	}

	pub(super) fn rcpt_to(
		&mut self,
		forward_path: String,
		notify: Option<crate::smtp::command::Notify>,
	) -> Action {
		// The order is checked before the address is even looked at (RFC
		// 5321 §4.1.4), so a RCPT out of sequence learns nothing about
		// whether a mailbox exists or is full.
		let open = match &self.state {
			State::ReceivingRecipients { .. } => true,
			State::ReceivingData { body, chunking, .. } => body.is_empty() && !*chunking,
			_ => false,
		};
		if !open {
			return Action::Continue(Reply::bad_sequence());
		}
		let Ok(address) = Address::parse(&forward_path) else {
			return Action::Continue(Reply::single(553, "5.1.3 invalid recipient address"));
		};
		match self.directory.resolve(&address) {
			// Foreign domains are relayed only for authenticated users.
			Resolution::NotLocal => {
				if self.authenticated.is_none() {
					return Action::Continue(Reply::single(550, "5.7.1 relaying denied"));
				}
			}
			Resolution::UnknownUser => {
				return Action::Continue(Reply::single(550, "5.1.1 no such user"));
			}
			// A full mailbox refuses this recipient only, temporarily: the
			// owner may make room (RFC 3463 X.2.2).
			Resolution::Account(account)
				if self
					.policy
					.quota()
					.is_some_and(|quota| quota.is_full(&self.directory, &account)) =>
			{
				return Action::Continue(Reply::single(452, "4.2.2 mailbox full"));
			}
			// A local account or a multi-target alias is an acceptable recipient.
			Resolution::Account(_) | Resolution::Alias(_) => {}
		}
		let forward_path = address.to_string();
		// Suppress failure DSNs for NOTIFY=NEVER or a NOTIFY without FAILURE (RFC 3461).
		use crate::smtp::command::Notify;
		let suppresses_dsn = matches!(
			notify,
			Some(Notify::Never | Notify::On { failure: false, .. })
		);
		match &mut self.state {
			State::ReceivingRecipients {
				reverse_path,
				require_tls,
			} => {
				let reverse_path = reverse_path.clone();
				let require_tls = *require_tls;
				let no_dsn = if suppresses_dsn {
					vec![forward_path.clone()]
				} else {
					Vec::new()
				};
				self.state = State::ReceivingData {
					reverse_path,
					recipients: vec![forward_path],
					no_dsn,
					size: 0,
					body: Vec::new(),
					require_tls,
					chunking: false,
					line_check: crate::smtp::line::LineCheck::stored(),
					reserved: Reservation::none(),
					budget_exhausted: false,
				};
				Action::Continue(Reply::ok())
			}
			// More recipients are accepted only before message data starts; once
			// a BDAT chunk has begun (RFC 3030) RCPT is no longer valid.
			State::ReceivingData {
				recipients,
				no_dsn,
				body,
				chunking,
				..
			} if body.is_empty() && !*chunking => {
				if recipients.len() >= self.max_recipients {
					return Action::Continue(Reply::single(452, "4.5.3 too many recipients"));
				}
				if suppresses_dsn {
					no_dsn.push(forward_path.clone());
				}
				recipients.push(forward_path);
				Action::Continue(Reply::ok())
			}
			_ => Action::Continue(Reply::bad_sequence()),
		}
	}

	/// Drop any in-progress transaction, keeping the greeting. The body
	/// and any announced chunk are dropped with it, and so is their claim
	/// on the memory budget.
	pub(super) fn reset(&mut self) {
		self.chunk_reservation = Reservation::none();
		if self.state != State::Connected {
			self.state = State::Greeted;
		}
	}
}
