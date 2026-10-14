//! One SMTP conversation with the exchanger (or smarthost) of one recipient
//! domain, and the answer it gives for each recipient.

use super::Worker;
use super::attempt::{Route, Session};
use crate::queue::client::{DeliveryError, RecipientResult};
use crate::queue::destination::Destination;
use crate::queue::limits::MAX_EXCHANGERS;
use crate::queue::tls_outcome::{STS_POLICY_FETCH_ERROR, TlsOutcome};
use crate::storage::SpoolEntry;
use crate::tlsrpt::sessions::Attempt;

/// What one conversation decided for the recipients it carried.
pub(super) struct Conversation {
	/// The host that answered, when a connection got that far.
	pub(super) remote: Option<String>,
	/// One answer per recipient.
	pub(super) results: Vec<RecipientResult>,
	/// A slow-down reply from an exchanger tried before the one that gave
	/// these results: that exchanger, and its reply.
	pub(super) slowed: Option<(String, String)>,
	/// Set when no exchanger was spoken to because each one reached was on
	/// hold: the recipients wait until then, with no attempt counted.
	pub(super) held_until: Option<u64>,
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

	/// The exchanger that asked the queue to slow down (when the
	/// conversation got as far as one), from this exchanger or an earlier
	/// one, and its reply.
	pub(super) fn throttled_by(&self) -> Option<(Option<&str>, &str)> {
		self.results
			.iter()
			.find_map(|(_, result)| match result {
				Err(DeliveryError::Transient(reason))
					if crate::queue::backoff::throttled(reason) =>
				{
					Some((self.remote.as_deref(), reason.as_str()))
				}
				_ => None,
			})
			.or(self
				.slowed
				.as_ref()
				.map(|(host, reason)| (Some(host.as_str()), reason.as_str())))
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
			slowed: None,
			held_until: None,
		}
	}
}

impl Worker {
	/// Route and run the conversation for `recipients`, all in `domain`,
	/// within [`crate::queue::timeouts::ATTEMPT`] for every exchanger and
	/// every step together. Past it the recipients are deferred like after
	/// any other timeout, and the slot is free again, unless the whole
	/// message is already with the remote: its reply is then awaited for as
	/// long as the client's own limits on it allow, so a remote that did
	/// accept it is never sent a second copy.
	pub(super) async fn converse(
		&self,
		entry: &SpoolEntry,
		domain: &str,
		recipients: &[String],
	) -> Conversation {
		let limit = self.attempt_limit;
		let sent = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
		let talk = self.route(entry, domain, recipients, &sent);
		tokio::pin!(talk);
		match tokio::time::timeout(limit, &mut talk).await {
			Ok(conversation) => conversation,
			Err(_) if sent.load(std::sync::atomic::Ordering::SeqCst) => talk.await,
			Err(_) => Conversation::all(
				recipients,
				None,
				DeliveryError::Transient(format!(
					"delivery attempt timed out after {}s",
					limit.as_secs()
				)),
			),
		}
	}

	/// Route and run the conversation for `recipients`, all in `domain`.
	async fn route(
		&self,
		entry: &SpoolEntry,
		domain: &str,
		recipients: &[String],
		sent: &std::sync::Arc<std::sync::atomic::AtomicBool>,
	) -> Conversation {
		// MTA-STS: an enforce policy constrains MX choice and mandates TLS.
		// A testing-mode policy is kept for TLS-RPT, which reports on it.
		let mut sts_invalid = false;
		let mut sts_fetch_error: Option<&'static str> = None;
		let fetched = match &self.mta_sts {
			Some((store, dns)) => match store.policy(dns.as_ref(), domain).await {
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
				policy_domain: domain,
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
		let route = Route {
			entry,
			domain,
			recipients,
			fetched: fetched.as_ref(),
			sts_invalid,
			tls_optional,
			// MTA-STS enforce or a sender's REQUIRETLS both mandate
			// verified TLS.
			require_tls: policy.is_some() || entry.envelope.require_tls,
			sent,
		};

		// Route this delivery: a configured transport (relay/fail) or direct.
		let sender_account = entry
			.envelope
			.reverse_path
			.rsplit_once('@')
			.map(|(local, _)| local)
			.filter(|local| !local.is_empty());
		match crate::config::select_transport(&self.transports, sender_account, domain) {
			Some(rule) if rule.kind == crate::config::TransportKind::Fail => Conversation::all(
				recipients,
				None,
				DeliveryError::Permanent(format!("transport policy rejects {domain}")),
			),
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
				let session = Session {
					stream,
					server_name: host,
					auth,
					tls_required: rule.starttls,
					dane: crate::dane::rrset::TlsaRrset::Absent,
					endpoints: None,
				};
				self.attempt(&route, session).await.0
			}
			// Direct (no rule, or kind = direct): MX delivery.
			_ => self.exchange(&route, policy.as_ref()).await,
		}
	}

	/// Deliver through the exchangers of the domain, in preference order:
	/// one that turns the session away before the mail transaction begins
	/// is passed over for the next (RFC 5321 section 5.1), up to
	/// [`MAX_EXCHANGERS`] of them whatever the connector offers. The policy
	/// limits which exchangers may be contacted, and DANE applies to each
	/// host on its own.
	async fn exchange(
		&self,
		route: &Route<'_>,
		policy: Option<&crate::mtasts::Policy>,
	) -> Conversation {
		let mut tried: Vec<String> = Vec::new();
		let mut last: Option<Conversation> = None;
		let mut slowed: Option<(String, String)> = None;
		let now = self.now_epoch();
		let mut held: Option<Conversation> = None;
		loop {
			if tried.len() >= MAX_EXCHANGERS {
				let mut conversation = last.or(held).unwrap_or_else(|| {
					let reason = format!("no further exchanger for {}", route.domain);
					Conversation::all(route.recipients, None, DeliveryError::Transient(reason))
				});
				conversation.slowed = conversation.slowed.take().or(slowed);
				return conversation;
			}
			let connection = match self
				.connector
				.connect_skipping(route.domain, policy, &tried)
				.await
			{
				Ok(connection) => connection,
				// No exchanger left: the last answer stands.
				Err(error) => {
					let mut conversation = last
						.or(held)
						.unwrap_or_else(|| Conversation::all(route.recipients, None, error));
					conversation.slowed = conversation.slowed.take().or(slowed);
					return conversation;
				}
			};
			tried.push(connection.host.clone());
			// An exchanger on hold (its provider asked to slow down for
			// another of its domains) is left before a word is said.
			let exchanger = Destination::exchanger(&connection.host);
			let hold = self.holds().held(&exchanger, now).cloned();
			if let Some(hold) = hold {
				let reason = format!("{} is on hold: {}", connection.host, hold.reason);
				let mut waiting =
					Conversation::all(route.recipients, None, DeliveryError::Transient(reason));
				let until = held
					.and_then(|earlier| earlier.held_until)
					.map_or(hold.until, |earlier| earlier.min(hold.until));
				waiting.held_until = Some(until);
				held = Some(waiting);
				continue;
			}
			let (conversation, next) = self.attempt_direct(route, connection).await;
			if !next {
				let mut conversation = conversation;
				conversation.slowed = slowed;
				return conversation;
			}
			slowed = slowed.or_else(|| {
				conversation.throttled_by().map(|(host, reason)| {
					(host.unwrap_or_default().to_string(), reason.to_string())
				})
			});
			last = Some(conversation);
		}
	}
}

/// What follows from a conversation a destination asked to slow down.
pub(super) struct SlowDown {
	/// The recipient domain.
	pub(super) domain: Destination,
	/// The exchanger that asked, when the conversation reached one.
	pub(super) host: Option<String>,
	/// When its recipients are due again.
	pub(super) until: u64,
	/// Their slow-down deferrals in a row, this one included.
	pub(super) deferrals: u32,
	/// The reply that asked.
	pub(super) reason: String,
}

impl Worker {
	/// How `conversation` asked to slow down, if it did: its recipients
	/// wait for the step after the most deferrals in a row of any of them,
	/// of the domain, or of the exchanger. A deferral while the destination
	/// is still on hold (another conversation of the same burst) keeps that
	/// hold instead of growing it.
	pub(super) fn slow_down(
		&self,
		entry: &SpoolEntry,
		conversation: &Conversation,
		now: u64,
	) -> Option<SlowDown> {
		if conversation.held_until.is_some() {
			return None;
		}
		let (host, reason) = conversation.throttled_by()?;
		let (first, _) = conversation.results.first()?;
		let domain = Destination::of_recipient(first);
		let host = host.filter(|host| !host.is_empty()).map(str::to_string);
		let exchanger = host.as_deref().map(Destination::exchanger);
		let holds = self.holds();
		let own = conversation
			.results
			.iter()
			.map(|(recipient, _)| entry.envelope.recipient_state(recipient).throttled)
			.max()
			.unwrap_or(0);
		let keys = std::iter::once(&domain).chain(exchanger.as_ref());
		let running = keys
			.clone()
			.filter_map(|key| holds.held(key, now))
			.max_by_key(|hold| hold.until)
			.map(|hold| (hold.until, hold.deferrals));
		let behind = keys.map(|key| holds.deferrals(key)).fold(own, u32::max);
		let (until, deferrals) = running.unwrap_or_else(|| {
			let wait = crate::queue::backoff::step(&self.backoff_steps, behind);
			(now.saturating_add(wait), behind.saturating_add(1))
		});
		Some(SlowDown {
			domain,
			host,
			until,
			deferrals: deferrals.max(own.saturating_add(1)),
			reason: reason.chars().take(200).collect(),
		})
	}
}
