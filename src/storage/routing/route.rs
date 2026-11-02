use super::*;

impl SplitDelivery {
	/// Route `message`: local recipients to their mailboxes, the rest to the
	/// outbound spool under `queue_id`, DKIM-signed when a signer is set.
	/// `account` is the local account that submitted, when known; `extra` is
	/// the caller-supplied correlation map (the API may attach one).
	/// `presigned` is the exact outbound copy when the caller recorded
	/// evidence over it.
	pub(super) fn route_classed(
		&self,
		message: AcceptedMessage,
		queue_id: uuid::Uuid,
		account: Option<&str>,
		extra: &BTreeMap<String, String>,
		class: (crate::evidence::MailClass, Option<u32>),
		presigned: Option<Vec<u8>>,
	) -> Result<(), SinkError> {
		self.route_reporting(
			message,
			(queue_id, account, extra),
			class,
			presigned,
			&mut None,
		)
	}

	/// [`route_classed`](Self::route_classed), telling `done` which
	/// recipients were delivered locally and whether a rule rejected them,
	/// as soon as that is so: a later failure does not undo it.
	pub(super) fn route_reporting(
		&self,
		message: AcceptedMessage,
		(queue_id, account, extra): (uuid::Uuid, Option<&str>, &BTreeMap<String, String>),
		(class, evidence): (crate::evidence::MailClass, Option<u32>),
		presigned: Option<Vec<u8>>,
		done: &mut Option<LocalDone>,
	) -> Result<(), SinkError> {
		let mut local = Vec::new();
		let mut remote = Vec::new();
		let mut srs_returns = Vec::new();
		for recipient in &message.recipients {
			// An SRS-return address forwards the (bounce) message back to the
			// original sender it encodes.
			if let Some(original) = self.srs_return(recipient) {
				srs_returns.push(original);
				continue;
			}
			let address = Address::parse(recipient).map_err(|_| {
				SinkError::Unavailable(format!("unparseable recipient {recipient}"))
			})?;
			match self.directory.current().resolve(&address) {
				// An account or a multi-target alias delivers locally; the alias
				// is expanded to its members by `LocalDelivery`.
				Resolution::Account(_) | Resolution::Alias(_) => local.push(recipient.clone()),
				Resolution::NotLocal => remote.push(recipient.clone()),
				// The session rejected unknown local users; drift here is
				// a logic error and the whole delivery fails closed.
				Resolution::UnknownUser => {
					return Err(self.directory.current().unresolved(
						&address,
						format!("recipient {recipient} no longer resolves"),
					));
				}
			}
		}

		if !local.is_empty() {
			let mailbox = message
				.mailbox
				.clone()
				.or_else(|| self.target_mailbox(&message));
			let local_message = AcceptedMessage {
				recipients: local,
				..message.clone()
			};
			let delivered = match self
				.local
				.deliver_routed(&local_message, mailbox.as_deref())
			{
				Ok(delivered) => delivered,
				Err(SinkError::MailboxFull(_)) if !remote.is_empty() || !srs_returns.is_empty() => {
					crate::storage::delivery::Delivered {
						over_quota: local_message.recipients.clone(),
						..Default::default()
					}
				}
				Err(error) => return Err(error),
			};
			*done = Some(LocalDone {
				recipients: local_message.recipients.clone(),
				reject: delivered.reject.clone(),
			});
			// Notify the webhook for messages that actually landed (not rejected).
			if delivered.reject.is_none()
				&& let Some(webhook) = &self.webhook
			{
				for recipient in &local_message.recipients {
					let webhook = webhook.clone();
					let event = Self::message_event(recipient, &local_message);
					tokio::spawn(async move { webhook.notify(&event).await });
				}
			}
			if let Some(reason) = delivered.reject {
				if let Some(metrics) = &self.metrics {
					metrics.sieve_rejected();
				}
				let hostname = local_message
					.recipients
					.first()
					.and_then(|r| r.rsplit_once('@'))
					.map(|(_, domain)| domain.to_string())
					.unwrap_or_else(|| "localhost".to_string());
				// Recipients with NOTIFY=NEVER (RFC 3461) get no failure DSN.
				let dsn_recipients: Vec<String> = local_message
					.recipients
					.iter()
					.filter(|r| !local_message.no_dsn.contains(r))
					.cloned()
					.collect();
				if let Some(bounce) = (!dsn_recipients.is_empty())
					.then(|| {
						crate::queue::bounce::build(
							&hostname,
							&message.reverse_path,
							&dsn_recipients,
							&reason,
							&message.data,
							std::time::SystemTime::now(),
							self.identification.system_auto_submitted,
						)
					})
					.flatten()
				{
					self.outbound
						.store(&bounce, account, extra)
						.map_err(|error| SinkError::Unavailable(error.to_string()))?;
				}
			}
			let full: Vec<_> = delivered
				.over_quota
				.iter()
				.filter(|recipient| {
					!local_message.no_dsn.contains(recipient)
						&& !local_message.recipients.iter().any(|original| {
							local_message.no_dsn.contains(original)
								&& Address::parse(original)
									.ok()
									.and_then(|address| {
										self.directory.current().final_recipients(&address)
									})
									.is_some_and(|finals| {
										finals.iter().any(|(_, address)| address == *recipient)
									})
						})
				})
				.cloned()
				.collect();
			let hostname = full
				.first()
				.and_then(|address| address.rsplit_once('@'))
				.map_or("localhost", |(_, domain)| domain);
			if !full.is_empty()
				&& let Some(report) = crate::queue::bounce::build(
					hostname,
					&message.reverse_path,
					&full,
					"552 5.2.2 mailbox full",
					&message.data,
					std::time::SystemTime::now(),
					self.identification.system_auto_submitted,
				) {
				// A report failure does not repeat copies already delivered.
				if let Err(error) = self.store_outbound(&report) {
					tracing::warn!(%error, "mailbox-full report not queued");
				}
			}
			self.queue_redirects(&message, delivered.redirects)?;
			self.bounce_loops(&message, &delivered.looped)?;
			for mut reply in delivered.replies {
				self.sign_reply(&mut reply);
				self.outbound
					.store(&reply, account, extra)
					.map_err(|error| SinkError::Unavailable(error.to_string()))?;
				if let Some(metrics) = &self.metrics {
					metrics.vacation_sent();
				}
			}
		}
		// Forward SRS-return (bounce) messages back to the original senders.
		for original in srs_returns {
			let returned = AcceptedMessage {
				reverse_path: message.reverse_path.clone(),
				recipients: vec![original],
				data: message.data.clone(),
				require_tls: false,
				mailbox: None,
				tlsrpt_verified: false,
				sender_verified: false,
				no_dsn: Vec::new(),
			};
			self.outbound
				.store(&returned, account, extra)
				.map_err(|error| SinkError::Unavailable(error.to_string()))?;
		}
		if !remote.is_empty() {
			let mut outbound_message = AcceptedMessage {
				recipients: remote,
				..message
			};
			// With evidence the acceptance was recorded over the signed bytes
			// already: queue exactly those, never a second signature.
			match presigned {
				Some(signed) => outbound_message.data = signed,
				None => self.sign_outbound(&mut outbound_message),
			}
			// The acceptance was recorded before routing: the queue entry
			// only has to say so, so its outcomes are recorded too.
			let recorded = |_: &[u8]| Ok(());
			let options = crate::storage::spool::StoreOptions {
				account,
				extra,
				class,
				evidence: evidence.map(|_| &recorded as &dyn Fn(&[u8]) -> std::io::Result<()>),
				retain_days: evidence.unwrap_or(0),
			};
			self.outbound
				.store_with(&outbound_message, queue_id, &options)
				.map_err(|error| SinkError::Unavailable(error.to_string()))?;
		}
		Ok(())
	}
}
