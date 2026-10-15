//! The evidence service the server holds: what the mail paths call to
//! record an acceptance or an outcome, and the gate that holds
//! transactional mail while the evidence does not verify.
//!
//! The retention policy is read again on [`EvidenceService::reload`]; a
//! policy that cannot be read keeps the last good one and is reported, never
//! replaced by a looser default.

use std::path::{Path, PathBuf};
use std::sync::RwLock;

use uuid::Uuid;

use super::MailClass;
use super::chain::Chain;
use super::policy::Policy;
use super::record::{
	Abandoned, Accepted, Entry, Outcome, OutcomeKind, Retention, RetentionMode, TlsSummary,
	bounded, sha256, to_hex,
};
use crate::storage::MessageCrypto;

/// The directory of kept messages, under the evidence root.
pub const MESSAGES_DIR: &str = "messages";

/// What an acceptance is about.
#[derive(Debug, Clone, Copy)]
pub struct Submitted<'a> {
	/// The queue id.
	pub spool_id: Uuid,
	/// The submitting account.
	pub account: &'a str,
	/// The class granted.
	pub class: MailClass,
	/// The envelope sender.
	pub from: &'a str,
	/// The envelope recipients.
	pub recipients: &'a [String],
	/// The exact bytes handed to the queue.
	pub data: &'a [u8],
}

/// One recipient outcome to record.
#[derive(Debug, Clone)]
pub struct Delivery<'a> {
	/// The queue id.
	pub spool_id: Uuid,
	/// The class of the message.
	pub class: MailClass,
	/// The recipient.
	pub recipient: &'a str,
	/// What happened.
	pub result: OutcomeKind,
	/// The attempt, from one.
	pub attempt: u32,
	/// The receiving server.
	pub remote: Option<&'a str>,
	/// Its reply.
	pub reply: Option<&'a str>,
	/// The TLS session.
	pub tls: Option<TlsSummary>,
	/// Whether DANE authenticated the server.
	pub dane: bool,
	/// The MTA-STS mode of the recipient domain.
	pub mta_sts: Option<&'a str>,
	/// Days to keep the record.
	pub retain_days: u32,
}

/// The server's evidence service.
#[derive(Debug)]
pub struct EvidenceService {
	root: PathBuf,
	chain: Chain,
	tenants: Vec<(String, Vec<String>)>,
	policy: RwLock<Policy>,
	policy_error: RwLock<Option<String>>,
	gate: RwLock<Option<String>>,
	crypto: MessageCrypto,
}

impl EvidenceService {
	/// Open the service under `data_dir/evidence`. `tenants` are the
	/// configured tenants (name, domains). A policy that cannot be read
	/// refuses to open: there is no last good policy yet.
	pub fn open(
		data_dir: &Path,
		tenants: Vec<(String, Vec<String>)>,
		crypto: MessageCrypto,
	) -> std::io::Result<Self> {
		let root = data_dir.join("evidence");
		let chain = Chain::open(&root)?;
		let policy = super::policy::load(&root)?;
		Ok(EvidenceService {
			root,
			chain,
			tenants,
			policy: RwLock::new(policy),
			policy_error: RwLock::new(None),
			gate: RwLock::new(None),
			crypto,
		})
	}

	/// The evidence root.
	pub fn root(&self) -> &Path {
		&self.root
	}

	/// Read the policy again. On failure the last good policy stays in force
	/// and the error is kept for `epistle status`.
	pub fn reload(&self) {
		match super::policy::load(&self.root) {
			Ok(policy) => {
				if let Ok(mut current) = self.policy.write() {
					*current = policy;
				}
				if let Ok(mut error) = self.policy_error.write() {
					*error = None;
				}
			}
			Err(error) => {
				tracing::warn!(%error, "evidence policy unreadable; keeping the last good one");
				if let Ok(mut kept) = self.policy_error.write() {
					*kept = Some(error.to_string());
				}
			}
		}
	}

	/// Why the policy could not be reloaded, when it could not.
	pub fn policy_error(&self) -> Option<String> {
		self.policy_error
			.read()
			.ok()
			.and_then(|error| error.clone())
	}

	/// Hold transactional mail for `reason`, or release it with `None`.
	pub fn set_gate(&self, reason: Option<String>) {
		if let Ok(mut gate) = self.gate.write() {
			*gate = reason;
		}
	}

	/// Why transactional mail is held, when it is.
	pub fn held(&self) -> Option<String> {
		// A poisoned lock holds the mail: the gate fails closed.
		match self.gate.read() {
			Ok(gate) => gate.clone(),
			Err(_) => Some("the evidence gate is unavailable".into()),
		}
	}

	/// The tenant whose domains include the domain of `address`.
	pub fn tenant_of(&self, address: &str) -> Option<String> {
		let domain = address.rsplit_once('@')?.1.to_ascii_lowercase();
		self.tenants
			.iter()
			.find(|(_, domains)| {
				domains
					.iter()
					.any(|owned| owned.eq_ignore_ascii_case(&domain))
			})
			.map(|(name, _)| name.clone())
	}

	/// The retention for `class` mail from `account` sending as `from`, or
	/// `None` when no evidence is kept. A poisoned policy lock keeps
	/// transactional evidence at its default.
	pub fn retention(&self, account: &str, from: &str, class: MailClass) -> Option<Retention> {
		let tenant = self.tenant_of(from);
		match self.policy.read() {
			Ok(policy) => policy.retention(account, tenant.as_deref(), class),
			Err(_) => Policy::default().retention(account, tenant.as_deref(), class),
		}
	}

	/// Record the acceptance of `submitted` under `retention`: the message
	/// first when it is kept in full, then the record, synced before this
	/// returns.
	pub fn accept(&self, submitted: &Submitted<'_>, retention: Retention) -> std::io::Result<()> {
		if retention.mode == RetentionMode::Full {
			self.keep_message(submitted, retention)?;
		}
		let header = |name: &str| {
			crate::smtp::trace::header_values(submitted.data, name)
				.into_iter()
				.next()
				.map(|value| bounded(&value))
		};
		let accepted = Accepted {
			spool_id: submitted.spool_id,
			account: bounded(submitted.account),
			tenant: self.tenant_of(submitted.from),
			class: submitted.class,
			from: bounded(submitted.from),
			recipients: submitted.recipients.iter().map(|r| bounded(r)).collect(),
			message_id: header("message-id"),
			date: header("date"),
			subject: header("subject"),
			sha256: to_hex(&sha256(submitted.data)),
			size: submitted.data.len() as u64,
			retention,
		};
		self.chain.append(Entry::Accepted(accepted))?;
		Ok(())
	}

	/// Record that the acceptance of `spool_id` never reached the queue.
	pub fn abandon(&self, spool_id: Uuid, reason: &str) -> std::io::Result<()> {
		self.chain.append(Entry::Abandoned(Abandoned {
			spool_id,
			reason: bounded(reason),
			retain_days: super::policy::DEFAULT_DAYS,
		}))?;
		Ok(())
	}

	/// Record one recipient outcome.
	pub fn outcome(&self, delivery: &Delivery<'_>) -> std::io::Result<()> {
		self.chain.append(Entry::Outcome(Outcome {
			spool_id: delivery.spool_id,
			class: delivery.class,
			recipient: bounded(delivery.recipient),
			result: delivery.result,
			attempt: delivery.attempt,
			remote: delivery.remote.map(bounded),
			reply: delivery.reply.map(bounded),
			tls: delivery.tls.clone(),
			dane: delivery.dane,
			mta_sts: delivery.mta_sts.map(bounded),
			retain_days: delivery.retain_days,
		}))?;
		Ok(())
	}

	/// Keep the exact bytes, sealed under the at-rest key when one is set,
	/// in `messages/<day>/<days>/<id>.eml`, so the sweeper can drop a whole
	/// directory once its retention has passed.
	fn keep_message(&self, submitted: &Submitted<'_>, retention: Retention) -> std::io::Result<()> {
		let day = super::day::Day::of_epoch(crate::storage::delivery_log::now_epoch());
		let dir = self
			.root
			.join(MESSAGES_DIR)
			.join(day.name())
			.join(retention.days.to_string());
		super::chain::create_private_dir(&dir)?;
		let sealed = self
			.crypto
			.encode_with_aad(submitted.data, submitted.spool_id.as_bytes())?;
		crate::storage::write_secret(&dir.join(format!("{}.eml", submitted.spool_id)), &sealed)
	}
}

#[cfg(test)]
#[path = "service_tests.rs"]
mod tests;

/// At start-up, before submissions are taken: record `abandoned` for every
/// entry a crash left staged with evidence, then discard the staged files.
/// Returns how many entries were reconciled. At most 10 000 per call.
pub fn reconcile(
	spool: &crate::storage::FsSpool,
	service: &EvidenceService,
) -> std::io::Result<usize> {
	let leftovers = spool.leftovers(10_000)?;
	for leftover in &leftovers {
		if leftover.evidence {
			service.abandon(
				leftover.id,
				"the server stopped before the message was queued",
			)?;
		}
		spool.discard_leftover(leftover.id)?;
	}
	Ok(leftovers.len())
}
