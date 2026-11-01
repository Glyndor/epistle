//! The DANE TLSA record of the mail host after its certificate changed,
//! whoever changed it: ACME renewal or the operator replacing the `[tls]`
//! files.
//!
//! The certificate is in service before the record can follow it, so a DNS
//! failure leaves DANE senders looking at a record that names the old
//! certificate. [`refresh`] therefore never drops a failed publication: it
//! stores it in [`State`] with the reason and the next attempt, and
//! [`retry_due`] (called on every tick of the renewal loop and of the file
//! watcher) tries again with a growing wait until the provider accepts it.
//! `epistle status` reads the same state to show what is owed.

mod plan;
mod state;
mod write;

use std::path::Path;

use crate::dns::provider::DnsProvider;
pub use state::{Pending, State, path as state_path, wait_after};

/// The TTL of the record.
const TTL: u32 = 3600;

/// Where a TLSA record is published.
pub struct Target<'a> {
	/// The `[dns]` provider, when one is configured.
	pub provider: Option<&'a dyn DnsProvider>,
	/// The mail host whose `_25._tcp` name is published.
	pub hostname: &'a str,
	/// The data directory, where the state is kept.
	pub data_dir: &'a Path,
}

/// What a refresh did.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
	/// The provider published the record for the new certificate.
	Published {
		/// The `3 0 1 <sha256>` association now published.
		value: String,
	},
	/// The publication failed; it is kept and tried again later.
	Pending {
		/// The association still to publish.
		value: String,
		/// Why the attempt failed.
		reason: String,
		/// The failed attempts so far.
		attempts: u32,
		/// How long until the next attempt.
		retry_in: std::time::Duration,
	},
	/// No `[dns]` provider can write: the record is the operator's.
	ByHand {
		/// The association to publish.
		value: String,
	},
	/// The chain has no certificate to hash.
	NoCertificate,
}

/// Publish the TLSA record of `chain_pem`, the leaf certificate now in
/// service, at `now` (seconds since the epoch). `previous_chain` is the
/// certificate it replaces, when known: its association is a value this
/// instance served, so it may be replaced even when the state does not
/// remember publishing it. A failure is stored as the pending publication;
/// a success clears it.
///
/// Only values this instance published are replaced. A TLSA record at the
/// name that is not one of them stays; see [`write`].
pub async fn refresh(
	target: &Target<'_>,
	chain_pem: &str,
	previous_chain: Option<&str>,
	now: u64,
) -> Outcome {
	let Some(value) = crate::dns::records::tlsa_full_cert(chain_pem) else {
		return Outcome::NoCertificate;
	};
	let Some(provider) = target.provider else {
		return Outcome::ByHand { value };
	};
	let mut state = State::load(target.data_dir, target.hostname);
	let mut known = state.managed.clone();
	known.extend(previous_chain.and_then(crate::dns::records::tlsa_full_cert));
	// The intent is stored before the zone is touched, so a write whose
	// answer is lost is still known as epistle's own at the next refresh.
	state.intend(&value, &known);
	store(&state, target);
	match write::publish(provider, target.hostname, &value, &known).await {
		Ok(()) => {
			state.pending = None;
			store(&state, target);
			Outcome::Published { value }
		}
		// A provider that cannot write at all is not a failure to retry.
		Err(write::Refused::Unsupported) => Outcome::ByHand { value },
		Err(write::Refused::Failed(reason)) => {
			state.fail(&value, reason, now);
			store(&state, target);
			pending_outcome(&state, value)
		}
	}
}

/// Try the owed publication again when its wait is over. `chain_pem` is the
/// chain actually in service now, so a certificate renewed in the meantime
/// is the one published, and a pair on disk that was never put in service
/// is never published. `None` when nothing is owed or the wait is not over.
pub async fn retry_due(target: &Target<'_>, chain_pem: &str, now: u64) -> Option<Outcome> {
	target.provider?;
	let state = State::load(target.data_dir, target.hostname);
	let pending = state.pending?;
	if now < pending.next_attempt {
		return None;
	}
	Some(refresh(target, chain_pem, None, now).await)
}

fn pending_outcome(state: &State, value: String) -> Outcome {
	let (attempts, reason) = state
		.pending
		.as_ref()
		.map(|pending| (pending.attempts, pending.reason.clone()))
		.unwrap_or_default();
	Outcome::Pending {
		value,
		reason,
		attempts,
		retry_in: wait_after(attempts),
	}
}

/// Keep the state. A state that cannot be stored is reported and does not
/// undo the publication: the next certificate change publishes again.
fn store(state: &State, target: &Target<'_>) {
	if let Err(error) = state.save(target.data_dir) {
		tracing::warn!(
			%error,
			path = %state_path(target.data_dir).display(),
			"cannot store the TLSA state; a failed publication will not be retried after a restart",
		);
	}
}

/// Log what [`refresh`] or [`retry_due`] did. A record left to the operator
/// or still pending is a warning that names it and the value to publish:
/// DANE senders refuse mail while it names the old certificate.
pub fn log_outcome(outcome: &Outcome, hostname: &str) {
	let name = format!("_25._tcp.{hostname}");
	match outcome {
		Outcome::Published { value } => {
			tracing::info!(%name, %value, "TLSA record updated for the new certificate");
		}
		Outcome::Pending {
			value,
			reason,
			attempts,
			retry_in,
		} => tracing::warn!(
			%name,
			%reason,
			attempts,
			retry_in_secs = retry_in.as_secs(),
			"the TLSA record for the new certificate is not published yet and will be retried; if you publish DANE, set {name} TLSA {value} by hand meanwhile",
		),
		Outcome::ByHand { value } => tracing::warn!(
			%name,
			"the certificate changed and no [dns] provider can write; if you publish DANE, update {name} TLSA to {value} by hand",
		),
		Outcome::NoCertificate => {}
	}
}

#[cfg(test)]
mod tests;
