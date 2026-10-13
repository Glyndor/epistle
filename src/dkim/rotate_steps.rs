//! A rotation as journaled steps, so a process killed at any of them
//! leaves a state the next tick completes or rolls back.
//!
//! The rotation is written to the state as [`Pending`] before any key or
//! record exists. From then on every step can be repeated: an existing key
//! file that loads is reused, an upsert replaces the record of the same
//! purpose, a delete of an absent record is harmless. The commit is the one
//! state save that names the new key as active and clears the journal; the
//! live signer switches only after it. A rotation that cannot be confirmed
//! is marked as withdrawing before anything is removed, so a crash during
//! the rollback finishes the rollback instead of publishing again.

use std::path::Path;
use std::sync::Arc;

use super::{
	ERROR_FILE, Pending, Previous, RotateError, RotationState, Rotator, Signer, selector_for,
	txt_record,
};

/// A point in a rotation or a retirement. Production code passes each one
/// to [`Rotator::checkpoint`]; only tests act on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Step {
	/// The pending rotation is in the journal and no key exists yet.
	Journaled,
	/// The new key file is on disk.
	KeyWritten,
	/// The new TXT for the n-th signing domain was published.
	Published(usize),
	/// The new selector was not visible yet and the rotator is waiting.
	Waiting,
	/// Every signing domain shows the new key.
	Confirmed,
	/// The state naming the new key is saved.
	Committed,
	/// The live signer was switched to the new key.
	Swapped,
	/// A rotation that could not be confirmed is marked as withdrawing.
	Withdrawing,
	/// The n-th TXT of a withdrawn rotation was deleted.
	WithdrawnRecord(usize),
	/// The key file of a withdrawn rotation was removed.
	WithdrawnKey,
	/// The n-th TXT of the retired selector was deleted.
	RetiredRecord(usize),
	/// The retired selector's key file was removed.
	RetiredKey,
	/// The state without the retired selector is saved.
	RetiredState,
}

impl Rotator {
	/// Stop here when a test asked for a crash at `step`: the error leaves
	/// every file and record exactly as a killed process would.
	pub(super) fn checkpoint(&self, step: Step) -> Result<(), RotateError> {
		#[cfg(test)]
		if self.crash_at == Some(step) {
			return Err(RotateError(format!("crash injected at {step:?}")));
		}
		let _ = step;
		Ok(())
	}

	/// Make [`Rotator::checkpoint`] fail at `step`.
	#[cfg(test)]
	pub(crate) fn crash_at(mut self, step: Step) -> Self {
		self.crash_at = Some(step);
		self
	}

	/// Journal a rotation to `selector_for(now)` and run it. The caller has
	/// already ruled out a selector collision and checked that nothing is
	/// pending.
	pub(super) async fn rotate(
		&self,
		state: &mut RotationState,
		now: u64,
	) -> Result<(), RotateError> {
		let selector = selector_for(now);
		let key_file = self.data_dir.join(format!("dkim-{selector}.key"));
		state.pending = Some(Pending {
			selector,
			key_file,
			domains: self.signing_domains.clone(),
			started_at: now,
			withdrawing: None,
		});
		self.save_state(state)?;
		self.checkpoint(Step::Journaled)?;
		self.resume(state, now).await
	}

	/// Carry the journaled rotation to its end: commit it once every signing
	/// domain shows the new key, or withdraw it. `Err` when it was withdrawn
	/// (now or by an earlier run) or when a step failed and the journal
	/// keeps it for the next tick.
	pub(super) async fn resume(
		&self,
		state: &mut RotationState,
		now: u64,
	) -> Result<(), RotateError> {
		let Some(pending) = state.pending.clone() else {
			return Ok(());
		};
		if let Some(reason) = &pending.withdrawing {
			return self.withdraw(state, &pending, reason, now).await;
		}
		let txt = pending_key(&pending)?;
		self.checkpoint(Step::KeyWritten)?;
		// A domain dropped from the configuration since the rotation began
		// gets no new record; one published there before the restart goes.
		for domain in pending
			.domains
			.iter()
			.filter(|d| !self.signing_domains.contains(d))
		{
			self.provider
				.delete(
					&self.zone,
					txt_record(&Self::record_name(&pending.selector, domain), ""),
				)
				.await
				.map_err(|error| RotateError(format!("withdraw from {domain}: {error}")))?;
		}
		for (index, domain) in self.signing_domains.iter().enumerate() {
			let name = Self::record_name(&pending.selector, domain);
			if let Err(error) = self
				.provider
				.upsert(&self.zone, txt_record(&name, &txt))
				.await
			{
				let reason = format!("publish {name}: {error}");
				return self.withdraw(state, &pending, &reason, now).await;
			}
			self.checkpoint(Step::Published(index))?;
		}
		if let Err(reason) = self.confirm_published(&pending.selector, &txt).await? {
			return self.withdraw(state, &pending, &reason, now).await;
		}
		self.checkpoint(Step::Confirmed)?;
		let signer = match self
			.signer
			.current()
			.with_rotated_key(&pending.selector, &pending.key_file)
		{
			Ok(signer) => signer,
			Err(error) => {
				let reason = format!("load {}: {error}", pending.key_file.display());
				return self.withdraw(state, &pending, &reason, now).await;
			}
		};
		// Retire the just-replaced selector after the overlap window.
		let previous = (!state.selector.is_empty()).then(|| Previous {
			selector: state.selector.clone(),
			key_file: self.data_dir.join(&state.key_file),
			retire_at: now.saturating_add(self.overlap),
		});
		*state = RotationState {
			selector: pending.selector,
			key_file: pending.key_file,
			rotated_at: now,
			previous,
			pending: None,
		};
		self.save_state(state)?;
		self.checkpoint(Step::Committed)?;
		self.signer.reload(Arc::new(signer));
		self.checkpoint(Step::Swapped)?;
		let _ = std::fs::remove_file(self.data_dir.join(ERROR_FILE));
		Ok(())
	}

	/// Take back a rotation that cannot complete: its TXT from every domain
	/// it may have reached, then its key file, then the journal. The old key
	/// keeps signing throughout. `Err` always: the rotation did not happen.
	async fn withdraw(
		&self,
		state: &mut RotationState,
		pending: &Pending,
		reason: &str,
		now: u64,
	) -> Result<(), RotateError> {
		if pending.withdrawing.is_none() {
			state.pending = Some(Pending {
				withdrawing: Some(reason.to_string()),
				..pending.clone()
			});
			self.save_state(state)?;
			self.checkpoint(Step::Withdrawing)?;
		}
		let mut domains = pending.domains.clone();
		domains.extend(
			self.signing_domains
				.iter()
				.filter(|d| !pending.domains.contains(d))
				.cloned(),
		);
		let mut failed = None;
		for (index, domain) in domains.iter().enumerate() {
			let name = Self::record_name(&pending.selector, domain);
			if let Err(error) = self
				.provider
				.delete(&self.zone, txt_record(&name, ""))
				.await
			{
				failed = Some(format!("delete {name}: {error}"));
			}
			self.checkpoint(Step::WithdrawnRecord(index))?;
		}
		if let Some(error) = failed {
			return Err(RotateError(format!(
				"withdrawing the rotation to {}: {error}; retried at the next tick",
				pending.selector
			)));
		}
		remove_key_file(&pending.key_file, "withdrawn");
		self.checkpoint(Step::WithdrawnKey)?;
		state.pending = None;
		self.save_state(state)?;
		self.report_unpublished(&pending.selector, reason, now)
			.await;
		Err(RotateError(format!(
			"rotation to {} withdrawn: {reason}",
			pending.selector
		)))
	}

	/// Take the previous selector's TXT down from every signing domain,
	/// remove its key file, then drop it from the state. Until that save the
	/// state still names it, so a failure or a crash anywhere before repeats
	/// the whole retirement on the next tick.
	pub(super) async fn retire(
		&self,
		state: &mut RotationState,
		selector: &str,
	) -> Result<(), RotateError> {
		let retired_key_file = state.previous.as_ref().and_then(|p| {
			(p.selector == selector && !p.key_file.as_os_str().is_empty())
				.then(|| p.key_file.clone())
		});
		let mut last_error: Option<String> = None;
		for (index, domain) in self.signing_domains.iter().enumerate() {
			let name = Self::record_name(selector, domain);
			if let Err(error) = self
				.provider
				.delete(&self.zone, txt_record(&name, ""))
				.await
			{
				last_error = Some(format!("delete {name}: {error}"));
			}
			self.checkpoint(Step::RetiredRecord(index))?;
		}
		if let Some(error) = last_error {
			return Err(RotateError(error));
		}
		if let Some(path) = retired_key_file {
			remove_key_file(&self.data_dir.join(path), "retired");
		}
		self.checkpoint(Step::RetiredKey)?;
		state.previous = None;
		self.save_state(state)?;
		self.checkpoint(Step::RetiredState)?;
		Ok(())
	}

	/// Remove the temporary files a write killed before its rename left
	/// beside the state and the keys. Only the rotator writes those names.
	pub(super) fn sweep_temporary_files(&self) {
		let Ok(entries) = std::fs::read_dir(&self.data_dir) else {
			return;
		};
		for entry in entries.flatten() {
			let name = entry.file_name();
			let name = name.to_string_lossy();
			let stale = (name.starts_with(".dkim-") && name.ends_with(".tmp"))
				|| name == "dkim-rotation.json.tmp";
			if stale && let Err(error) = std::fs::remove_file(entry.path()) {
				tracing::warn!(%error, file = %name, "cannot remove a stale DKIM temporary file");
			}
		}
	}
}

/// The TXT value for the pending key, writing the key first when no file
/// that loads exists. A file that loads is the one a killed run wrote and
/// may already have published, so it is kept.
fn pending_key(pending: &Pending) -> Result<String, RotateError> {
	if let Ok(signer) = Signer::load(&pending.selector, &pending.key_file) {
		return Ok(signer.dns_record_value());
	}
	let (pem, txt) = super::super::generate_key().map_err(|e| RotateError(e.to_string()))?;
	write_key(&pending.key_file, &pem)?;
	Ok(txt)
}

/// Write a key file `0600` from creation, through a synced temporary file
/// renamed into place, so a crash leaves either no key or the whole key.
pub(super) fn write_key(path: &Path, pem: &str) -> std::io::Result<()> {
	crate::storage::write_secret(path, pem.as_bytes())
}

/// Remove a key file that nothing names any more. Best effort: `NotFound`
/// is the case an operator caused by hand, and any other failure is logged
/// rather than allowed to block the rotation forever.
fn remove_key_file(path: &Path, which: &str) {
	if let Err(error) = std::fs::remove_file(path)
		&& error.kind() != std::io::ErrorKind::NotFound
	{
		tracing::warn!(
			%error,
			path = %path.display(),
			"failed to remove the {which} DKIM key file; DNS and state are already cleared",
		);
	}
}
