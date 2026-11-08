//! The steps of one domain's rotation and retirement, journaled so a process
//! killed at any of them leaves a state the next tick completes or takes
//! back. See `crate::dkim::rotate::steps` for the `[dkim]` key's version of
//! the same sequence.

use std::path::Path;
use std::sync::Arc;

use super::DomainRotator;
use super::state::{ERROR_FILE, active_from, next_selectors, save_state};
use crate::dkim::rotate::{
	Pending, Previous, RotateError, RotationState, RsaKey, Step, key_of, pending_key,
	remove_key_file, write_key,
};

impl DomainRotator {
	/// Stop here when a test asked for a crash at `step`.
	pub(super) fn checkpoint(&self, step: Step) -> Result<(), RotateError> {
		#[cfg(test)]
		if self.crash_at == Some(step) {
			return Err(RotateError::from_reason(format!(
				"crash injected at {step:?}"
			)));
		}
		let _ = step;
		Ok(())
	}

	/// Make [`DomainRotator::checkpoint`] fail at `step`.
	#[cfg(test)]
	pub(crate) fn crash_at(mut self, step: Step) -> Self {
		self.crash_at = Some(step);
		self
	}

	fn record_name(&self, selector: &str) -> String {
		format!("{selector}._domainkey.{}", self.domain())
	}

	/// Journal a rotation and run it. Nothing may be pending.
	pub(super) async fn rotate(
		&self,
		state: &mut RotationState,
		now: u64,
	) -> Result<(), RotateError> {
		// An entry configured by hand may keep its key elsewhere; the
		// rotation's own files still go to the domain's key directory.
		crate::dkim::domain_keys::private_dir(&self.dir)?;
		let dual = self.signer.current().rsa_selector().is_some();
		let (selector, rsa_selector) =
			next_selectors(&self.entry, Some(state), &self.reserved, dual, now);
		let rsa = rsa_selector.map(|selector| RsaKey {
			key_file: self.dir.join(format!("{selector}.pem")),
			selector,
		});
		state.pending = Some(Pending {
			key_file: self.dir.join(format!("{selector}.pem")),
			selector,
			domains: vec![self.domain()],
			started_at: now,
			withdrawing: None,
			rsa,
		});
		save_state(&self.dir, state)?;
		self.checkpoint(Step::Journaled)?;
		self.resume(state, now).await
	}

	/// Carry the journaled rotation to its end: commit it once the resolver
	/// shows every new record, or withdraw it. `Err` when it was withdrawn
	/// or a step failed and the journal keeps it for the next tick.
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
		let rsa_txt = match self.pending_rsa_key(&pending) {
			Ok(rsa_txt) => rsa_txt,
			Err(reason) => return self.withdraw(state, &pending, &reason, now).await,
		};
		let mut records = vec![(pending.selector.clone(), txt, Step::Published(0))];
		if let (Some(rsa), Some(rsa_txt)) = (&pending.rsa, rsa_txt) {
			self.checkpoint(Step::RsaKeyWritten)?;
			records.push((rsa.selector.clone(), rsa_txt, Step::RsaPublished(0)));
		}
		for (selector, value, step) in &records {
			let name = self.record_name(selector);
			if let Err(reason) = self.publisher.publish(&name, value).await {
				return self.withdraw(state, &pending, &reason, now).await;
			}
			self.checkpoint(*step)?;
		}
		for (selector, value, _) in &records {
			if let Err(reason) = self.confirm_published(selector, value).await? {
				return self.withdraw(state, &pending, &reason, now).await;
			}
		}
		self.checkpoint(Step::Confirmed)?;
		let rsa_paths = pending
			.rsa
			.as_ref()
			.map(|rsa| (rsa.selector.as_str(), rsa.key_file.as_path()));
		let signer = match self.signer.current().with_rotated_keys(
			&pending.selector,
			&pending.key_file,
			rsa_paths,
		) {
			Ok(signer) => signer,
			Err(error) => {
				let reason = format!("load the rotated keys: {error}");
				return self.withdraw(state, &pending, &reason, now).await;
			}
		};
		let replaced = active_from(&self.entry, &self.data_dir, Some(state));
		let retired_rsa = match (&pending.rsa, &state.rsa) {
			(Some(_), Some(rsa)) => Some(RsaKey {
				selector: rsa.selector.clone(),
				key_file: self.data_dir.join(&rsa.key_file),
			}),
			_ => None,
		};
		// A domain that has not rotated signs with the configured key, which
		// is never retired; only a key a rotation made becomes the previous.
		let previous = (!state.selector.is_empty()).then(|| Previous {
			selector: replaced.ed.selector,
			key_file: replaced.ed.key_file,
			retire_at: now.saturating_add(self.overlap),
			rsa: retired_rsa,
		});
		let rsa = pending.rsa.clone().or_else(|| state.rsa.clone());
		*state = RotationState {
			selector: pending.selector,
			key_file: pending.key_file,
			rotated_at: now,
			previous,
			pending: None,
			rsa,
		};
		save_state(&self.dir, state)?;
		self.checkpoint(Step::Committed)?;
		self.signer.reload(Arc::new(signer));
		self.checkpoint(Step::Swapped)?;
		let _ = std::fs::remove_file(self.dir.join(ERROR_FILE));
		tracing::info!(domain = %self.domain(), selector = %state.selector, "DKIM key of the domain rotated");
		Ok(())
	}

	/// The TXT value of the pending RSA key, making the key first when no
	/// file that loads exists. `Ok(None)` when the rotation does not cover
	/// RSA; `Err` names why the rotation has to be withdrawn.
	fn pending_rsa_key(&self, pending: &Pending) -> Result<Option<String>, String> {
		let Some(rsa) = &pending.rsa else {
			return Ok(None);
		};
		if self.signer.current().rsa_selector().is_none() {
			return Err(format!(
				"RSA dual signing was turned off while the rotation to {} ran",
				rsa.selector
			));
		}
		if let Ok(txt) = crate::dkim::rsa_record_value(&rsa.key_file) {
			return Ok(Some(txt));
		}
		let (pem, txt) = (self.rsa_keygen)()
			.map_err(|error| format!("generate the RSA key for {}: {error}", rsa.selector))?;
		write_key(&rsa.key_file, &pem)
			.map_err(|error| format!("write the RSA key for {}: {error}", rsa.selector))?;
		Ok(Some(txt))
	}

	/// Wait until the resolver shows `value`'s key at `selector`.
	/// `Ok(Err(reason))` when it never does; `Err` only when a test stopped
	/// the rotator while it waited.
	async fn confirm_published(
		&self,
		selector: &str,
		value: &str,
	) -> Result<Result<(), String>, RotateError> {
		let name = self.record_name(selector);
		let expected = key_of(value);
		let mut waits = self.waits.iter();
		loop {
			let seen = match self.resolver.txt(&name).await {
				Ok(values) => expected.is_some() && values.iter().any(|v| key_of(v) == expected),
				Err(_) => false,
			};
			if seen {
				return Ok(Ok(()));
			}
			match waits.next() {
				Some(wait) => {
					self.checkpoint(Step::Waiting)?;
					tokio::time::sleep(*wait).await;
				}
				None => return Ok(Err(format!("{name} does not show the new key in DNS"))),
			}
		}
	}

	/// Take back a rotation that cannot complete: its records, then its key
	/// files, then the journal. The current key keeps signing throughout.
	/// `Err` always: the rotation did not happen.
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
			save_state(&self.dir, state)?;
			self.checkpoint(Step::Withdrawing)?;
		}
		let mut selectors = vec![pending.selector.as_str()];
		selectors.extend(pending.rsa.as_ref().map(|rsa| rsa.selector.as_str()));
		for selector in selectors {
			let name = self.record_name(selector);
			if let Err(error) = self.publisher.withdraw(&name).await {
				return Err(RotateError::from_reason(format!(
					"withdrawing the rotation of {} to {}: {error}; retried at the next tick",
					self.domain(),
					pending.selector
				)));
			}
		}
		self.checkpoint(Step::WithdrawnRecord(0))?;
		self.remove_made_key(&pending.key_file, "withdrawn");
		if let Some(rsa) = &pending.rsa {
			self.remove_made_key(&rsa.key_file, "withdrawn");
		}
		self.checkpoint(Step::WithdrawnKey)?;
		state.pending = None;
		save_state(&self.dir, state)?;
		self.report_withdrawn(&pending.selector, reason, now).await;
		Err(RotateError::from_reason(format!(
			"rotation of {} to {} withdrawn: {reason}",
			self.domain(),
			pending.selector
		)))
	}

	/// Withdraw the replaced selector's records, remove its key files, then
	/// drop it from the state. Until that save the state still names it, so
	/// a failure or a crash before repeats the whole retirement.
	pub(super) async fn retire(
		&self,
		state: &mut RotationState,
		selector: &str,
	) -> Result<(), RotateError> {
		let Some(previous) = state.previous.clone().filter(|p| p.selector == selector) else {
			return Ok(());
		};
		let mut names = vec![previous.selector.clone()];
		names.extend(previous.rsa.iter().map(|rsa| rsa.selector.clone()));
		let in_service = active_from(&self.entry, &self.data_dir, Some(state));
		for selector in &names {
			// The selector in service and the configured ones are never
			// retired, whatever a damaged state says.
			if self.is_kept(selector, &in_service) {
				return Err(RotateError::from_reason(format!(
					"refusing to retire {selector} at {}: the domain still signs with it or its entry names it",
					self.domain()
				)));
			}
			self.publisher
				.withdraw(&self.record_name(selector))
				.await
				.map_err(RotateError::from_reason)?;
		}
		self.checkpoint(Step::RetiredRecord(0))?;
		self.remove_made_key(&previous.key_file, "retired");
		if let Some(rsa) = &previous.rsa {
			self.remove_made_key(&rsa.key_file, "retired");
		}
		self.checkpoint(Step::RetiredKey)?;
		state.previous = None;
		save_state(&self.dir, state)?;
		self.checkpoint(Step::RetiredState)?;
		Ok(())
	}

	fn is_kept(&self, selector: &str, in_service: &super::DomainActive) -> bool {
		let same = |other: &str| other.eq_ignore_ascii_case(selector);
		same(&in_service.ed.selector)
			|| in_service
				.rsa
				.as_ref()
				.is_some_and(|rsa| same(&rsa.selector))
			|| same(&self.entry.selector)
			|| self.entry.rsa_selector.as_deref().is_some_and(same)
	}

	/// Remove a key file a rotation made. A file outside the domain's key
	/// directory, or one the entry names, is left alone: the rotation made
	/// neither.
	fn remove_made_key(&self, path: &Path, which: &str) {
		let path = self.data_dir.join(path);
		let configured = std::iter::once(&self.entry.key_file)
			.chain(self.entry.rsa_key_file.as_ref())
			.any(|file| *file == path);
		if path.as_os_str().is_empty() || configured || !path.starts_with(&self.dir) {
			return;
		}
		remove_key_file(&path, which);
	}

	/// Record why the rotation was withdrawn: the error file `dkim show`
	/// reads, a log line and the webhook.
	async fn report_withdrawn(&self, selector: &str, reason: &str, now: u64) {
		let domain = self.domain();
		tracing::error!(%domain, %selector, %reason, "DKIM rotation of the domain withdrawn; its current key keeps signing");
		let _ = std::fs::write(
			self.dir.join(ERROR_FILE),
			format!("{now} rotation to {selector} withdrawn: {reason}\n"),
		);
		if let Some(webhook) = &self.webhook {
			webhook
				.notify(&crate::webhook::WebhookEvent::DkimRotationFailed {
					selector: format!("{selector}._domainkey.{domain}"),
					reason: reason.to_string(),
				})
				.await;
		}
	}
}
