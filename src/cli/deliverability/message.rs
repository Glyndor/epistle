//! The test message: a plain, realistic note from the account to the
//! address the operator named, signed with the key the server signs with.

use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use uuid::Uuid;

use super::plan::Plan;
use crate::config::Config;
use crate::dkim::{PerDomainSigner, ReloadableSigner, Signer};

/// The message, with its DKIM signature when the server has a key for the
/// sending domain.
pub(super) struct Built {
	pub data: Vec<u8>,
	pub signed: bool,
}

/// Build the message sent by `plan` at `now` (epoch seconds) under `id`,
/// and sign it for the sending domain. Every field written into a header
/// comes from a validated address or from the configured host name.
pub(super) fn build(
	plan: &Plan,
	hostname: &str,
	now: u64,
	id: Uuid,
	signer: Option<&PerDomainSigner>,
) -> Built {
	let date = crate::clock::rfc5322(UNIX_EPOCH + Duration::from_secs(now));
	let text = format!(
		"From: {from}\r\nTo: {to}\r\nSubject: Deliverability test from {hostname}\r\nDate: {date}\r\nMessage-ID: <{id}@{domain}>\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 7bit\r\n\r\nThis is a one-off test message sent from {hostname} for {domain}.\r\nIt checks how a receiving server treats mail from this address.\r\nNo reply is needed.\r\n",
		from = plan.from,
		to = plan.to,
		domain = plan.domain,
	);
	let mut data = text.into_bytes();
	let header = signer.and_then(|signer| signer.sign(&plan.domain, &data));
	let signed = header.is_some();
	if let Some(header) = header {
		let mut with = Vec::with_capacity(header.len() + data.len());
		with.extend_from_slice(header.as_bytes());
		with.append(&mut data);
		data = with;
	}
	Built { data, signed }
}

/// Load the signer: the `[dkim]` default plus every per-domain key. `None`
/// when `[dkim]` is not configured, so the message goes unsigned and the
/// report says so.
pub(super) fn load_signer(config: &Config) -> std::io::Result<Option<PerDomainSigner>> {
	let Some(dkim) = &config.dkim else {
		return Ok(None);
	};
	let invalid = |error| std::io::Error::new(std::io::ErrorKind::InvalidData, error);
	let active = crate::dkim::rotate::active_ed25519(dkim, &config.data_dir).map_err(invalid)?;
	let mut signer =
		Signer::load(&active.selector, &active.key_file).map_err(std::io::Error::other)?;
	if let Some(rsa) = crate::dkim::rotate::active_rsa(dkim, &config.data_dir).map_err(invalid)? {
		signer = signer
			.with_rsa(&rsa.selector, &rsa.key_file)
			.map_err(std::io::Error::other)?;
	}
	let overrides = crate::cli::serve::dkim::load_per_domain_signers(dkim, &config.data_dir)?;
	Ok(Some(PerDomainSigner::new(
		ReloadableSigner::new(Arc::new(signer)),
		overrides,
	)))
}
