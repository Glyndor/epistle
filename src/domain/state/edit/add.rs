//! What adding a domain makes besides the entry: the DKIM key it signs with
//! and the secret its forwarded mail is signed with. `epistle domain add` and
//! `POST /api/v1/domains` both build their [`Change::Add`] here.

use std::path::PathBuf;

use crate::config::Config;
use crate::dkim::domain_keys;

use super::super::file::{OwnKey, StoredRole};
use super::{Change, EditError, rules};

/// How a new domain signs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Signing {
	/// With a key of its own, made now under `keys/dkim/<domain>/`.
	#[default]
	OwnKey,
	/// With the `[dkim]` key every domain without one shares.
	SharedKey,
}

/// A [`Change::Add`] ready to commit, and the key files made for it.
#[derive(Debug, Clone)]
pub struct Prepared {
	/// The change.
	pub change: Change,
	/// The key files this call wrote. When the change is not committed they
	/// are removed with [`discard`], so nothing names them.
	pub created: Vec<PathBuf>,
	/// The selector of the new key, when one was made or planned.
	pub selector: Option<String>,
}

/// Check `raw` as a new domain of `config` and make what it needs.
///
/// With `[dkim]` configured and [`Signing::OwnKey`], the domain gets a key of
/// its own unless the configuration file already names one for it; a dry
/// run names the key without writing it. The domain also gets an SRS secret
/// of its own, so it never signs what it forwards with a secret shared with
/// the other domains. `now` is the clock the key's selector is named after.
pub fn prepare(
	config: &Config,
	raw: &str,
	role: StoredRole,
	(signing, dry_run): (Signing, bool),
	now: u64,
) -> Result<Prepared, EditError> {
	let name = rules::check_new_domain(config, raw)?;
	let secret = crate::queue::srs::generate_secret().ok_or_else(|| {
		EditError::Io("the system gave no random bytes for the domain's SRS secret".into())
	})?;
	let (dkim, created) = own_key(config, &name, signing, dry_run, now)?;
	let selector = dkim.as_ref().map(|key| key.selector.clone());
	Ok(Prepared {
		change: Change::Add {
			name,
			role,
			dkim,
			srs_secret: Some(secret),
		},
		created,
		selector,
	})
}

/// Remove the key files of a [`Prepared`] whose change was not committed.
pub fn discard(prepared: &Prepared) {
	domain_keys::remove(&prepared.created);
}

fn own_key(
	config: &Config,
	name: &str,
	signing: Signing,
	dry_run: bool,
	now: u64,
) -> Result<(Option<OwnKey>, Vec<PathBuf>), EditError> {
	let Some(dkim) = config.dkim.as_ref() else {
		return Ok((None, Vec::new()));
	};
	if signing == Signing::SharedKey
		|| config
			.domain_seed
			.dkim_domains
			.iter()
			.any(|entry| entry.name.eq_ignore_ascii_case(name))
	{
		return Ok((None, Vec::new()));
	}
	let dual = dkim.rsa_selector.is_some() && dkim.rsa_key_file.is_some();
	let reserved = domain_keys::reserved_selectors(config).map_err(EditError::Io)?;
	let (keys, created) = if dry_run {
		(
			domain_keys::planned(&config.data_dir, name, dual, now, &reserved)
				.map_err(EditError::Io)?,
			Vec::new(),
		)
	} else {
		domain_keys::ensure(&config.data_dir, name, dual, now, &reserved).map_err(EditError::Io)?
	};
	let (rsa_selector, rsa_key_file) = match keys.rsa {
		Some((selector, file)) => (Some(selector), Some(file)),
		None => (None, None),
	};
	Ok((
		Some(OwnKey {
			selector: keys.selector,
			key_file: keys.key_file,
			rsa_selector,
			rsa_key_file,
		}),
		created,
	))
}
