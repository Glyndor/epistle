//! Turning a [`Plan`] into domains, aliases and DKIM settings in the
//! configuration file, key files, and disabled accounts.
//!
//! [`prepare`] decides everything and validates the edited configuration
//! without writing; `--dry-run` stops there. [`apply`] then writes in an
//! order that leaves the server usable if it stops halfway: key files, the
//! configuration, the password file, and last the accounts.
//!
//! Nothing that exists is overwritten. Without `merge` an existing domain,
//! account or alias refuses the whole import; with it, existing ones are
//! kept as they are and reported.

use std::io::Write;
use std::path::{Path, PathBuf};

use serde::Serialize;
use zeroize::Zeroizing;

use super::keys::{Algorithm, to_pem};
use super::{Key, Plan};
use crate::cli::config_edit::ConfigDocument;
use crate::config::Config;
use crate::directory_store::{AccountStore, DynamicAccount};
use crate::util::path_containment::contained_child;

/// How imported accounts get a password.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Passwords {
	/// A random temporary password per account, written to this new file
	/// (mode 0600) as `account<TAB>password` lines.
	File(PathBuf),
	/// A random password nobody is told: the operator sets one later with
	/// `epistle account password`.
	Reset,
}

/// What [`apply`] did, or [`prepare`] would do.
#[derive(Debug, Default, Serialize)]
pub(crate) struct Outcome {
	/// Domains added to the configuration.
	pub(crate) domains_added: Vec<String>,
	/// Domains already configured, left as they were.
	pub(crate) domains_kept: Vec<String>,
	/// Accounts created (disabled for login).
	pub(crate) accounts_added: Vec<String>,
	/// Accounts that already existed, left as they were.
	pub(crate) accounts_kept: Vec<String>,
	/// Aliases added.
	pub(crate) aliases_added: Vec<String>,
	/// Aliases that already existed, left as they were.
	pub(crate) aliases_kept: Vec<String>,
	/// Key files written (paths), one per domain and selector.
	pub(crate) key_files: Vec<String>,
	/// The `[dkim]` change, when the imported keys can sign every domain.
	pub(crate) dkim: Option<String>,
	/// Things the operator has to know.
	pub(crate) notes: Vec<String>,
	/// Whether the configuration file changed (the server then needs a
	/// restart).
	#[serde(skip)]
	pub(crate) config_changed: bool,
}

/// Why an import did not happen.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ApplyError {
	/// Something exists already, or the input is unusable: exit code 2.
	#[error("{0}")]
	Refused(String),
	/// A write failed: exit code 1.
	#[error("{0}")]
	Failed(String),
}

/// Everything decided, ready to write.
pub(crate) struct Prepared {
	/// The outcome to report.
	pub(crate) outcome: Outcome,
	document: ConfigDocument,
	config: Config,
	new_accounts: Vec<super::Account>,
	key_paths: Vec<(PathBuf, usize)>,
}

/// Decide what the import changes, refusing conflicts unless `merge`.
pub(crate) fn prepare(
	plan: &Plan,
	config_path: &Path,
	merge: bool,
) -> Result<Prepared, ApplyError> {
	let mut document = ConfigDocument::open(config_path).map_err(ApplyError::Failed)?;
	let config = document.config().map_err(ApplyError::Failed)?;
	let store = open_store(&config, &config.domains)?;
	let mut outcome = Outcome::default();
	let mut conflicts = Vec::new();

	let mut domains = config.domains.clone();
	for domain in &plan.domains {
		if domains
			.iter()
			.any(|known| known.eq_ignore_ascii_case(domain))
		{
			conflicts.push(format!("domain {domain} is already configured"));
			outcome.domains_kept.push(domain.clone());
		} else {
			domains.push(domain.clone());
			outcome.domains_added.push(domain.clone());
		}
	}
	let existing: Vec<String> = store.account_views().into_iter().map(|v| v.0).collect();
	let mut new_accounts = Vec::new();
	for account in &plan.accounts {
		if existing.iter().any(|name| name == &account.name) {
			conflicts.push(format!("account {} already exists", account.name));
			outcome.accounts_kept.push(account.name.clone());
		} else {
			outcome.accounts_added.push(account.name.clone());
			new_accounts.push(account.clone());
		}
	}
	for alias in &plan.aliases {
		if config
			.alias
			.iter()
			.any(|a| a.address.eq_ignore_ascii_case(&alias.address))
		{
			conflicts.push(format!("alias {} already exists", alias.address));
			outcome.aliases_kept.push(alias.address.clone());
			continue;
		}
		let members = toml_edit::Array::from_iter(alias.members.iter().map(String::as_str));
		document
			.upsert_element(
				"alias",
				"address",
				&alias.address,
				&[
					("members", toml_edit::Value::Array(members)),
					("hidden", toml_edit::Value::from(alias.hidden)),
				],
			)
			.map_err(ApplyError::Failed)?;
		outcome.aliases_added.push(alias.address.clone());
	}
	if !conflicts.is_empty() && !merge {
		return Err(ApplyError::Refused(format!(
			"refusing to overwrite what exists ({}); rerun with --merge to keep those and add the rest",
			conflicts.join("; ")
		)));
	}
	let array = toml_edit::Array::from_iter(domains.iter().map(String::as_str));
	document
		.replace_top_array("domains", array)
		.map_err(ApplyError::Failed)?;

	let key_dir = contained_child(&config.data_dir, "dkim-migrated").map_err(io_failed)?;
	let mut key_paths = Vec::new();
	for (index, key) in plan.keys.iter().enumerate() {
		let path = key_path(&key_dir, key)?;
		outcome.key_files.push(path.display().to_string());
		key_paths.push((path, index));
	}
	choose_dkim(plan, &domains, &key_paths, &mut document, &mut outcome)?;
	document.config().map_err(ApplyError::Failed)?;
	Ok(Prepared {
		outcome,
		document,
		config,
		new_accounts,
		key_paths,
	})
}

/// Write what [`prepare`] decided.
pub(crate) fn apply(
	plan: &Plan,
	prepared: Prepared,
	passwords: &Passwords,
) -> Result<Outcome, ApplyError> {
	let Prepared {
		mut outcome,
		document,
		config,
		new_accounts,
		key_paths,
	} = prepared;
	for (path, index) in &key_paths {
		write_key(path, &plan.keys[*index])?;
	}
	let domains = document.config().map_err(ApplyError::Failed)?.domains;
	outcome.config_changed =
		document.commit().map_err(ApplyError::Failed)? == crate::cli::config_edit::Outcome::Changed;
	let mut secrets: Vec<(String, Zeroizing<String>)> = new_accounts
		.iter()
		.map(|account| Ok((account.name.clone(), temporary_password()?)))
		.collect::<Result<_, ApplyError>>()?;
	if let Passwords::File(path) = passwords {
		write_passwords(path, &secrets)?;
	}
	let store = open_store(&config, &domains)?;
	let policy = crate::password::Policy::from_config(&config.auth);
	for (account, (_, secret)) in new_accounts.iter().zip(secrets.iter_mut()) {
		let created = DynamicAccount::with_password(
			account.name.clone(),
			account.addresses.clone(),
			secret,
			&policy,
			config.auth.scram,
		)
		.and_then(|built| {
			store.add(DynamicAccount {
				disabled: true,
				catch_all: account.catch_all.clone(),
				display_name: account.display_name.clone(),
				..built
			})
		});
		if let Err(error) = created {
			outcome.accounts_added.retain(|name| name != &account.name);
			outcome
				.notes
				.push(format!("account {} was not created: {error}", account.name));
		}
	}
	Ok(outcome)
}

fn open_store(config: &Config, domains: &[String]) -> Result<AccountStore, ApplyError> {
	AccountStore::open(
		&config.data_dir,
		domains.to_vec(),
		config.domain_aliases.clone(),
		config.accounts.clone(),
	)
	.map_err(|error| ApplyError::Failed(format!("opening account store: {error}")))
}

fn io_failed(error: std::io::Error) -> ApplyError {
	ApplyError::Failed(error.to_string())
}

/// `<data_dir>/dkim-migrated/<domain>/<selector>.<algorithm>.pem`.
fn key_path(dir: &Path, key: &Key) -> Result<PathBuf, ApplyError> {
	let algorithm = match key.algorithm {
		Algorithm::Ed25519 => "ed25519",
		Algorithm::Rsa => "rsa",
	};
	let domain_dir = contained_child(dir, &key.domain).map_err(io_failed)?;
	contained_child(&domain_dir, &format!("{}.{algorithm}.pem", key.selector)).map_err(io_failed)
}

/// Write a key file (mode 0600, directories 0700). An existing file with
/// the same key is kept; one with another key is never replaced.
fn write_key(path: &Path, key: &Key) -> Result<(), ApplyError> {
	let pem = to_pem(&key.pkcs8);
	if let Ok(existing) = std::fs::read(path) {
		return if existing == pem.as_bytes() {
			Ok(())
		} else {
			Err(ApplyError::Refused(format!(
				"{} exists and holds another key; move it away first",
				path.display()
			)))
		};
	}
	if let Some(parent) = path.parent() {
		let mut builder = std::fs::DirBuilder::new();
		builder.recursive(true);
		#[cfg(unix)]
		std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
		builder.create(parent).map_err(io_failed)?;
	}
	private_file(path)
		.and_then(|mut file| file.write_all(pem.as_bytes()))
		.map_err(|error| ApplyError::Failed(format!("{}: {error}", path.display())))
}

/// A new file only the owner can read; an existing one is refused.
fn private_file(path: &Path) -> std::io::Result<std::fs::File> {
	let mut options = std::fs::OpenOptions::new();
	options.write(true).create_new(true);
	#[cfg(unix)]
	std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
	options.open(path)
}

fn write_passwords(path: &Path, secrets: &[(String, Zeroizing<String>)]) -> Result<(), ApplyError> {
	let mut body = Zeroizing::new(String::new());
	for (name, secret) in secrets {
		body.push_str(name);
		body.push('\t');
		body.push_str(secret);
		body.push('\n');
	}
	private_file(path)
		.and_then(|mut file| file.write_all(body.as_bytes()))
		.map_err(|error| ApplyError::Refused(format!("{}: {error}", path.display())))
}

/// 24 random octets as URL-safe base64: 32 printable ASCII characters.
fn temporary_password() -> Result<Zeroizing<String>, ApplyError> {
	use base64::Engine;
	let bytes = ring::rand::generate::<[u8; 24]>(&ring::rand::SystemRandom::new())
		.map_err(|_| ApplyError::Failed("the system random generator is unavailable".into()))?
		.expose();
	Ok(Zeroizing::new(
		base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes),
	))
}

/// Point `[dkim]` at the imported keys when one ed25519 key (and at most
/// one RSA key) under one selector covers every configured domain: epistle
/// signs every domain with the same key pair, so per-domain keys cannot
/// all be kept in service.
fn choose_dkim(
	plan: &Plan,
	domains: &[String],
	key_paths: &[(PathBuf, usize)],
	document: &mut ConfigDocument,
	outcome: &mut Outcome,
) -> Result<(), ApplyError> {
	let covering = |algorithm: Algorithm| {
		key_paths.iter().find(|(_, index)| {
			let candidate = &plan.keys[*index];
			candidate.algorithm == algorithm
				&& domains.iter().all(|domain| {
					plan.keys.iter().any(|key| {
						&key.domain == domain
							&& key.algorithm == algorithm
							&& key.selector == candidate.selector
							&& *key.pkcs8 == *candidate.pkcs8
					})
				})
		})
	};
	let has = |algorithm: Algorithm| plan.keys.iter().any(|key| key.algorithm == algorithm);
	let Some((ed_path, ed)) = covering(Algorithm::Ed25519) else {
		if !plan.keys.is_empty() {
			outcome.notes.push(
				"the imported DKIM keys are written to files but [dkim] is left as it is: epistle signs \
				 every domain with one key pair, and no imported key covers every configured \
				 domain under one selector; publish epistle's selector (epistle dns-records) \
				 for the other domains before moving their mail"
					.into(),
			);
		}
		return Ok(());
	};
	let ed_selector = plan.keys[*ed].selector.clone();
	let mut fields: Vec<crate::cli::config_edit::FieldChange> = vec![
		("selector", Some(ed_selector.clone().into())),
		("key_file", Some(ed_path.display().to_string().into())),
	];
	let mut summary = format!("ed25519 selector {ed_selector}");
	match covering(Algorithm::Rsa) {
		Some((rsa_path, rsa)) => {
			let selector = plan.keys[*rsa].selector.clone();
			summary.push_str(&format!(" and rsa selector {selector}"));
			fields.push(("rsa_selector", Some(selector.into())));
			fields.push(("rsa_key_file", Some(rsa_path.display().to_string().into())));
		}
		None => {
			if has(Algorithm::Rsa) {
				outcome.notes.push(
					"the imported RSA keys differ per domain, so only the ed25519 key signs; \
					 receivers that only check RSA see the mail as unsigned"
						.into(),
				);
			}
			fields.push(("rsa_selector", None));
			fields.push(("rsa_key_file", None));
		}
	}
	document
		.set_table_fields(&["dkim"], &fields)
		.map_err(ApplyError::Failed)?;
	outcome.dkim = Some(format!("signing with the imported {summary}"));
	Ok(())
}

#[cfg(test)]
#[path = "apply_tests.rs"]
mod tests;
