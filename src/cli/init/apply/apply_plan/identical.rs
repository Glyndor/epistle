//! Whether the config and compose file on disk already equal what init would write.

use super::super::Answers;
use super::super::ApplyError;
use super::super::apply_config;
use crate::cli::init::compose;

/// Return `true` when an existing config file at `config_path` already
/// matches what `apply` would produce after merging the desired
/// config on top of it. Used by `plan` to decide whether the `config`
/// step should say `identical, not touched` instead of `write`. When
/// no config exists at the path, the answer is `false` (the file
/// would be written). The desired config is built from the planned
/// post-step key state: the RSA key the apply phase generates is
/// included so the plan cannot claim `identical` while the apply
/// phase rewrites the config to add the new RSA fields. The same
/// `Config::load` validation the apply phase runs before returning
/// `Identical` is mirrored here so the plan cannot say "identical, not
/// touched" for a file the rest of the CLI would refuse.
pub(super) fn config_is_identical_to_desired(
	answers: &Answers,
	mail_addr: std::net::IpAddr,
	dkim_ed25519: &std::path::Path,
	dkim_rsa: &std::path::Path,
	cert_file: &std::path::Path,
	key_file: &std::path::Path,
	existing: Option<&apply_config::ExistingConfig>,
) -> Result<bool, ApplyError> {
	let Some(opened) = existing else {
		return Ok(false);
	};
	let existing = &opened.text;
	let config_path = &answers.config_path;
	// The apply phase always lands the RSA key, so the desired config
	// always names it. The plan reads the same signal so the desired
	// config it builds matches the one apply will write a moment later.
	let dkim_rsa_for_desired: Option<&std::path::Path> = Some(dkim_rsa);
	let desired = apply_config::build_config(
		answers,
		mail_addr,
		Some(dkim_ed25519),
		dkim_rsa_for_desired,
		cert_file,
		key_file,
	)?;
	let desired_bytes =
		toml::to_string(&desired).map_err(|error| ApplyError::ConfigEncode(error.to_string()))?;
	let desired_bytes = crate::cli::init::host_secrets::with_storage_key(
		desired_bytes,
		Some(existing.as_str()),
		&answers.data_dir,
	);
	let mut desired_value: toml::Value = toml::from_str(&desired_bytes)
		.map_err(|error| ApplyError::ConfigEncode(error.to_string()))?;
	// What `init` writes only into a new file is not part of the comparison,
	// as it is not part of the merge the apply phase does into this one.
	super::super::apply_config_merge::without_new_install_defaults(&mut desired_value);
	let existing_value: toml::Value = toml::from_str(existing).map_err(|error| {
		ApplyError::ConfigRead(
			config_path.to_path_buf(),
			std::io::Error::other(error.to_string()),
		)
	})?;
	let merged = apply_config::reconcile(existing_value, desired_value, false);
	let existing_parsed = toml::from_str(existing).map_err(|error| {
		ApplyError::ConfigRead(
			config_path.to_path_buf(),
			std::io::Error::other(error.to_string()),
		)
	})?;
	if merged == existing_parsed {
		// The apply phase will refuse to call this `identical` when
		// `Config::load` rejects the on-disk file. Mirror that check
		// here so the plan cannot say `identical, not touched` for a
		// config `config-check` and `serve` would refuse.
		if let Err(error) = opened.validate(config_path) {
			return Err(ApplyError::ConfigInvalid(format!(
				"existing config at {} would be left untouched but is invalid: {}",
				config_path.display(),
				error
			)));
		}
		Ok(true)
	} else {
		Ok(false)
	}
}

/// Count of top-level keys the apply phase writes into the desired
/// config. Used by the plan to tell the operator how much a rewrite
/// will touch. Six keys are always written (`hostname`, `data_dir`,
/// `domains`, `listeners`, `dkim`, `tls`); `public_ipv4`, `public_ipv6`,
/// `dns`, and `database` are added when the operator supplied them.
/// `database` is special: only `url` and `password_file` are managed
/// inside the table; the rest (`directory`, `max_connections`, `tls`)
/// are the operator's to keep.
pub(super) fn managed_key_count(answers: &Answers) -> usize {
	let mut count = 6;
	if answers.public_ipv4.is_some() {
		count += 1;
	}
	if answers.public_ipv6.is_some() {
		count += 1;
	}
	if answers.dns.is_some() {
		count += 1;
	}
	if answers.services.database {
		count += 1;
	}
	count
}

/// `true` when the compose file on disk is already byte-for-byte
/// the bytes the apply phase would write. Used by the plan to
/// decide whether the compose file step says `identical, not
/// touched` or `update` / `write`. A read failure here only
/// means "we cannot tell"; the apply phase re-renders the file
/// and writes it, which is the right behaviour when the disk
/// state is unknown.
pub(super) fn compose_is_identical_to_desired(answers: &Answers) -> Result<bool, ApplyError> {
	let path = compose::compose_file_path(&answers.data_dir);
	let existing = match crate::cli::regular::read::read_to_string(&path) {
		Ok(text) => text,
		Err(_) => return Ok(false),
	};
	let desired = compose::render_for(answers, answers.services.database)?;
	Ok(existing == desired)
}
