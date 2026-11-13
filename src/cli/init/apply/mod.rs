//! Apply: read an `Answers`, build the plan, write the keys, write the
//! config, print the report.
//!
//! Every file is written through `crate::storage::write_secret` (write
//! to a sibling temp, fsync, rename, 0600) so a crash mid-write cannot
//! leave a half-written secret in place. The config goes through the
//! same path with an extra gate: the candidate must pass `Config::load`
//! before the rename, so a config that would not validate never reaches
//! its destination.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use super::answers::Answers;
#[cfg(test)]
pub(crate) use super::plan::PlanStep;

/// Ensure `data_dir` exists with mode `0700`. When the directory does
/// not exist yet, create it at `0700` and record a `CreatedDir` step
/// in the report so the operator sees it. When it already exists with
/// looser permissions, warn on stderr naming the mode rather than
/// tightening it: a hand-crafted directory the operator put there on
/// purpose (e.g. mounted with wider group access for backup tooling)
/// must not be silently changed.
fn ensure_data_dir(data_dir: &Path, report: &mut Report) -> Result<(), ApplyError> {
	if !data_dir.exists() {
		fs::create_dir_all(data_dir)
			.map_err(|error| ApplyError::KeysDir(data_dir.to_path_buf(), error))?;
		#[cfg(unix)]
		{
			use std::os::unix::fs::PermissionsExt;
			let permissions = std::fs::Permissions::from_mode(0o700);
			fs::set_permissions(data_dir, permissions)
				.map_err(|error| ApplyError::KeysDir(data_dir.to_path_buf(), error))?;
		}
		report
			.steps
			.push(ReportStep::CreatedDir(data_dir.to_path_buf()));
		return Ok(());
	}
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		let metadata = fs::metadata(data_dir)
			.map_err(|error| ApplyError::KeysDir(data_dir.to_path_buf(), error))?;
		let mode = metadata.permissions().mode() & 0o777;
		if mode > 0o700 {
			let mut out = crate::cli::style::stderr();
			let _ = writeln!(
				out,
				"warning: data_dir {} exists with mode {:04o}; init will not change it, tighten by hand if you want owner-only access",
				data_dir.display(),
				mode
			);
		}
	}
	Ok(())
}

/// Compute the key directory under `data_dir`. Created on demand with
/// mode `0700`; existing directories are left untouched but their mode
/// is tightened so a hand-crafted tree the operator wrote cannot keep
/// wider permissions than `init` itself enforces.
fn ensure_keys_dir(data_dir: &Path) -> Result<PathBuf, ApplyError> {
	let dir = data_dir.join("keys");
	fs::create_dir_all(&dir).map_err(|error| ApplyError::KeysDir(dir.clone(), error))?;
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		let permissions = std::fs::Permissions::from_mode(0o700);
		fs::set_permissions(&dir, permissions)
			.map_err(|error| ApplyError::KeysDir(dir.clone(), error))?;
	}
	Ok(dir)
}

/// Create the parent directory of `config_path` with mode `0750` if it
/// does not exist. The directory is left untouched when it already
/// exists: on a fresh install `/etc/epistle/` is absent and `init` lays
/// it down; on a re-run the operator's `/etc/epistle/` keeps whatever
/// mode they already had.
fn ensure_config_parent_dir(config_path: &Path, report: &mut Report) -> Result<(), ApplyError> {
	let Some(parent) = config_path.parent() else {
		return Err(ApplyError::ConfigInvalid(format!(
			"config_path {} has no parent directory",
			config_path.display()
		)));
	};
	if parent.as_os_str().is_empty() || parent.exists() {
		return Ok(());
	}
	fs::create_dir_all(parent)
		.map_err(|error| ApplyError::ConfigDir(parent.to_path_buf(), error))?;
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		let permissions = std::fs::Permissions::from_mode(0o750);
		fs::set_permissions(parent, permissions)
			.map_err(|error| ApplyError::ConfigDir(parent.to_path_buf(), error))?;
	}
	report
		.steps
		.push(ReportStep::CreatedDir(parent.to_path_buf()));
	Ok(())
}

/// Run every step: keys, then config. Every file goes through
/// `write_secret` so a crash mid-write cannot leave a half-written file
/// at its destination. The outcome carries every step that completed,
/// including the ones that landed before a later step failed; the
/// caller renders the partial report before the error so the operator
/// can see exactly what is on disk.
///
/// Mail listeners bind the dual-stack IPv6 any (`::`) so an IPv4
/// client and an IPv6 client can both reach the server. The
/// management API listener binds loopback (`127.0.0.1`) because it
/// is closed to the network by design.
pub fn apply(answers: &Answers) -> ApplyOutcome {
	let mut report = Report::default();
	if let Err(error) = ensure_data_dir(&answers.data_dir, &mut report) {
		return ApplyOutcome {
			report,
			error: Some(error),
		};
	}
	let keys_dir = match ensure_keys_dir(&answers.data_dir) {
		Ok(dir) => dir,
		Err(error) => {
			return ApplyOutcome {
				report,
				error: Some(error),
			};
		}
	};

	match super::host_secrets::move_legacy_keys(&answers.data_dir) {
		Ok(moved) => report.steps.extend(
			moved
				.into_iter()
				.map(|(from, to)| ReportStep::Moved { from, to }),
		),
		Err(message) => {
			return ApplyOutcome {
				report,
				error: Some(ApplyError::KeyMove(message)),
			};
		}
	}
	let secrets_dir = super::host_secrets::dir(&answers.data_dir);
	let (dkim_ed25519_path, dkim_rsa_path, cert_path, key_path) =
		match apply_keys::ensure_keys_and_certs(
			&keys_dir,
			&secrets_dir,
			&answers.hostname,
			&mut report,
		) {
			Ok(paths) => paths,
			Err(error) => {
				return ApplyOutcome {
					report,
					error: Some(error),
				};
			}
		};
	// When ACME is on, the renewal loop writes the certificate the
	// authority issues to `<data_dir>/acme/cert.pem` and
	// `<data_dir>/acme/key.pem`. The directory is created here so it
	// carries the same mode as the rest of the data tree, but it
	// stays empty: a bootstrap certificate written there would be
	// read by `needs_renewal` as a certificate valid until the year
	// 4096, so the first boot would never place an order and the
	// host would serve the bootstrap forever. The server loads the
	// self-signed pair from `keys/` (the `[tls]` section points
	// there) until the authority answers, and
	// `crate::tls::served_tls` prefers the ACME pair from then on.
	if apply_config_acme::should_enable_acme(answers) {
		let acme_dir = answers.data_dir.join("acme");
		if let Err(error) = fs::create_dir_all(&acme_dir) {
			return ApplyOutcome {
				report,
				error: Some(ApplyError::KeyWrite(acme_dir.clone(), error)),
			};
		}
		#[cfg(unix)]
		{
			use std::os::unix::fs::PermissionsExt;
			if let Err(error) =
				fs::set_permissions(&acme_dir, std::fs::Permissions::from_mode(0o700))
			{
				return ApplyOutcome {
					report,
					error: Some(ApplyError::KeyWrite(acme_dir.clone(), error)),
				};
			}
		}
	}
	if let Err(error) = ensure_config_parent_dir(&answers.config_path, &mut report) {
		return ApplyOutcome {
			report,
			error: Some(error),
		};
	}
	let _held = match crate::cli::service::lock::acquire(&answers.config_path) {
		Ok(held) => held,
		Err(error) => {
			return ApplyOutcome {
				report,
				error: Some(ApplyError::ConfigRead(
					answers.config_path.clone(),
					std::io::Error::other(error),
				)),
			};
		}
	};
	// Lay down the database password before the config: `Config::load`
	// opens `[database] password_file` to validate the URL.
	if answers.services.database
		&& let Err(error) = super::compose::ensure_db_password(&answers.data_dir, &mut report)
			.and_then(|_| super::compose::ensure_db_admin_password(&answers.data_dir, &mut report))
	{
		return ApplyOutcome {
			report,
			error: Some(error),
		};
	}
	// `build_config` cannot fail from any caller: the apply phase always
	// supplies Some for `dkim_ed25519_path`, and the (None, _) arm in
	// `build_config` is now `unreachable!()`. The `.expect` documents
	// the invariant for the next reader.
	let mut desired = apply_config::build_config(
		answers,
		std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
		dkim_ed25519_path.as_deref(),
		dkim_rsa_path.as_deref(),
		&cert_path,
		&key_path,
	)
	.expect("build_config always succeeds for the inputs apply supplies");
	// A configuration `init` creates gives every domain after the first a
	// key of its own. One that exists keeps the keys it has: re-running
	// `init` neither adds nor takes away a domain's key.
	if std::fs::symlink_metadata(&answers.config_path).is_err() {
		match apply_keys::ensure_domain_keys(
			&answers.data_dir,
			&answers.domains,
			dkim_rsa_path.is_some(),
			&mut report,
		) {
			Ok(entries) => desired.dkim.domain = entries,
			Err(error) => {
				return ApplyOutcome {
					report,
					error: Some(error),
				};
			}
		}
	}
	// `toml::to_string` on a `DesiredConfig` whose fields are all
	// plain strings, vecs and nested structs cannot fail; the only
	// way it would is if a future field required custom serialisation
	// that returned an error, which is currently impossible.
	let desired_bytes = toml::to_string(&desired).expect("DesiredConfig serialises without errors");
	let existing = match apply_config::read_config(&answers.config_path) {
		Ok(existing) => existing,
		Err(error) => {
			return ApplyOutcome {
				report,
				error: Some(error),
			};
		}
	};
	let desired_bytes = super::host_secrets::with_storage_key(
		desired_bytes,
		existing.as_ref().map(|existing| existing.text.as_str()),
		&answers.data_dir,
	);
	let keep_existing_listeners =
		match apply_config::listeners_from_existing(&answers.config_path, existing.as_ref()) {
			Ok(listeners) => listeners.is_some(),
			Err(error) => {
				return ApplyOutcome {
					report,
					error: Some(error),
				};
			}
		};
	match apply_config::merge_with_read_config(
		&answers.config_path,
		&desired_bytes,
		keep_existing_listeners,
		existing.as_ref(),
	) {
		Ok(apply_config::ConfigWrite::Identical) => report
			.steps
			.push(ReportStep::ConfigIdentical(answers.config_path.clone())),
		Ok(apply_config::ConfigWrite::Wrote) => report
			.steps
			.push(ReportStep::Wrote(answers.config_path.clone())),
		Ok(apply_config::ConfigWrite::Updated) => report
			.steps
			.push(ReportStep::Updated(answers.config_path.clone())),
		Err(error) => {
			return ApplyOutcome {
				report,
				error: Some(error),
			};
		}
	}

	// The compose file is the last step. It is independent of the
	// config and the keys, but a config-write failure must not
	// leave a half-rendered compose file on disk.
	if let Err(error) = super::compose::write_compose_step(answers, &mut report) {
		return ApplyOutcome {
			report,
			error: Some(error),
		};
	}
	ApplyOutcome {
		report,
		error: None,
	}
}

mod error;
mod report;
pub use self::error::ApplyError;
pub use self::report::{ApplyOutcome, Report, ReportStep};

mod apply_config;
mod apply_config_acme;
mod apply_config_merge;

mod apply_plan;

mod apply_keys;
pub(crate) use apply_keys::prepare_keys_for_update;

pub use apply_plan::plan;

/// The set of listeners `init` will write into the config.
/// Re-exported so the compose step (a sibling of `apply`) can
/// derive the published-port list from the same listener set
/// the config-write step wrote, without taking a second pass
/// at the apply-internal `apply_config` module.
pub(crate) use apply_config::listeners_to_write;

#[cfg(test)]
mod tests;
