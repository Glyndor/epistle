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
#[cfg(test)]
pub(crate) use apply_plan::which_openssl_for_tests as which_openssl;

/// What `apply` actually did: a step list the operator can scan, with
/// every `reused: true` line meaning "the file was already there and
/// was not touched`.
#[derive(Debug, Default)]
pub struct Report {
	/// Every step the apply phase carried out, in order.
	pub steps: Vec<ReportStep>,
}

/// The outcome of a single `apply` call: the steps that completed plus,
/// when a step failed after effects were already on disk, the error
/// that stopped the run. The report is always populated with whatever
/// steps ran before the failure, so the operator can see exactly what
/// landed on their machine.
#[derive(Debug, Default)]
pub struct ApplyOutcome {
	/// Every step that completed, including the step that failed when
	/// it made partial progress.
	pub report: Report,
	/// Set when the apply phase stopped early. `None` means every step
	/// succeeded.
	pub error: Option<ApplyError>,
}

/// One line of the report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportStep {
	/// A file already existed and was left byte-for-byte untouched.
	Reused(PathBuf),
	/// A file was newly written.
	Wrote(PathBuf),
	/// A file was rewritten with new bytes.
	Updated(PathBuf),
	/// The config matched the desired one byte for byte and was not
	/// touched (the file's mtime did not change).
	ConfigIdentical(PathBuf),
	/// A directory was created (typically the parent of `config_path`,
	/// which never existed on a fresh install).
	CreatedDir(PathBuf),
	/// A step was skipped because its precondition did not hold (e.g.
	/// `openssl` was not on `PATH` for the RSA DKIM key).
	Skipped {
		/// Operator-facing name of what was skipped.
		name: String,
		/// Operator-facing reason it was skipped.
		reason: String,
	},
}

impl Report {
	/// Write the report to `out` as one line per entry.
	pub fn write_to(&self, out: &mut impl Write) -> std::io::Result<()> {
		for step in &self.steps {
			match step {
				ReportStep::Reused(p) => writeln!(out, "  reused: {}", p.display())?,
				ReportStep::Wrote(p) => writeln!(out, "  wrote:  {}", p.display())?,
				ReportStep::Updated(p) => writeln!(out, "  updated: {}", p.display())?,
				ReportStep::ConfigIdentical(p) => {
					writeln!(out, "  config identical: {}", p.display())?
				}
				ReportStep::CreatedDir(p) => writeln!(out, "  created dir: {}", p.display())?,
				ReportStep::Skipped { name, reason } => {
					writeln!(out, "  skipped: {name} ({reason})")?
				}
			}
		}
		Ok(())
	}
}

/// Errors the apply phase can produce. Each variant owns its own
/// diagnostic so callers can route it through `style::error` without an
/// intermediate formatting step (and so a taint analyser cannot read a
/// constant string into a key sink).
#[derive(Debug)]
pub enum ApplyError {
	/// The database volume exists without credentials, or its state cannot be checked.
	DatabaseVolume(String),
	/// The data directory could not be created or its `keys/` child
	/// could not be created with mode `0700`.
	KeysDir(PathBuf, std::io::Error),
	/// Writing a secret file (DKIM, storage, OAuth, TLS, self-signed
	/// cert) to disk failed. Distinct from `ConfigWrite` so the
	/// operator-facing message names the secret file and the operator
	/// can recover or rotate that credential.
	KeyWrite(PathBuf, std::io::Error),
	/// The OAuth ES256 key pair is incomplete: only the public half
	/// is on disk and the matching private half is missing. Carries
	/// the operator-facing recovery message (which missing file to
	/// restore or to delete). The apply phase refuses to mint a fresh
	/// unrelated private key because doing so would silently break
	/// every existing token issuer that pins the old public key.
	OAuthPairIncomplete(String),
	/// The OAuth ES256 key pair is present but the two halves do not
	/// correspond: the public point on disk is not derivable from the
	/// private key on disk. Tokens signed with the private key would
	/// not verify against the public one.
	OAuthPairMismatch,
	/// The self-signed certificate pair is incomplete: only the
	/// certificate half is on disk and the matching private key is
	/// missing. The apply phase refuses to mint a fresh key because
	/// doing so would silently break any operator who pinned the old
	/// key in their ACME configuration or backup. Carries the
	/// operator-facing recovery message.
	CertPairIncomplete(String),
	/// Building the desired config from the answers failed (TOML encode).
	ConfigEncode(String),
	/// The candidate config failed to validate through `Config::load`;
	/// the destination was never touched. Carries the formatted
	/// `ConfigError`.
	ConfigInvalid(String),
	/// Reading or rewriting the existing config file failed.
	ConfigRead(PathBuf, std::io::Error),
	/// Writing the new config file through `write_secret` failed.
	ConfigWrite(PathBuf, std::io::Error),
	/// Creating the parent directory of `config_path` failed. Distinct
	/// from `ConfigWrite` so the operator-facing message names the
	/// directory, not the config file.
	ConfigDir(PathBuf, std::io::Error),
	/// `config_path` is a symlink. The apply phase refuses rather than
	/// silently replace the link with a regular file; the operator
	/// has to resolve the link by hand first.
	ConfigSymlink(PathBuf),
	/// `config_path` exists and is not a regular file (a directory,
	/// a fifo, a device, or a socket). The apply phase refuses
	/// rather than silently overwrite or step into a non-file; the
	/// operator has to point `config_path` at a file.
	ConfigNotAFile(PathBuf),
	/// `openssl` is on `PATH` but the `genpkey` invocation failed
	/// (broken binary, missing entropy, etc.) and the RSA DKIM key
	/// could not be produced. Carries the operator-facing reason.
	/// Distinct from `KeyWrite` because no key file was attempted;
	/// the failure is in the key-generation step itself, before any
	/// write would have happened.
	RsaKeygen(String),
	/// The system CSPRNG could not produce bytes for a key (DKIM
	/// ed25519, certificate pair, storage, oauth). Carries the
	/// failing source so the operator can see which key did not
	/// land. The previous shape `expect`-panicked on the same
	/// condition and exited 101 with no report; the run now exits
	/// 1 with the report of what already landed.
	Rng(String),
	/// An existing secret file (today: the database password)
	/// is on disk but cannot be read, a directory in its place,
	/// a `mode 0o000` file, an unreadable mount. The apply phase
	/// refuses to mint a fresh value because PostgreSQL still
	/// holds the old credential in its volume and a new password
	/// would lock epistle out. The error names the path and the
	/// underlying cause so the operator can repair the file's
	/// mode (or remove it by hand) and rerun.
	ExistingSecretUnreadable(PathBuf, std::io::Error),
	/// The answers leave the mail image unset (the default
	/// host-binary shape), but the host binary the compose
	/// file bind-mounts is missing or is not a statically linked
	/// 64-bit LE ELF. The apply phase refuses rather than emit
	/// a compose file the runtime cannot serve: a broken mail
	/// service is worse than a refused `init`. The message names
	/// the failing reason and what the operator needs to do
	/// (install the .deb, or set `image` in the answers).
	HostBinaryInvalid(String),
}

impl std::fmt::Display for ApplyError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			ApplyError::DatabaseVolume(message) => f.write_str(message),
			ApplyError::KeysDir(path, error) => write!(
				f,
				"cannot create keys directory {}: {error}",
				path.display()
			),
			ApplyError::KeyWrite(path, error) => {
				write!(f, "cannot write key file {}: {error}", path.display())
			}
			ApplyError::OAuthPairIncomplete(message) => write!(f, "{message}"),
			ApplyError::OAuthPairMismatch => write!(
				f,
				"oauth public and private keys do not correspond; restore the matching half from backup or delete both and rerun init"
			),
			ApplyError::CertPairIncomplete(message) => write!(f, "{message}"),
			ApplyError::ConfigEncode(message) => {
				write!(f, "cannot encode the desired config: {message}")
			}
			ApplyError::ConfigInvalid(message) => {
				write!(f, "the candidate config is invalid: {message}")
			}
			ApplyError::ConfigRead(path, error) => {
				write!(f, "cannot read existing config {}: {error}", path.display())
			}
			ApplyError::ConfigWrite(path, error) => {
				write!(f, "cannot write config {}: {error}", path.display())
			}
			ApplyError::ConfigDir(path, error) => write!(
				f,
				"cannot create config directory {}: {error}",
				path.display()
			),
			ApplyError::ConfigSymlink(path) => write!(
				f,
				"config_path {} is a symlink; resolve the link (or replace it with its target) and rerun init",
				path.display()
			),
			ApplyError::ConfigNotAFile(path) => write!(
				f,
				"config_path {} exists but is not a regular file; point config_path at a file and rerun init",
				path.display()
			),
			ApplyError::RsaKeygen(reason) => {
				write!(f, "cannot generate the RSA DKIM key: {reason}")
			}
			ApplyError::Rng(source) => {
				write!(f, "system CSPRNG could not produce bytes for {source}")
			}
			ApplyError::ExistingSecretUnreadable(path, error) => write!(
				f,
				"the existing secret at {} cannot be read ({error}); \
				 not replaced to avoid locking the database out, \
				 restore read access (or remove the file by hand) and rerun init",
				path.display()
			),
			ApplyError::HostBinaryInvalid(message) => f.write_str(message),
		}
	}
}

impl std::error::Error for ApplyError {}

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

	let (dkim_ed25519_path, dkim_rsa_path, cert_path, key_path) =
		match apply_keys::ensure_keys_and_certs(&keys_dir, &answers.hostname, &mut report) {
			Ok(paths) => paths,
			Err(error) => {
				return ApplyOutcome {
					report,
					error: Some(error),
				};
			}
		};
	// When ACME is on, the [tls] section points at
	// `<data_dir>/acme/cert.pem` (the renewal loop's target) but
	// the self-signed bootstrap cert is generated next to the
	// other keys in `keys/`. Copy both halves into the ACME path
	// so the server can load them at startup; ACME renewal will
	// overwrite the files in place. Without this step, a fresh
	// install with ACME on would fail to start because the cert
	// the server is told to load is not on disk yet.
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
		let acme_cert = acme_dir.join("cert.pem");
		let acme_key = acme_dir.join("key.pem");
		for (src, dst) in [(&cert_path, &acme_cert), (&key_path, &acme_key)] {
			match fs::read(src) {
				Ok(bytes) => {
					if let Err(error) = crate::storage::write_secret(dst, &bytes) {
						return ApplyOutcome {
							report,
							error: Some(ApplyError::KeyWrite(dst.clone(), error)),
						};
					}
					report.steps.push(ReportStep::Wrote(dst.clone()));
				}
				Err(error) => {
					return ApplyOutcome {
						report,
						error: Some(ApplyError::KeyWrite(src.clone(), error)),
					};
				}
			}
		}
	}
	if let Err(error) = ensure_config_parent_dir(&answers.config_path, &mut report) {
		return ApplyOutcome {
			report,
			error: Some(error),
		};
	}
	// Lay down the database password before the config: `Config::load`
	// opens `[database] password_file` to validate the URL.
	if answers.services.database
		&& let Err(error) = super::compose::ensure_db_password(&answers.data_dir, &mut report)
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
	let desired = apply_config::build_config(
		answers,
		std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
		dkim_ed25519_path.as_deref(),
		dkim_rsa_path.as_deref(),
		&cert_path,
		&key_path,
	)
	.expect("build_config always succeeds for the inputs apply supplies");
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

#[path = "apply_config.rs"]
mod apply_config;
#[path = "apply_config_acme.rs"]
mod apply_config_acme;
#[path = "apply_config_merge.rs"]
mod apply_config_merge;

#[path = "apply_plan.rs"]
mod apply_plan;

#[path = "apply_keys.rs"]
mod apply_keys;

pub use apply_plan::plan;

/// The set of listeners `init` will write into the config.
/// Re-exported so the compose step (a sibling of `apply`) can
/// derive the published-port list from the same listener set
/// the config-write step wrote, without taking a second pass
/// at the apply-internal `apply_config` module.
pub(crate) use apply_config::listeners_to_write;

/// Re-export so the apply tests can call into the keys module
/// without the rest of the crate going through `apply::apply_keys`.
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use apply_keys::openssl_available;

#[cfg(test)]
#[path = "apply_tests.rs"]
mod tests;
#[cfg(test)]
#[path = "apply_tests_acme.rs"]
mod tests_acme;
#[cfg(test)]
#[path = "apply_tests_b.rs"]
mod tests_b;
#[cfg(test)]
#[path = "apply_bind_tests.rs"]
mod tests_bind;
#[cfg(test)]
#[path = "apply_tests_c.rs"]
mod tests_c;
#[cfg(test)]
#[path = "apply_tests_d.rs"]
mod tests_d;
#[cfg(test)]
#[path = "apply_failures_tests.rs"]
mod tests_failures;
#[cfg(test)]
#[path = "apply_failures_tests_b.rs"]
mod tests_failures_b;
#[cfg(test)]
#[path = "apply_failures_tests_c.rs"]
mod tests_failures_c;
#[cfg(test)]
#[path = "apply_failures_tests_d.rs"]
mod tests_failures_d;
#[cfg(test)]
#[path = "apply_tests_implicit_tls.rs"]
mod tests_implicit_tls;
#[cfg(test)]
#[path = "apply_keep_listeners_tests.rs"]
mod tests_keep_listeners;
#[cfg(test)]
#[path = "apply_listeners_lines_tests.rs"]
mod tests_listeners_lines;

pub(crate) use apply_config_merge::set_listener_enabled;
