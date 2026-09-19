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
}

impl std::fmt::Display for ApplyError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
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
			ApplyError::RsaKeygen(reason) => {
				write!(f, "cannot generate the RSA DKIM key: {reason}")
			}
			ApplyError::Rng(source) => {
				write!(f, "system CSPRNG could not produce bytes for {source}")
			}
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

/// Generate a self-signed certificate for the configured hostname and
/// write the PEM pair to `<keys_dir>/cert.pem` and `<keys_dir>/key.pem`
/// in mode `0600`. The two halves are inspected independently: when
/// both exist they are reused byte-for-byte; when only `key.pem`
/// survives, a replacement self-signed certificate is built from that
/// key without regenerating it; when only `cert.pem` survives the run
/// stops with a recoverable diagnostic rather than overwrite either
/// half. The same generator `epistle local` uses for its loopback
/// harness, so the resulting material loads through the production
/// TLS path.
fn ensure_self_signed_cert(
	keys_dir: &Path,
	hostname: &str,
	report: &mut Report,
) -> Result<(PathBuf, PathBuf), ApplyError> {
	let cert_path = keys_dir.join("cert.pem");
	let key_path = keys_dir.join("key.pem");
	if cert_path.exists() && key_path.exists() {
		report.steps.push(ReportStep::Reused(cert_path.clone()));
		report.steps.push(ReportStep::Reused(key_path.clone()));
		return Ok((cert_path, key_path));
	}
	if cert_path.exists() && !key_path.exists() {
		return Err(ApplyError::CertPairIncomplete(format!(
			"self-signed certificate {} exists but the matching private key {} is missing; restore the private key from backup or delete {} and rerun init",
			cert_path.display(),
			key_path.display(),
			cert_path.display()
		)));
	}
	// Build the certificate parameters once. The hostname was
	// normalised by `Answers::validate` so it always fits the IA5
	// string constraint rcgen imposes; a future Unicode hostname that
	// slips through would still fail later when rcgen validates its
	// own parameter set.
	let mut params = rcgen::CertificateParams::new(vec![hostname.to_string()])
		.expect("certificate params should be valid for any FQDN");
	params.distinguished_name.push(
		rcgen::DnType::CommonName,
		rcgen::DnValue::Utf8String(hostname.to_string()),
	);
	let key_pair = if key_path.exists() {
		// Reuse the surviving private key: load its PEM, decode it,
		// and self-sign the new certificate with it. A corrupt or
		// wrong-algorithm key fails here with a recoverable
		// diagnostic instead of silently regenerating.
		let pem_bytes =
			fs::read(&key_path).map_err(|error| ApplyError::KeyWrite(key_path.clone(), error))?;
		let pem_text = std::str::from_utf8(&pem_bytes).map_err(|_| {
			ApplyError::CertPairIncomplete(format!(
				"self-signed private key {} is not valid utf-8",
				key_path.display()
			))
		})?;
		let key_pair = rcgen::KeyPair::from_pem(pem_text).map_err(|error| {
			ApplyError::CertPairIncomplete(format!(
				"cannot load surviving private key {}: {error}",
				key_path.display()
			))
		})?;
		report.steps.push(ReportStep::Reused(key_path.clone()));
		key_pair
	} else {
		// `rcgen::KeyPair::generate` returns a Result on well-formed
		// hosts; a CSPRNG failure surfaces here as
		// `ApplyError::Rng` so the run exits 1 instead of panicking.
		// The disk write still routes through `write_secret_with_report`.
		let key_pair = rcgen::KeyPair::generate()
			.map_err(|error| ApplyError::Rng(format!("certificate key pair: {error}")))?;
		write_secret_with_report(&key_path, key_pair.serialize_pem().as_bytes(), report)?;
		key_pair
	};
	let cert = params
		.self_signed(&key_pair)
		.expect("self-signing should succeed for the parameters above");
	write_secret_with_report(&cert_path, cert.pem().as_bytes(), report)?;
	Ok((cert_path, key_path))
}

/// Write `bytes` to `path` through `storage::write_secret`. On success
/// the step is pushed into the report before the call returns, so a
/// later step that fails does not lose the earlier `Wrote` line. On
/// failure the path is mapped to `ApplyError::KeyWrite` and the staging
/// temp left by `write_secret` is removed so the next run can proceed
/// without a leftover `O_EXCL` blocker.
fn write_secret_with_report(
	path: &Path,
	bytes: &[u8],
	report: &mut Report,
) -> Result<(), ApplyError> {
	if let Err(error) = crate::storage::write_secret(path, bytes) {
		let tmp = path.with_extension("secret.tmp");
		let _ = fs::remove_file(&tmp);
		return Err(ApplyError::KeyWrite(path.to_path_buf(), error));
	}
	report.steps.push(ReportStep::Wrote(path.to_path_buf()));
	Ok(())
}

/// True when `openssl` is on `PATH` and we can shell out to it. Used by
/// the RSA DKIM key step; false leaves the step out of the apply phase
/// and reports the gap on stderr.
pub(super) fn openssl_available() -> bool {
	apply_plan::openssl_available()
}

/// Run every step: keys, then config. Every file goes through
/// `write_secret` so a crash mid-write cannot leave a half-written file
/// at its destination. The outcome carries every step that completed,
/// including the ones that landed before a later step failed; the
/// caller renders the partial report before the error so the operator
/// can see exactly what is on disk.
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

	let s1 = keys_dir.join("s1.pem");
	let s2 = keys_dir.join("s2.pem");
	let storage = keys_dir.join("storage.key");
	let oauth_private = keys_dir.join("oauth_signing.key");
	let oauth_public = keys_dir.join("oauth_public.key");

	if s1.exists() {
		report.steps.push(ReportStep::Reused(s1.clone()));
	} else {
		// A CSPRNG failure surfaces as `ApplyError::Rng` so the run
		// exits 1 instead of panicking; a disk write failure routes
		// through `write_secret_with_report` with the path intact.
		let (pem, _record) = match crate::dkim::generate_key() {
			Ok(pair) => pair,
			Err(error) => {
				return ApplyOutcome {
					report,
					error: Some(ApplyError::Rng(format!("DKIM ed25519 key: {error}"))),
				};
			}
		};
		if let Err(error) = write_secret_with_report(&s1, pem.as_bytes(), &mut report) {
			return ApplyOutcome {
				report,
				error: Some(error),
			};
		}
	}

	if s2.exists() {
		report.steps.push(ReportStep::Reused(s2.clone()));
	} else if openssl_available() {
		match crate::cli::util::generate_rsa_key(2048) {
			Ok((pem, _record)) => {
				if let Err(error) = write_secret_with_report(&s2, pem.as_bytes(), &mut report) {
					return ApplyOutcome {
						report,
						error: Some(error),
					};
				}
			}
			Err(error) => {
				// openssl is on PATH but the actual key generation
				// failed (broken binary, missing entropy, etc.). The
				// operator asked for the key, the key did not land:
				// stop the run with `ApplyOutcome.error` so the
				// rendered report (which still lists the keys that
				// did land, e.g. s1.pem) is followed by an exit-1
				// diagnostic rather than a silent Skipped line that
				// looks like a successful run.
				return ApplyOutcome {
					report,
					error: Some(ApplyError::RsaKeygen(error.to_string())),
				};
			}
		}
	} else {
		report.steps.push(ReportStep::Skipped {
			name: "dkim rsa key".to_string(),
			reason: "openssl not on PATH; run \"epistle dkim-keygen --rsa\" to create it"
				.to_string(),
		});
	}

	if storage.exists() {
		report.steps.push(ReportStep::Reused(storage.clone()));
	} else {
		let key = match crate::storage::generate_key_base64() {
			Some(key) => key,
			None => {
				return ApplyOutcome {
					report,
					error: Some(ApplyError::Rng("storage key".to_string())),
				};
			}
		};
		if let Err(error) = write_secret_with_report(&storage, key.as_bytes(), &mut report) {
			return ApplyOutcome {
				report,
				error: Some(error),
			};
		}
	}

	if oauth_private.exists() {
		report.steps.push(ReportStep::Reused(oauth_private.clone()));
		let private_bytes = match fs::read(&oauth_private) {
			Ok(bytes) => bytes,
			Err(error) => {
				return ApplyOutcome {
					report,
					error: Some(ApplyError::KeyWrite(oauth_private.clone(), error)),
				};
			}
		};
		let private_text = match std::str::from_utf8(&private_bytes) {
			Ok(text) => text,
			Err(_) => {
				return ApplyOutcome {
					report,
					error: Some(ApplyError::OAuthPairIncomplete(format!(
						"oauth private key {} is not valid utf-8; cannot derive the public key",
						oauth_private.display()
					))),
				};
			}
		};
		let derived_public = match crate::cli::util::derive_oauth_public_from_private(private_text)
		{
			Some(derived) => derived,
			None => {
				return ApplyOutcome {
					report,
					error: Some(ApplyError::OAuthPairIncomplete(format!(
						"oauth private key {} is not a valid PKCS#8 ES256 key; cannot derive the public key",
						oauth_private.display()
					))),
				};
			}
		};
		if oauth_public.exists() {
			let public_bytes = match fs::read(&oauth_public) {
				Ok(bytes) => bytes,
				Err(error) => {
					return ApplyOutcome {
						report,
						error: Some(ApplyError::KeyWrite(oauth_public.clone(), error)),
					};
				}
			};
			let public_text = match std::str::from_utf8(&public_bytes) {
				Ok(text) => text,
				Err(_) => {
					return ApplyOutcome {
						report,
						error: Some(ApplyError::OAuthPairIncomplete(format!(
							"oauth public key {} is not valid utf-8",
							oauth_public.display()
						))),
					};
				}
			};
			if public_text.trim() != derived_public.trim() {
				return ApplyOutcome {
					report,
					error: Some(ApplyError::OAuthPairMismatch),
				};
			}
			report.steps.push(ReportStep::Reused(oauth_public.clone()));
		} else {
			if let Err(error) =
				write_secret_with_report(&oauth_public, derived_public.as_bytes(), &mut report)
			{
				return ApplyOutcome {
					report,
					error: Some(error),
				};
			}
		}
	} else if oauth_public.exists() {
		return ApplyOutcome {
			report,
			error: Some(ApplyError::OAuthPairIncomplete(format!(
				"oauth public key {} exists but the matching private key {} is missing; restore the private key from backup or delete {} and rerun init",
				oauth_public.display(),
				oauth_private.display(),
				oauth_public.display()
			))),
		};
	} else {
		let (private_b64, public_b64) = match crate::cli::util::generate_oauth_keypair() {
			Some(pair) => pair,
			None => {
				return ApplyOutcome {
					report,
					error: Some(ApplyError::Rng("oauth key pair".to_string())),
				};
			}
		};
		if let Err(error) =
			write_secret_with_report(&oauth_private, private_b64.as_bytes(), &mut report)
		{
			return ApplyOutcome {
				report,
				error: Some(error),
			};
		}
		if let Err(error) =
			write_secret_with_report(&oauth_public, public_b64.as_bytes(), &mut report)
		{
			return ApplyOutcome {
				report,
				error: Some(error),
			};
		}
	}

	let dkim_ed25519_path = if s1.exists() { Some(s1.clone()) } else { None };
	let dkim_rsa_path = if s2.exists() { Some(s2.clone()) } else { None };
	let (cert_path, key_path) =
		match ensure_self_signed_cert(&keys_dir, &answers.hostname, &mut report) {
			Ok(pair) => pair,
			Err(error) => {
				return ApplyOutcome {
					report,
					error: Some(error),
				};
			}
		};
	if let Err(error) = ensure_config_parent_dir(&answers.config_path, &mut report) {
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
	match apply_config::merge_with_existing(&answers.config_path, &desired_bytes) {
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

	ApplyOutcome {
		report,
		error: None,
	}
}

#[path = "apply_config.rs"]
mod apply_config;

#[path = "apply_plan.rs"]
mod apply_plan;

pub use apply_plan::plan;

#[cfg(test)]
#[path = "apply_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "apply_tests_b.rs"]
mod tests_b;

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
