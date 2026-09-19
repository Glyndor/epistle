//! Build the plan from the answers and the disk state.
//!
//! Split off from `apply.rs` to keep the per-file line limit; the
//! functions here are read-only and never touch the operator's
//! machine. `apply` re-derives the same decisions step by step so a
//! step that succeeds here cannot silently disappear in `apply`.

use super::Answers;
use super::ApplyError;
use super::apply_config;
use crate::cli::init::plan::{Plan, PlanStep};

/// True when `openssl` is on `PATH` and the RSA DKIM key step can be
/// generated. Used by the plan step so the operator sees the skip text
/// in advance.
pub(super) fn openssl_available() -> bool {
	which_openssl()
}

#[cfg(unix)]
fn which_openssl() -> bool {
	use std::process::Command;
	Command::new("openssl")
		.arg("version")
		.stdin(std::process::Stdio::null())
		.stdout(std::process::Stdio::null())
		.stderr(std::process::Stdio::null())
		.status()
		.map(|status| status.success())
		.unwrap_or(false)
}

#[cfg(not(unix))]
fn which_openssl() -> bool {
	false
}

/// Re-export so the apply-phase tests can ask whether `openssl` is on
/// `PATH` the same way the plan and apply phases do.
#[cfg(test)]
pub(crate) fn which_openssl_for_tests() -> bool {
	openssl_available()
}

/// Walk the answers and produce the plan, WITHOUT writing anything. The
/// plan is what the operator reads before the confirmation prompt; it
/// is computed from the disk so a re-run says `reuse` for every key
/// the apply phase would also reuse, and `identical` for a config the
/// apply phase would leave alone. The apply phase re-derives the
/// decision on every step so a step that succeeds in `plan` cannot
/// silently disappear in `apply`.
pub fn plan(answers: &Answers) -> Result<Plan, ApplyError> {
	let keys_dir = answers.data_dir.join("keys");
	let s1 = keys_dir.join("s1.pem");
	let s2 = keys_dir.join("s2.pem");
	let storage = keys_dir.join("storage.key");
	let oauth_private = keys_dir.join("oauth_signing.key");
	let oauth_public = keys_dir.join("oauth_public.key");
	let cert_path = keys_dir.join("cert.pem");
	let key_path = keys_dir.join("key.pem");
	let oauth_private_exists = oauth_private.exists();
	let oauth_public_exists = oauth_public.exists();
	let oauth_pair = resolve_oauth_pair(
		oauth_private_exists,
		oauth_public_exists,
		&oauth_private,
		&oauth_public,
	)?;
	// Directory steps first: every write that follows needs the
	// directory it lives in. The previous shape listed the five key
	// writes ahead of the directory creation that those writes
	// depend on, so the operator read a plan that said "we will
	// write s1.pem" before "we will create data_dir". The apply
	// phase creates the directories first, and the plan now
	// mirrors that order so the operator sees the same shape they
	// will see in the report.
	let mut steps = Vec::new();
	if !answers.data_dir.exists() {
		steps.push(PlanStep::DataDir {
			path: answers.data_dir.clone(),
		});
	}
	if let Some(parent) = answers.config_path.parent()
		&& !parent.as_os_str().is_empty()
		&& !parent.exists()
	{
		steps.push(PlanStep::ConfigDir {
			path: parent.to_path_buf(),
		});
	}
	steps.extend([
		PlanStep::DkimEd25519 {
			path: s1.clone(),
			reused: s1.exists(),
		},
		PlanStep::DkimRsa {
			path: s2.clone(),
			reused: s2.exists(),
			openssl_available: openssl_available(),
		},
		PlanStep::Storage {
			path: storage.clone(),
			reused: storage.exists(),
		},
		PlanStep::OAuthPrivate {
			path: oauth_private.clone(),
			reused: oauth_pair.private_reused,
		},
		PlanStep::OAuthPublic {
			path: oauth_public.clone(),
			reused: oauth_pair.public_reused,
		},
	]);
	let cert_exists = cert_path.exists();
	let key_exists = key_path.exists();
	if cert_exists && !key_exists {
		// The apply phase refuses with a recoverable diagnostic;
		// the plan carries the same shape so the operator sees the
		// refusal before confirming.
		return Err(ApplyError::CertPairIncomplete(format!(
			"self-signed certificate {} exists but the matching private key {} is missing; restore the private key from backup or delete {} and rerun init",
			cert_path.display(),
			key_path.display(),
			cert_path.display()
		)));
	}
	steps.push(PlanStep::SelfSignedCert {
		cert_path: cert_path.clone(),
		key_path: key_path.clone(),
		reused: cert_exists && key_exists,
		key_reused: key_exists,
	});
	let identical = config_is_identical_to_desired(
		answers,
		&s1,
		&s2,
		&cert_path,
		&key_path,
		&answers.config_path,
	)?;
	let file_exists = answers.config_path.exists();
	let count = managed_key_count(answers);
	steps.push(PlanStep::Config {
		path: answers.config_path.clone(),
		identical,
		file_exists,
		count,
		preserves_comments: false,
	});
	if let Some(dns) = &answers.dns {
		steps.push(PlanStep::Dns {
			provider: dns.provider.clone(),
			zone: dns.zone.clone(),
		});
	}
	Ok(Plan { steps })
}

/// What the apply phase will do for the OAuth ES256 key pair. `private_reused`
/// is `true` when the apply phase will leave the private key on disk
/// untouched; `public_reused` is `true` when the apply phase will leave the
/// public key on disk untouched. The plan and the apply phase both call
/// this function so the two agree on whether each half is reused.
struct OAuthPairDecision {
	/// `true` when the apply phase will reuse the existing private key.
	private_reused: bool,
	/// `true` when the apply phase will reuse the existing public key.
	public_reused: bool,
}

/// Resolve the OAuth pair-state decision shared by plan and apply. Returns
/// `Err` when only the public half exists (the apply phase refuses to mint a
/// fresh unrelated private key) or when both halves exist but do not
/// correspond. The plan surfaces these as errors so the operator sees the
/// refusal before confirming.
fn resolve_oauth_pair(
	private_exists: bool,
	public_exists: bool,
	private_path: &std::path::Path,
	public_path: &std::path::Path,
) -> Result<OAuthPairDecision, ApplyError> {
	match (private_exists, public_exists) {
		(true, true) => {
			// Both halves exist; the apply phase verifies they
			// correspond before reusing. The plan cannot fail here
			// unless the on-disk bytes decode to something that is
			// not a P-256 PKCS#8 key; a corrupt file is reported as
			// `OAuthPairIncomplete` so the operator sees the same
			// shape of error whether they hit it in `plan` or
			// `apply`.
			let private_bytes = std::fs::read(private_path)
				.map_err(|error| ApplyError::KeyWrite(private_path.to_path_buf(), error))?;
			let private_text = std::str::from_utf8(&private_bytes).map_err(|_| {
				ApplyError::OAuthPairIncomplete(format!(
					"oauth private key {} is not valid utf-8; cannot derive the public key",
					private_path.display()
				))
			})?;
			let derived = crate::cli::util::derive_oauth_public_from_private(private_text)
				.ok_or_else(|| {
					ApplyError::OAuthPairIncomplete(format!(
						"oauth private key {} is not a valid PKCS#8 ES256 key; cannot derive the public key",
						private_path.display()
					))
				})?;
			let public_bytes = std::fs::read(public_path)
				.map_err(|error| ApplyError::KeyWrite(public_path.to_path_buf(), error))?;
			let public_text = std::str::from_utf8(&public_bytes).map_err(|_| {
				ApplyError::OAuthPairIncomplete(format!(
					"oauth public key {} is not valid utf-8",
					public_path.display()
				))
			})?;
			if public_text.trim() != derived.trim() {
				return Err(ApplyError::OAuthPairMismatch);
			}
			Ok(OAuthPairDecision {
				private_reused: true,
				public_reused: true,
			})
		}
		(true, false) => {
			// The apply phase derives the public from the private
			// and writes it. The plan says private is reused, public
			// is not (the apply phase writes it).
			Ok(OAuthPairDecision {
				private_reused: true,
				public_reused: false,
			})
		}
		(false, true) => Err(ApplyError::OAuthPairIncomplete(format!(
			"oauth public key {} exists but the matching private key {} is missing; restore the private key from backup or delete {} and rerun init",
			public_path.display(),
			private_path.display(),
			public_path.display()
		))),
		(false, false) => Ok(OAuthPairDecision {
			private_reused: false,
			public_reused: false,
		}),
	}
}

/// Return `true` when an existing config file at `config_path` already
/// matches what `apply` would produce after merging the desired
/// config on top of it. Used by `plan` to decide whether the `config`
/// step should say `identical, not touched` instead of `write`. When
/// no config exists at the path, the answer is `false` (the file
/// would be written). The desired config is built from the planned
/// post-step key state: an RSA key scheduled for generation (openssl
/// on PATH, file not yet on disk) is included so the plan cannot
/// claim `identical` while the apply phase rewrites the config to
/// add the new RSA fields. The same `Config::load` validation the
/// apply phase runs before returning `Identical` is mirrored here so
/// the plan cannot say "identical, not touched" for a file the rest
/// of the CLI would refuse.
fn config_is_identical_to_desired(
	answers: &Answers,
	dkim_ed25519: &std::path::Path,
	dkim_rsa: &std::path::Path,
	cert_file: &std::path::Path,
	key_file: &std::path::Path,
	config_path: &std::path::Path,
) -> Result<bool, ApplyError> {
	// A read failure here only means "we cannot tell whether the
	// existing file matches the desired one". The apply phase will
	// surface the same read failure with its own error variant; the
	// plan, which only describes what the operator is about to see,
	// can safely say "we will write a fresh config" and let the
	// apply phase handle the failure.
	let existing = match std::fs::read_to_string(config_path) {
		Ok(text) => text,
		Err(_) => return Ok(false),
	};
	// The apply phase will land `dkim_rsa` if openssl is on PATH or
	// if the file already exists. The plan reads the same signals so
	// the desired config it builds matches the one apply will write
	// a moment later.
	let dkim_rsa_for_desired: Option<&std::path::Path> = if dkim_rsa.exists() || openssl_available()
	{
		Some(dkim_rsa)
	} else {
		None
	};
	let desired = apply_config::build_config(
		answers,
		Some(dkim_ed25519),
		dkim_rsa_for_desired,
		cert_file,
		key_file,
	)?;
	let desired_bytes =
		toml::to_string(&desired).map_err(|error| ApplyError::ConfigEncode(error.to_string()))?;
	let desired_value: toml::Value = toml::from_str(&desired_bytes)
		.map_err(|error| ApplyError::ConfigEncode(error.to_string()))?;
	let existing_value: toml::Value = toml::from_str(&existing).map_err(|error| {
		ApplyError::ConfigRead(
			config_path.to_path_buf(),
			std::io::Error::other(error.to_string()),
		)
	})?;
	let merged = apply_config::reconcile(existing_value, desired_value);
	let existing_parsed = toml::from_str(&existing).map_err(|error| {
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
		if let Err(error) = crate::config::Config::load(config_path) {
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
/// and `dns` are added when the operator supplied them.
fn managed_key_count(answers: &Answers) -> usize {
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
	count
}
