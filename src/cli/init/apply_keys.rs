//! Key and certificate generation for the apply phase.
//!
//! Split off from `apply.rs` to keep the per-file line limit. The
//! functions here write every key under `<data_dir>/keys/`
//! (DKIM ed25519, DKIM RSA, storage, OAuth ES256) plus the
//! self-signed certificate pair. Every file goes through
//! `storage::write_secret` so a crash mid-write cannot leave a
//! half-written secret in place. Each step pushes a `Reused`
//! or `Wrote` line into the report so the operator sees what
//! landed; a generation or write failure surfaces as
//! `ApplyError::*` and the caller stops the run with the report
//! of the keys that already landed.

use std::fs;
use std::path::{Path, PathBuf};

use super::apply_plan;
use super::{ApplyError, Report, ReportStep};

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

/// Lay down the five key-tree files under `keys_dir`:
/// `s1.pem` (DKIM ed25519), `s2.pem` (DKIM RSA via openssl, or
/// skipped when openssl is not on PATH, or refused when genpkey
/// fails), `storage.key`, and the OAuth ES256 pair (private +
/// public). Each step pushes a `Reused` or `Wrote` line into the
/// report; a generation or write failure surfaces as
/// `ApplyError::*` and the caller stops the run with the report
/// of the keys that already landed.
fn ensure_key_tree(
	s1: &Path,
	s2: &Path,
	storage: &Path,
	oauth_private: &Path,
	oauth_public: &Path,
	report: &mut Report,
) -> Result<(), ApplyError> {
	if s1.exists() {
		report.steps.push(ReportStep::Reused(s1.to_path_buf()));
	} else {
		// A CSPRNG failure surfaces as `ApplyError::Rng` so the run
		// exits 1 instead of panicking; a disk write failure routes
		// through `write_secret_with_report` with the path intact.
		let (pem, _record) = crate::dkim::generate_key()
			.map_err(|error| ApplyError::Rng(format!("DKIM ed25519 key: {error}")))?;
		write_secret_with_report(s1, pem.as_bytes(), report)?;
	}

	if s2.exists() {
		report.steps.push(ReportStep::Reused(s2.to_path_buf()));
	} else if openssl_available() {
		let (pem, _record) = match crate::cli::util::generate_rsa_key(2048) {
			Ok(pair) => pair,
			Err(error) => {
				// openssl is on PATH but the actual key generation
				// failed (broken binary, missing entropy, etc.). The
				// operator asked for the key, the key did not land:
				// the run exits 1 with the report of the keys that
				// did land rather than a silent Skipped line.
				return Err(ApplyError::RsaKeygen(error.to_string()));
			}
		};
		write_secret_with_report(s2, pem.as_bytes(), report)?;
	} else {
		report.steps.push(ReportStep::Skipped {
			name: "dkim rsa key".to_string(),
			reason: "openssl not on PATH; run \"epistle dkim-keygen --rsa\" to create it"
				.to_string(),
		});
	}

	if storage.exists() {
		report.steps.push(ReportStep::Reused(storage.to_path_buf()));
	} else {
		let key = crate::storage::generate_key_base64()
			.ok_or_else(|| ApplyError::Rng("storage key".to_string()))?;
		write_secret_with_report(storage, key.as_bytes(), report)?;
	}

	if oauth_private.exists() {
		report
			.steps
			.push(ReportStep::Reused(oauth_private.to_path_buf()));
		let private_bytes = fs::read(oauth_private)
			.map_err(|error| ApplyError::KeyWrite(oauth_private.to_path_buf(), error))?;
		let private_text = std::str::from_utf8(&private_bytes).map_err(|_| {
			ApplyError::OAuthPairIncomplete(format!(
				"oauth private key {} is not valid utf-8; cannot derive the public key",
				oauth_private.display()
			))
		})?;
		let derived_public = crate::cli::util::derive_oauth_public_from_private(private_text)
			.ok_or_else(|| {
				ApplyError::OAuthPairIncomplete(format!(
					"oauth private key {} is not a valid PKCS#8 ES256 key; cannot derive the public key",
					oauth_private.display()
				))
			})?;
		if oauth_public.exists() {
			let public_bytes = fs::read(oauth_public)
				.map_err(|error| ApplyError::KeyWrite(oauth_public.to_path_buf(), error))?;
			let public_text = std::str::from_utf8(&public_bytes).map_err(|_| {
				ApplyError::OAuthPairIncomplete(format!(
					"oauth public key {} is not valid utf-8",
					oauth_public.display()
				))
			})?;
			if public_text.trim() != derived_public.trim() {
				return Err(ApplyError::OAuthPairMismatch);
			}
			report
				.steps
				.push(ReportStep::Reused(oauth_public.to_path_buf()));
		} else {
			write_secret_with_report(oauth_public, derived_public.as_bytes(), report)?;
		}
	} else if oauth_public.exists() {
		return Err(ApplyError::OAuthPairIncomplete(format!(
			"oauth public key {} exists but the matching private key {} is missing; restore the private key from backup or delete {} and rerun init",
			oauth_public.display(),
			oauth_private.display(),
			oauth_public.display()
		)));
	} else {
		let (private_b64, public_b64) = crate::cli::util::generate_oauth_keypair()
			.ok_or_else(|| ApplyError::Rng("oauth key pair".to_string()))?;
		write_secret_with_report(oauth_private, private_b64.as_bytes(), report)?;
		write_secret_with_report(oauth_public, public_b64.as_bytes(), report)?;
	}

	Ok(())
}

/// True when `openssl` is on `PATH` and we can shell out to it. Used by
/// the RSA DKIM key step; false leaves the step out of the apply phase
/// and reports the gap on stderr.
pub(crate) fn openssl_available() -> bool {
	apply_plan::openssl_available()
}

/// Materialise the keys dir + every key + the self-signed cert
/// pair. Returns the absolute paths the apply phase needs to
/// write the config, or `Err(error)` on a key-write failure
/// (the report is left in the caller's hands).
pub(super) fn ensure_keys_and_certs(
	keys_dir: &Path,
	hostname: &str,
	report: &mut Report,
) -> Result<(Option<PathBuf>, Option<PathBuf>, PathBuf, PathBuf), ApplyError> {
	let s1 = keys_dir.join("s1.pem");
	let s2 = keys_dir.join("s2.pem");
	let storage = keys_dir.join("storage.key");
	let oauth_private = keys_dir.join("oauth_signing.key");
	let oauth_public = keys_dir.join("oauth_public.key");
	ensure_key_tree(&s1, &s2, &storage, &oauth_private, &oauth_public, report)?;
	let ed = s1.exists().then(|| s1.clone());
	let rsa = s2.exists().then(|| s2.clone());
	let (cert, key) = ensure_self_signed_cert(keys_dir, hostname, report)?;
	Ok((ed, rsa, cert, key))
}
