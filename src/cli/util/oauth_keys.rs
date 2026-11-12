//! `epistle oauth-keygen` and the ES256 key-pair helpers behind it.

use super::output::print_json;
use std::process::ExitCode;

/// `epistle oauth-keygen --out FILE`: generate a fresh ES256 key pair for the
/// built-in OAuth authorization server and write it to `out`, readable by the
/// owner only. The base64 PKCS#8 private key goes in `[oauth] signing_key`, the
/// base64 public point in `[oauth] public_key` (a pair, so issued tokens verify
/// with the configured verifier). The private key is never printed, so it does
/// not land in a terminal scrollback, a shell pipe or a CI log. An existing
/// file is refused, like `dkim-keygen`.
pub(in crate::cli) fn oauth_keygen(out: &std::path::Path, json: bool) -> ExitCode {
	if out.exists() {
		crate::cli::style::error(format_args!(
			"{} already exists, refusing to overwrite",
			out.display()
		));
		return ExitCode::FAILURE;
	}
	let Some((private_b64, public_b64)) = generate_oauth_keypair() else {
		crate::cli::style::error("system CSPRNG unavailable");
		return ExitCode::FAILURE;
	};
	let text = format!(
		"# Paste into [oauth]. signing_key is secret.\nsigning_key = \"{private_b64}\"\npublic_key = \"{public_b64}\"\nalgorithm = \"ES256\"\n"
	);
	if let Err(error) = crate::storage::write_secret(out, text.as_bytes()) {
		crate::cli::style::error(format_args!("writing {}: {error}", out.display()));
		return ExitCode::FAILURE;
	}
	if json {
		return print_json(&serde_json::json!({
			"result": "saved", "action": "oauth-keygen", "out": out.display().to_string(),
			"public_key": public_b64, "algorithm": "ES256",
		}));
	}
	println!("wrote the OAuth key pair to {} (mode 0600)", out.display());
	ExitCode::SUCCESS
}

/// Generate a fresh ES256 key pair as `(private_b64, public_b64)`: the base64
/// PKCS#8 private key and the base64 raw public point. The two are a matching
/// pair, so a token signed with the private key verifies against the public one.
/// `None` only if the CSPRNG fails (fail closed).
pub(in crate::cli) fn generate_oauth_keypair() -> Option<(String, String)> {
	use base64::Engine;
	use ring::rand::SystemRandom;
	use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
	let rng = SystemRandom::new();
	let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).ok()?;
	let pair =
		EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).ok()?;
	let b64 = base64::engine::general_purpose::STANDARD;
	Some((
		b64.encode(pkcs8.as_ref()),
		b64.encode(pair.public_key().as_ref()),
	))
}

/// Derive the matching ES256 public key from a base64 PKCS#8 private key.
/// `None` when the private key cannot be decoded as a P-256 PKCS#8 key
/// (corrupt bytes, wrong algorithm, truncated PEM).
pub(in crate::cli) fn derive_oauth_public_from_private(private_b64: &str) -> Option<String> {
	use base64::Engine;
	use ring::rand::SystemRandom;
	use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
	let rng = SystemRandom::new();
	let bytes = base64::engine::general_purpose::STANDARD
		.decode(private_b64.as_bytes())
		.ok()?;
	let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &bytes, &rng).ok()?;
	let b64 = base64::engine::general_purpose::STANDARD;
	Some(b64.encode(pair.public_key().as_ref()))
}
