//! Shared CLI helpers: stdin reading, token hashing, secret generation and the
//! DKIM key-generation command body.

use std::process::ExitCode;

pub(super) fn token_hash(json: bool) -> ExitCode {
	token_hash_from(std::io::stdin().lock(), json)
}

/// Print `value` as the `--json` result on stdout.
fn print_json(value: &serde_json::Value) -> ExitCode {
	super::json_out::print(&mut std::io::stdout().lock(), value)
}

/// Generate a strong random credential secret: 32 bytes from the system CSPRNG,
/// base32-encoded (unpadded, lowercase) for an easy-to-copy ~52-character
/// string. `None` if the CSPRNG cannot produce bytes (fail closed).
pub(super) fn generate_secret() -> Option<String> {
	use ring::rand::SecureRandom;
	let mut bytes = [0u8; 32];
	ring::rand::SystemRandom::new().fill(&mut bytes).ok()?;
	// RFC 4648 base32 lowercase, no padding.
	const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
	let mut out = String::with_capacity(52);
	let mut buffer: u32 = 0;
	let mut bits = 0u32;
	for &byte in &bytes {
		buffer = (buffer << 8) | byte as u32;
		bits += 8;
		while bits >= 5 {
			bits -= 5;
			let index = ((buffer >> bits) & 0x1f) as usize;
			out.push(ALPHABET[index] as char);
		}
	}
	if bits > 0 {
		let index = ((buffer << (5 - bits)) & 0x1f) as usize;
		out.push(ALPHABET[index] as char);
	}
	Some(out)
}

/// The stdin read failed. The reason has already been written to stderr, so a
/// caller only has to choose its exit code.
///
/// Carries no data on purpose. `read_line` feeds values that callers bind to
/// names like `token` and `password`, which makes every constant returned from
/// it look, to a taint analyser, like a credential travelling to a credential
/// sink - `rust/hard-coded-cryptographic-value` flagged the exit code on the
/// error path for exactly that reason. Keeping the exit code at the call site
/// leaves nothing constant flowing out of this function.
pub(super) struct InputError;

/// Read one non-empty line (CR-trimmed) from `reader`.
///
/// Diagnostics go to stderr; the caller turns [`InputError`] into an exit code.
pub(super) fn read_line(reader: impl std::io::BufRead) -> Result<String, InputError> {
	let value = match reader.lines().next() {
		Some(Ok(line)) => line.trim_end_matches('\r').to_owned(),
		Some(Err(error)) => {
			super::style::error(format_args!("reading stdin: {error}"));
			return Err(InputError);
		}
		None => {
			super::style::error("no input: pipe or type the value on stdin");
			return Err(InputError);
		}
	};
	if value.is_empty() {
		super::style::error("input must not be empty");
		return Err(InputError);
	}
	Ok(value)
}

pub(super) fn token_hash_from(reader: impl std::io::BufRead, json: bool) -> ExitCode {
	// let-else for the same reason as the caller in `accounts.rs`: a returning
	// match arm still counts as an arm of the expression that binds `token`.
	let Ok(token) = read_line(reader) else {
		return ExitCode::FAILURE;
	};
	let digest = ring::digest::digest(&ring::digest::SHA256, token.as_bytes());
	let hex = digest
		.as_ref()
		.iter()
		.fold(String::with_capacity(64), |mut s, b| {
			use std::fmt::Write;
			write!(s, "{b:02x}").ok();
			s
		});
	if json {
		return print_json(&serde_json::json!({ "token_hash": format!("sha256:{hex}") }));
	}
	println!("sha256:{hex}");
	ExitCode::SUCCESS
}

/// Build the at-rest [`MessageCrypto`] from a loaded config, printing the
/// fail-closed error and returning `Err(FAILURE)` if the key cannot be loaded.
pub(super) fn message_crypto(
	config: &crate::config::Config,
) -> Result<crate::storage::MessageCrypto, ExitCode> {
	crate::storage::MessageCrypto::from_config(config.storage.as_ref()).map_err(|error| {
		super::style::error(error);
		ExitCode::FAILURE
	})
}

/// `epistle storage-keygen`: print a fresh base64 32-byte at-rest encryption key
/// to stdout for the operator to place in an env var or key file (off the data
/// disk). Mirrors `dkim-keygen`; never writes into `data_dir`.
pub(super) fn storage_keygen(json: bool) -> ExitCode {
	match crate::storage::generate_key_base64() {
		Some(key) if json => print_json(&serde_json::json!({ "key": key })),
		Some(key) => {
			println!("{key}");
			ExitCode::SUCCESS
		}
		None => {
			super::style::error("system CSPRNG unavailable");
			ExitCode::FAILURE
		}
	}
}

/// `epistle oauth-keygen --out FILE`: generate a fresh ES256 key pair for the
/// built-in OAuth authorization server and write it to `out`, readable by the
/// owner only. The base64 PKCS#8 private key goes in `[oauth] signing_key`, the
/// base64 public point in `[oauth] public_key` (a pair, so issued tokens verify
/// with the configured verifier). The private key is never printed, so it does
/// not land in a terminal scrollback, a shell pipe or a CI log. An existing
/// file is refused, like `dkim-keygen`.
pub(super) fn oauth_keygen(out: &std::path::Path, json: bool) -> ExitCode {
	if out.exists() {
		super::style::error(format_args!(
			"{} already exists, refusing to overwrite",
			out.display()
		));
		return ExitCode::FAILURE;
	}
	let Some((private_b64, public_b64)) = generate_oauth_keypair() else {
		super::style::error("system CSPRNG unavailable");
		return ExitCode::FAILURE;
	};
	let text = format!(
		"# Paste into [oauth]. signing_key is secret.\nsigning_key = \"{private_b64}\"\npublic_key = \"{public_b64}\"\nalgorithm = \"ES256\"\n"
	);
	if let Err(error) = crate::storage::write_secret(out, text.as_bytes()) {
		super::style::error(format_args!("writing {}: {error}", out.display()));
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
pub(super) fn generate_oauth_keypair() -> Option<(String, String)> {
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
pub(super) fn derive_oauth_public_from_private(private_b64: &str) -> Option<String> {
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

pub(super) fn dkim_keygen(out: &std::path::Path, rsa: bool, bits: u32, json: bool) -> ExitCode {
	if out.exists() {
		super::style::error(format_args!(
			"{} already exists, refusing to overwrite",
			out.display()
		));
		return ExitCode::FAILURE;
	}
	if rsa && !matches!(bits, 2048 | 4096) {
		super::style::error(format_args!("--bits must be 2048 or 4096 (got {bits})"));
		return ExitCode::FAILURE;
	}
	let (pem, record) = if rsa {
		match generate_rsa_key(bits) {
			Ok(generated) => generated,
			Err(error) => {
				super::style::error(error);
				return ExitCode::FAILURE;
			}
		}
	} else {
		match crate::dkim::generate_key() {
			Ok(generated) => generated,
			Err(error) => {
				super::style::error(error);
				return ExitCode::FAILURE;
			}
		}
	};
	if let Err(error) = write_key_pem(out, &pem) {
		super::style::error(format_args!("cannot write {}: {error}", out.display()));
		return ExitCode::FAILURE;
	}
	if json {
		return print_json(&serde_json::json!({
			"result": "saved", "action": "dkim-keygen", "out": out.display().to_string(),
			"algorithm": if rsa { "rsa" } else { "ed25519" }, "record": record,
		}));
	}
	println!("private key written to {}", out.display());
	println!("publish this TXT record at <selector>._domainkey.<your-domain>:");
	println!("{record}");
	ExitCode::SUCCESS
}

pub(super) use crate::dkim::generate_rsa_key;

/// Write the generated PEM to `path` with mode 0600 on Unix (or the
/// closest equivalent on other platforms). Shared between the ed25519 and
/// RSA paths so the file permissions do not drift between them.
pub(super) fn write_key_pem(path: &std::path::Path, pem: &str) -> std::io::Result<()> {
	// `init` reaches this through the same path; the function stays
	// `pub(super)` so other CLI helpers can call it without exposing it
	// beyond the `cli` module.
	use std::io::Write;
	let mut options = std::fs::OpenOptions::new();
	options.write(true).create_new(true);
	#[cfg(unix)]
	{
		use std::os::unix::fs::OpenOptionsExt;
		options.mode(0o600);
	}
	options
		.open(path)
		.and_then(|mut file| file.write_all(pem.as_bytes()))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn oauth_keypair_round_trips_through_jwt() {
		// The generated private/public pair must be matched: a token signed with the
		// private key verifies against the public point.
		use base64::Engine;
		let (private_b64, public_b64) = generate_oauth_keypair().expect("keypair");
		let private = base64::engine::general_purpose::STANDARD
			.decode(&private_b64)
			.expect("private b64");
		let public = base64::engine::general_purpose::STANDARD
			.decode(&public_b64)
			.expect("public b64");
		let claims = serde_json::json!({"sub": "x", "exp": 9999999999u64});
		let token =
			crate::jwt::sign(&claims, crate::jwt::Algorithm::Es256, &private).expect("sign");
		let validation = crate::jwt::Validation {
			now: 1000,
			issuer: None,
			audience: None,
		};
		assert!(
			crate::jwt::validate(&token, crate::jwt::Algorithm::Es256, &public, &validation)
				.is_ok()
		);
	}
}
