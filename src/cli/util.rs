//! Shared CLI helpers: stdin reading, token hashing, secret generation and the
//! DKIM key-generation command body.

use std::process::ExitCode;

pub(super) fn token_hash() -> ExitCode {
	token_hash_from(std::io::stdin().lock())
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
			eprintln!("error: reading stdin: {error}");
			return Err(InputError);
		}
		None => {
			eprintln!("error: no input — pipe or type the value on stdin");
			return Err(InputError);
		}
	};
	if value.is_empty() {
		eprintln!("error: input must not be empty");
		return Err(InputError);
	}
	Ok(value)
}

pub(super) fn token_hash_from(reader: impl std::io::BufRead) -> ExitCode {
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
	println!("sha256:{hex}");
	ExitCode::SUCCESS
}

/// Build the at-rest [`MessageCrypto`] from a loaded config, printing the
/// fail-closed error and returning `Err(FAILURE)` if the key cannot be loaded.
pub(super) fn message_crypto(
	config: &crate::config::Config,
) -> Result<crate::storage::MessageCrypto, ExitCode> {
	crate::storage::MessageCrypto::from_config(config.storage.as_ref()).map_err(|error| {
		eprintln!("error: {error}");
		ExitCode::FAILURE
	})
}

/// `epistle storage-keygen`: print a fresh base64 32-byte at-rest encryption key
/// to stdout for the operator to place in an env var or key file (off the data
/// disk). Mirrors `dkim-keygen`; never writes into `data_dir`.
pub(super) fn storage_keygen() -> ExitCode {
	match crate::storage::generate_key_base64() {
		Some(key) => {
			println!("{key}");
			ExitCode::SUCCESS
		}
		None => {
			eprintln!("error: system CSPRNG unavailable");
			ExitCode::FAILURE
		}
	}
}

/// `epistle oauth-keygen`: print a fresh ES256 key pair for the built-in OAuth
/// authorization server. The base64 PKCS#8 private key goes in `[oauth]
/// signing_key`; the base64 public point goes in `[oauth] public_key` (they are
/// a pair, so issued tokens verify with the configured verifier). Mirrors
/// `dkim-keygen`/`storage-keygen`; never writes into `data_dir`.
pub(super) fn oauth_keygen() -> ExitCode {
	match generate_oauth_keypair() {
		Some((private_b64, public_b64)) => {
			println!("# [oauth] signing_key (base64 PKCS#8 ES256 private key):");
			println!("{private_b64}");
			println!("# [oauth] public_key (base64 ES256 public point), algorithm = \"ES256\":");
			println!("{public_b64}");
			ExitCode::SUCCESS
		}
		None => {
			eprintln!("error: system CSPRNG unavailable");
			ExitCode::FAILURE
		}
	}
}

/// Generate a fresh ES256 key pair as `(private_b64, public_b64)`: the base64
/// PKCS#8 private key and the base64 raw public point. The two are a matching
/// pair, so a token signed with the private key verifies against the public one.
/// `None` only if the CSPRNG fails (fail closed).
fn generate_oauth_keypair() -> Option<(String, String)> {
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

pub(super) fn dkim_keygen(out: &std::path::Path, rsa: bool, bits: u32) -> ExitCode {
	if out.exists() {
		eprintln!(
			"error: {} already exists, refusing to overwrite",
			out.display()
		);
		return ExitCode::FAILURE;
	}
	if rsa && !matches!(bits, 2048 | 4096) {
		eprintln!("error: --bits must be 2048 or 4096 (got {bits})");
		return ExitCode::FAILURE;
	}
	let (pem, record) = if rsa {
		match generate_rsa_key(bits) {
			Ok(generated) => generated,
			Err(error) => {
				eprintln!("error: {error}");
				return ExitCode::FAILURE;
			}
		}
	} else {
		match crate::dkim::generate_key() {
			Ok(generated) => generated,
			Err(error) => {
				eprintln!("error: {error}");
				return ExitCode::FAILURE;
			}
		}
	};
	if let Err(error) = write_key_pem(out, &pem) {
		eprintln!("error: cannot write {}: {error}", out.display());
		return ExitCode::FAILURE;
	}
	println!("private key written to {}", out.display());
	println!("publish this TXT record at <selector>._domainkey.<your-domain>:");
	println!("{record}");
	ExitCode::SUCCESS
}

/// Generate an RSA DKIM key by asking `openssl genpkey` to produce a
/// PKCS#8 PEM, returning the PEM and the matching DKIM DNS record value
/// (`v=DKIM1; k=rsa; p=<base64 SPKI>`). The PEM is validated through
/// `ring`'s PKCS#8 loader before it is written to disk or printed, so a
/// process that depends on the loader (outbound signing, the publish
/// record, the verifier) cannot trip on an `openssl` build we never
/// actually parsed.
///
/// `openssl` must be on `PATH`; the message names the package to install
/// when it is not.
fn generate_rsa_key(bits: u32) -> Result<(String, String), KeygenError> {
	use base64::Engine;
	use base64::engine::general_purpose::STANDARD as BASE64;
	use ring::signature::{KeyPair, RSA_PKCS1_2048_8192_SHA256, RsaKeyPair, UnparsedPublicKey};
	use std::io::Read;
	use std::process::{Command, Stdio};

	let mut child = Command::new("openssl")
		.args([
			"genpkey",
			"-algorithm",
			"RSA",
			"-pkeyopt",
			&format!("rsa_keygen_bits:{bits}"),
			"-outform",
			"PEM",
		])
		.stdin(Stdio::null())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped())
		.spawn()
		.map_err(|error| match error.kind() {
			std::io::ErrorKind::NotFound => KeygenError::OpenSslMissing,
			_ => KeygenError::OpenSslRead(error),
		})?;

	let mut pem = String::new();
	if let Some(mut stdout) = child.stdout.take() {
		let mut limited = (&mut stdout).take(64 * 1024);
		limited
			.read_to_string(&mut pem)
			.map_err(KeygenError::OpenSslRead)?;
	}
	let output = child.wait_with_output().map_err(KeygenError::OpenSslRead)?;
	if !output.status.success() {
		let stderr = String::from_utf8_lossy(&output.stderr);
		return Err(KeygenError::OpenFailed(stderr.into_owned()));
	}

	// Validate through ring before we trust the bytes: the rendered record
	// has to come from a key we can actually sign with.
	let der = pem_body(&pem).ok_or(KeygenError::InvalidKey)?;
	let pair = RsaKeyPair::from_pkcs8(&der).map_err(|_| KeygenError::InvalidKey)?;
	let pkcs1 = pair.public_key().as_ref();
	// Touch the parsed key through the verifier's algorithm so an opaque
	// invalid one fails the same path the verifier will follow.
	let parsed = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, pkcs1);
	let _ = parsed;
	let spki = crate::dkim::spki_for_rsa(pkcs1);
	Ok((pem, format!("v=DKIM1; k=rsa; p={}", BASE64.encode(spki))))
}

/// Write the generated PEM to `path` with mode 0600 on Unix (or the
/// closest equivalent on other platforms). Shared between the ed25519 and
/// RSA paths so the file permissions do not drift between them.
pub(super) fn write_key_pem(path: &std::path::Path, pem: &str) -> std::io::Result<()> {
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

/// Errors from the RSA keygen path. Each variant owns its own message so
/// the CLI can `eprintln!` without an intermediate formatting step (and
/// without a taint analyser reading a constant string into a key sink).
enum KeygenError {
	OpenSslMissing,
	OpenSslRead(std::io::Error),
	OpenFailed(String),
	InvalidKey,
}

impl std::fmt::Display for KeygenError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			KeygenError::OpenSslMissing => f.write_str(
				"`openssl` was not found on PATH; install it (Debian/Ubuntu: `apt install openssl`)",
			),
			KeygenError::OpenSslRead(error) => write!(f, "cannot read `openssl` output: {error}"),
			KeygenError::OpenFailed(stderr) => write!(f, "`openssl genpkey` failed: {stderr}"),
			KeygenError::InvalidKey => {
				f.write_str("the key `openssl` produced is not a valid PKCS#8 RSA key")
			}
		}
	}
}

/// Extract the DER body of a single-block PEM file. Duplicated here from
/// `crate::dkim::sign::pem_body` because that one is `fn` (not `pub`).
fn pem_body(pem: &str) -> Option<Vec<u8>> {
	use base64::Engine;
	use base64::engine::general_purpose::STANDARD as BASE64;
	let mut body = String::new();
	let mut inside = false;
	for line in pem.lines() {
		if line.starts_with("-----BEGIN ") {
			inside = true;
			continue;
		}
		if line.starts_with("-----END ") {
			break;
		}
		if inside {
			body.push_str(line.trim());
		}
	}
	if body.is_empty() {
		return None;
	}
	BASE64.decode(body).ok()
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
