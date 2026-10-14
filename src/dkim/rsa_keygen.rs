//! RSA DKIM key generation through `openssl genpkey`, shared by
//! `epistle dkim-keygen --rsa`, `epistle init` and the rotation of the RSA
//! dual-signing key.

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
pub fn generate_rsa_key(bits: u32) -> Result<(String, String), KeygenError> {
	use base64::Engine;
	use base64::engine::general_purpose::STANDARD as BASE64;
	use ring::signature::{KeyPair, RsaKeyPair};
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
	let der = super::sign::pem_body(&pem).ok_or(KeygenError::InvalidKey)?;
	let pair = RsaKeyPair::from_pkcs8(&der).map_err(|_| KeygenError::InvalidKey)?;
	let pkcs1 = pair.public_key().as_ref();
	// Touch the parsed key through the verifier's algorithm so an opaque
	// invalid one fails the same path the verifier will follow.
	let spki = super::spki::spki_for_rsa(pkcs1);
	Ok((pem, format!("v=DKIM1; k=rsa; p={}", BASE64.encode(spki))))
}

/// Errors from the RSA keygen path. Each variant owns its own message so
/// the CLI can `eprintln!` without an intermediate formatting step (and
/// without a taint analyser reading a constant string into a key sink).
pub enum KeygenError {
	/// `openssl` is not on `PATH`.
	OpenSslMissing,
	/// `openssl` could not be started or its output read.
	OpenSslRead(std::io::Error),
	/// `openssl` exited with an error; carries its stderr.
	OpenFailed(String),
	/// The PEM `openssl` printed is not an RSA PKCS#8 key `ring` loads.
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
