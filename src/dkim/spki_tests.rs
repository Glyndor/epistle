//! Tests for the DKIM RSA SubjectPublicKeyInfo envelope. The single
//! control here is the openssl-roundtrip check: the `p=` value the
//! outbound signer publishes must equal what `openssl rsa -pubout`
//! prints for the same key (RFC 6376 §3.6.1, "the public key ...
//! encoded per RFC 5958 / X.509 SubjectPublicKeyInfo"). When openssl is
//! missing from PATH the test prints a reason and exits early rather
//! than failing, the same convention the CLI tests use.

use std::io::Write;

#[test]
fn rsa_dns_record_value_is_the_spki_openssl_prints() {
	// Skip (with a printed reason, never silently) when `openssl` is not
	// on PATH. The test is the only thing keeping the SPKI envelope in
	// sync with what the rest of the world calls an RSA public key:
	// skipping it would silently let the two drift.
	let Some(openssl) = find_openssl() else {
		eprintln!("skip: openssl not on PATH");
		return;
	};

	// Generate a real 2048-bit key with openssl (the same tool the
	// CLI delegates to) and load it into a Signer.
	let output = std::process::Command::new(&openssl)
		.args([
			"genpkey",
			"-algorithm",
			"RSA",
			"-pkeyopt",
			"rsa_keygen_bits:2048",
			"-outform",
			"PEM",
		])
		.stdin(std::process::Stdio::null())
		.output()
		.expect("openssl genpkey");
	assert!(
		output.status.success(),
		"openssl failed: {:?}",
		output.status
	);
	let pem = String::from_utf8(output.stdout).expect("pem utf8");

	let dir = tempfile::tempdir().expect("tempdir");
	let key_path = dir.path().join("rsa.pem");
	std::fs::write(&key_path, &pem).expect("write key");

	let signer = temp_signer()
		.with_rsa("rsasel", &key_path)
		.expect("with_rsa");
	let record = signer.rsa_dns_record_value().expect("rsa record present");

	// The published `p=` must equal the SPKI openssl prints for the
	// same key (RFC 6376 §3.6.1, "the public key ... encoded per
	// RFC 5958 / X.509 SubjectPublicKeyInfo"). Compute openssl's
	// view and compare against our envelope.
	let pubout = std::process::Command::new(&openssl)
		.args(["rsa", "-in", key_path.to_str().expect("utf-8"), "-pubout"])
		.stdin(std::process::Stdio::null())
		.output()
		.expect("openssl rsa -pubout");
	assert!(pubout.status.success(), "openssl rsa -pubout failed");
	let pubout_pem = String::from_utf8(pubout.stdout).expect("pubout utf8");
	let openssl_spki = strip_pem(&pubout_pem);

	// Our record is "v=DKIM1; k=rsa; p=<base64 SPKI>"; split out the
	// `p=` value and compare against what openssl printed.
	let p_value = record
		.split(';')
		.find_map(|tag| tag.trim().strip_prefix("p="))
		.expect("p= tag in record");
	assert_eq!(p_value, openssl_spki, "SPKI mismatch");

	// A 2048-bit RSA value is well over 255 bytes: this is the whole
	// reason the record needs splitting at the zone-file layer.
	assert!(record.len() > 255, "{} should be > 255 bytes", record.len());

	// And the helper genuinely splits it into multiple strings.
	assert!(
		crate::dns::records::txt_strings(&record).len() >= 2,
		"long RSA record did not split"
	);
}

/// Generate an ed25519 key and load it into a [`crate::dkim::Signer`]
/// backed by a temporary file. Mirrors the helper the inline
/// `sign::tests` module uses; duplicated here because that helper is
/// private to the inline module and the SPKI test must live in a
/// sibling file.
fn temp_signer() -> crate::dkim::Signer {
	let (pem, _record) = crate::dkim::generate_key().expect("generate");
	let mut file = tempfile::NamedTempFile::new().expect("temp file");
	file.write_all(pem.as_bytes()).expect("write key");
	let signer = crate::dkim::Signer::load("sel", file.path()).expect("load key");
	// Keep the file alive long enough.
	std::mem::forget(file);
	signer
}

/// Locate `openssl` on PATH, returning the binary name when it
/// resolves to a runnable executable and `None` otherwise.
fn find_openssl() -> Option<String> {
	let path = std::env::var_os("PATH")?;
	for dir in std::env::split_paths(&path) {
		let candidate = dir.join("openssl");
		if candidate.is_file() {
			return Some(candidate.to_string_lossy().into_owned());
		}
	}
	None
}

/// Strip PEM armour and whitespace from an X.509 SubjectPublicKeyInfo
/// PEM block, leaving the base64 body. Mirrors what
/// `dns::records::first_certificate_der` does for certificate blocks.
fn strip_pem(pem: &str) -> String {
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
	body
}
