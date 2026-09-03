//! CLI tests for the `epistle dkim-keygen --rsa` path: the `--bits`
//! allow-list, the openssl integration, and the resulting key being
//! loadable by ring's RSA loader (the same loader the outbound signer
//! uses). Sibling to `cli_tests.rs`, `cli_tests_b.rs`, `cli_tests_c.rs`.

use super::*;
use base64::Engine;
use ring::signature::KeyPair;

#[test]
fn dkim_keygen_rsa_refuses_bits_other_than_2048_or_4096() {
	let dir = tempfile::tempdir().expect("tempdir");
	let out = dir.path().join("rsa.pem");
	let cli = Cli::try_parse_from([
		"epistle",
		"dkim-keygen",
		"--rsa",
		"--bits",
		"3072",
		"--out",
		out.to_str().expect("utf-8 path"),
	])
	.expect("parses");
	assert_eq!(cli.run(), ExitCode::FAILURE);
	// No file written on rejection.
	assert!(!out.exists(), "refused write should not create a file");
}

#[test]
fn dkim_keygen_rsa_writes_a_key_ring_can_load() {
	if !openssl_on_path() {
		eprintln!("skip: openssl not on PATH");
		return;
	}
	let dir = tempfile::tempdir().expect("tempdir");
	let out = dir.path().join("rsa.pem");
	let cli = Cli::try_parse_from([
		"epistle",
		"dkim-keygen",
		"--rsa",
		"--out",
		out.to_str().expect("utf-8 path"),
	])
	.expect("parses");
	assert_eq!(cli.run(), ExitCode::SUCCESS);
	let pem = std::fs::read_to_string(&out).expect("pem read");
	assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----"));

	// Re-load the produced PEM through ring's RSA loader directly: the
	// same code path the outbound signer will follow. A key ring cannot
	// load is a hard failure (it is checked before anything is written).
	let key = std::fs::read_to_string(&out).expect("pem read");
	let body = {
		let mut buf = String::new();
		let mut inside = false;
		for line in key.lines() {
			if line.starts_with("-----BEGIN ") {
				inside = true;
				continue;
			}
			if line.starts_with("-----END ") {
				break;
			}
			if inside {
				buf.push_str(line.trim());
			}
		}
		buf
	};
	let der = base64::engine::general_purpose::STANDARD
		.decode(body.as_bytes())
		.expect("base64");
	let rsa_key = ring::signature::RsaKeyPair::from_pkcs8(&der).expect("ring loads pkcs8");
	let rsa_pub = rsa_key.public_key().as_ref();
	let spki = crate::dkim::spki_for_rsa(rsa_pub);
	let rsa_record = format!(
		"v=DKIM1; k=rsa; p={}",
		base64::engine::general_purpose::STANDARD.encode(spki)
	);
	assert!(
		rsa_record.starts_with("v=DKIM1; k=rsa; p="),
		"unexpected record: {rsa_record}"
	);
	assert!(
		rsa_record.len() > 255,
		"RSA-2048 record should exceed 255 bytes"
	);
	assert!(
		crate::dns::records::txt_strings(&rsa_record).len() >= 2,
		"RSA record did not split"
	);
}

/// Returns true when an `openssl` binary resolves somewhere on PATH. Used
/// to skip the truly cross-cutting tests when the host has no openssl
/// installed, so the suite stays runnable on minimal CI images.
fn openssl_on_path() -> bool {
	let Some(path) = std::env::var_os("PATH") else {
		return false;
	};
	std::env::split_paths(&path).any(|dir| dir.join("openssl").is_file())
}
