//! `epistle oauth-keygen --out FILE` writes the key pair to an owner-only
//! file; the private key never reaches stdout.

use std::process::ExitCode;

use crate::cli::util::{derive_oauth_public_from_private, oauth_keygen};

/// The value of `key = "..."` in the generated file.
fn field(text: &str, key: &str) -> String {
	let prefix = format!("{key} = \"");
	text.lines()
		.find_map(|line| line.strip_prefix(prefix.as_str()))
		.and_then(|rest| rest.strip_suffix('"'))
		.map(str::to_string)
		.unwrap_or_default()
}

#[test]
fn writes_a_matching_pair_to_an_owner_only_file() {
	let dir = tempfile::tempdir().expect("tempdir");
	let out = dir.path().join("oauth.toml");
	assert_eq!(oauth_keygen(&out, false), ExitCode::SUCCESS);
	let text = std::fs::read_to_string(&out).expect("key file");
	let private = field(&text, "signing_key");
	let public = field(&text, "public_key");
	assert!(!private.is_empty(), "the file must carry a signing_key");
	assert_eq!(field(&text, "algorithm"), "ES256");
	assert_eq!(
		derive_oauth_public_from_private(&private).as_deref(),
		Some(public.as_str()),
		"public_key must be the point of signing_key"
	);
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		let mode = std::fs::metadata(&out).expect("stat").permissions().mode();
		assert_eq!(mode & 0o777, 0o600, "the key file must be owner-only");
	}
}

#[test]
fn refuses_to_overwrite_an_existing_file() {
	let dir = tempfile::tempdir().expect("tempdir");
	let out = dir.path().join("oauth.toml");
	std::fs::write(&out, b"keep me").expect("seed");
	assert_eq!(oauth_keygen(&out, false), ExitCode::FAILURE);
	assert_eq!(std::fs::read(&out).expect("read"), b"keep me");
}
