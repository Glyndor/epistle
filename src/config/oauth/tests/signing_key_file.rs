//! `[oauth] signing_key_file`: the signing key read from a file instead of
//! written into the config.

use super::*;

fn oauth(extra: &str) -> Oauth {
	toml::from_str(&format!(
		"issuer = \"https://mail.example\"\naudience = \"mail\"\nalgorithm = \"ES256\"\npublic_key = \"PUB\"\n{extra}"
	))
	.expect("parse")
}

fn set_mode(path: &std::path::Path, mode: u32) {
	use std::os::unix::fs::PermissionsExt;
	std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

#[test]
fn the_key_is_read_from_the_file_and_trimmed() {
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("oauth_signing.key");
	std::fs::write(&path, "BASE64PRIV\n").unwrap();
	set_mode(&path, 0o600);
	let oauth = oauth(&format!(
		"signing_key_file = {:?}\n",
		path.display().to_string()
	));
	assert_eq!(oauth.validate(), Ok(()));
	assert_eq!(
		oauth.signing_key_material().unwrap().as_deref(),
		Some("BASE64PRIV")
	);
}

#[test]
fn an_inline_key_still_works_and_no_key_mounts_nothing() {
	assert_eq!(
		oauth("signing_key = \"INLINE\"\n")
			.signing_key_material()
			.unwrap()
			.as_deref(),
		Some("INLINE")
	);
	assert_eq!(oauth("").signing_key_material().unwrap(), None);
}

#[test]
fn a_missing_file_is_an_error_not_a_server_without_tokens() {
	let error = oauth("signing_key_file = \"/nonexistent/oauth_signing.key\"\n")
		.signing_key_material()
		.unwrap_err();
	assert!(
		error.to_string().contains("/nonexistent/oauth_signing.key"),
		"{error}"
	);
}

#[test]
fn both_sources_at_once_are_refused() {
	assert_eq!(
		oauth("signing_key = \"INLINE\"\nsigning_key_file = \"/k\"\n").validate(),
		Err(OauthConfigError::AmbiguousSigningKey)
	);
}

#[test]
fn a_key_file_needs_the_static_public_key_too() {
	let oauth: Oauth = toml::from_str(
		"issuer = \"https://mail.example\"\naudience = \"mail\"\nalgorithm = \"ES256\"\ndiscovery_url = \"https://idp.example/.well-known/openid-configuration\"\nsigning_key_file = \"/k\"\n",
	)
	.unwrap();
	assert_eq!(
		oauth.validate(),
		Err(OauthConfigError::SigningKeyWithoutPublicKey)
	);
}

#[test]
fn a_key_file_others_can_read_is_refused() {
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("oauth_signing.key");
	std::fs::write(&path, "BASE64PRIV\n").unwrap();
	for mode in [0o644, 0o640, 0o604] {
		set_mode(&path, mode);
		let error = oauth(&format!(
			"signing_key_file = {:?}\n",
			path.display().to_string()
		))
		.signing_key_material()
		.unwrap_err();
		let text = error.to_string();
		assert!(text.contains("group/world-accessible"), "{mode:#o}: {text}");
		assert!(!text.contains("BASE64PRIV"), "{text}");
	}
}

#[test]
fn a_key_file_that_is_not_a_regular_file_is_refused_not_waited_on() {
	let dir = tempfile::tempdir().unwrap();
	let error = oauth(&format!(
		"signing_key_file = {:?}\n",
		dir.path().display().to_string()
	))
	.signing_key_material()
	.unwrap_err();
	assert!(error.to_string().contains("regular file"), "{error}");
	let fifo = dir.path().join("fifo");
	let c_path = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
	// SAFETY: the path is a valid NUL-terminated string.
	assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
	let error = oauth(&format!(
		"signing_key_file = {:?}\n",
		fifo.display().to_string()
	))
	.signing_key_material()
	.unwrap_err();
	assert!(error.to_string().contains("regular file"), "{error}");
}
