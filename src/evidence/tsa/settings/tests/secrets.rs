//! Credentials for an authority never reach an output: not Debug, not the
//! settings JSON, not an error, not the chain. Assertions name the output
//! that leaked, never the secret.

use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

use super::*;
use crate::evidence::tsa::fake::FakeTsa;

fn secret() -> String {
	crate::test_fixtures::fresh_secret()
}

#[test]
fn a_url_with_credentials_is_refused_without_repeating_them() {
	let password = secret();
	let mut settings = Settings::default();
	settings.authorities[0].url = format!("https://operator:{password}@tsa.example.org/tsr");
	let error = settings.validate().expect_err("userinfo is refused");
	assert!(
		!error.0.contains(&password),
		"the validation error repeats the password"
	);
	assert_eq!(
		error.0,
		"a timestamp authority URL must not carry credentials (use token_file)"
	);
	let debug = format!("{settings:?}");
	assert!(
		!debug.contains(&password),
		"Debug of the settings shows the password"
	);
	let shown = settings.authorities[0].display();
	assert!(
		!shown.contains(&password),
		"the displayed authority shows the password"
	);
	assert_eq!(shown, "tsa.example.org");
}

#[tokio::test]
async fn a_token_file_is_read_for_the_request_and_shown_nowhere() {
	let token = secret();
	let dir = tempfile::tempdir().expect("tempdir");
	let token_path = dir.path().join("tsa.token");
	std::fs::write(&token_path, &token).expect("token");
	std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
	let tsa = Arc::new(FakeTsa::new(1_792_038_711));
	let url = Arc::clone(&tsa).serve().await;
	let authority = Authority {
		url,
		anchors: vec![crate::evidence::record::to_hex(&tsa.anchor)],
		policy: None,
		local_test: true,
		token_file: Some(token_path.clone()),
	};
	let settings = Settings {
		enabled: true,
		authorities: vec![authority.clone()],
	};
	assert!(
		!format!("{settings:?}").contains(&token),
		"Debug shows the token"
	);
	let json = serde_json::to_string(&settings).expect("json");
	assert!(!json.contains(&token), "the settings JSON holds the token");
	crate::evidence::tsa::client::obtain(&settings.authorities, &[1; 32])
		.await
		.expect("a token with the bearer header");
	let headers = tsa.authorization.lock().expect("lock").clone();
	assert!(
		headers == vec![format!("Bearer {token}")],
		"the bearer token was not sent as configured"
	);
	// A failure names the authority by host only.
	let mut unreachable = authority;
	unreachable.url = "http://127.0.0.1:9/tsr".into();
	let error = crate::evidence::tsa::client::obtain(&[unreachable], &[1; 32])
		.await
		.expect_err("down");
	assert!(!error.contains(&token), "an error shows the token");
	assert_eq!(error, "127.0.0.1: request failed: could not connect");
	record_change(dir.path(), &settings, "uid=0").expect("record");
	let chain = std::fs::read_dir(dir.path().join("chain"))
		.expect("chain")
		.count();
	assert!(chain > 0);
	for entry in std::fs::read_dir(dir.path().join("chain")).expect("chain") {
		let text = std::fs::read_to_string(entry.expect("entry").path()).unwrap_or_default();
		assert!(!text.contains(&token), "the chain holds the token");
	}
}

#[test]
fn a_token_file_others_can_read_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let token_path = dir.path().join("tsa.token");
	std::fs::write(&token_path, secret()).expect("token");
	std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
	match read_token(&token_path) {
		Ok(_) => panic!("a token file others can read was accepted"),
		Err(error) => assert_eq!(
			error.to_string(),
			"a TSA token file must be 0600 and owned by the server user"
		),
	}
}
