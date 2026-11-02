//! Frozen v0.12.5 writes must authenticate through the current readers.
//! Never generate these stores with the code under test: see the fixture README.

use std::num::NonZeroU32;
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use epistle::api::{ApiKeySet, ApiState, router};
use epistle::config::{Protocol, Storage};
use epistle::directory_store::AccountStore;
use epistle::smtp::directory::Directory;
use epistle::smtp::scram::{ScramCredentials, ScramError, ScramServer};
use epistle::storage::{FsSpool, MessageCrypto};
use ring::{digest, hmac, pbkdf2};
use tower::ServiceExt;

const FIXTURES: &str = concat!(
	env!("CARGO_MANIFEST_DIR"),
	"/tests/contracts/testdata/credentials-v0.12.5"
);
/// A public test value of the frozen stores, read from `test-values.toml`.
fn value(name: &str) -> String {
	let text = std::fs::read_to_string(Path::new(FIXTURES).join("test-values.toml"))
		.expect("test values of the frozen stores");
	let table: toml::Table = text.parse().expect("test values parse");
	table[name]
		.as_str()
		.expect("test value is a string")
		.to_string()
}

fn copy_store() -> tempfile::TempDir {
	let dir = tempfile::tempdir().expect("temporary store");
	for file in ["accounts.toml", "app_passwords.toml", "api_keys.toml"] {
		std::fs::copy(Path::new(FIXTURES).join(file), dir.path().join(file))
			.expect("copy frozen store");
	}
	dir
}

fn open(dir: &Path) -> AccountStore {
	AccountStore::open(dir, vec!["example.test".into()], Default::default(), vec![])
		.expect("load previous release accounts")
}

fn password_login(directory: &Directory, name: &str, presented: &str) -> bool {
	directory
		.authenticate(name, presented, Protocol::Imap)
		.as_deref()
		== Some(name)
}

#[test]
fn password_hash_and_app_password_survive_upgrade() {
	let dir = copy_store();
	let directory = open(dir.path()).handle().current();
	assert!(
		password_login(&directory, "password", &value("password")),
		"password must authenticate"
	);
	assert!(
		!password_login(&directory, "password", &value("wrong")),
		"wrong password must fail"
	);
	// An app password is an independent credential, even on a TOTP account.
	assert!(
		password_login(&directory, "secondfactor", &value("app")),
		"app password must authenticate"
	);
	assert!(
		!password_login(&directory, "secondfactor", &value("wrong")),
		"wrong app password must fail"
	);
}

fn check_totp(directory: &Directory, account: &str) {
	assert!(
		!password_login(directory, account, &value("password")),
		"second factor must be required"
	);
	let now = SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.expect("clock")
		.as_secs();
	let code = epistle::totp::totp(value("totp").as_bytes(), now);
	assert!(
		password_login(
			directory,
			account,
			&format!("{}{code:06}", value("password"))
		),
		"TOTP must authenticate"
	);
	assert!(
		!password_login(directory, account, &format!("{}{code:06}", value("wrong"))),
		"TOTP must not replace password"
	);
}

#[test]
fn plaintext_totp_survives_upgrade() {
	let dir = copy_store();
	check_totp(&open(dir.path()).handle().current(), "secondfactor");
}

#[test]
fn encrypted_totp_survives_upgrade() {
	let dir = tempfile::tempdir().expect("temporary encrypted store");
	std::fs::copy(
		Path::new(FIXTURES).join("sealed/accounts.toml"),
		dir.path().join("accounts.toml"),
	)
	.expect("copy encrypted accounts");
	let crypto = MessageCrypto::from_config(Some(&Storage {
		encrypt_at_rest: true,
		encryption_key_file: Some(Path::new(FIXTURES).join("encryption.key")),
		..Default::default()
	}))
	.expect("load fixture encryption key");
	check_totp(
		&open(dir.path()).with_crypto(crypto).handle().current(),
		"sealed",
	);
	let locked = open(dir.path()).handle().current();
	assert!(
		!password_login(&locked, "sealed", &value("password")),
		"missing key must fail closed"
	);
	let now = SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.expect("clock")
		.as_secs();
	let code = epistle::totp::totp(value("totp").as_bytes(), now);
	assert!(
		!password_login(
			&locked,
			"sealed",
			&format!("{}{code:06}", value("password"))
		),
		"missing key must not bypass TOTP"
	);
}

fn mac(key: &[u8], message: &[u8]) -> Vec<u8> {
	hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), message)
		.as_ref()
		.to_vec()
}

// Compute a client proof from the password and the server's advertised salt
// and iteration count, independently of its persisted StoredKey/ServerKey.
fn exchange(credentials: &ScramCredentials, password: &str) -> Result<String, ScramError> {
	let mut server = ScramServer::new("server-contract-nonce");
	let bare = "n=password,r=client-contract-nonce";
	let (_, first) = server.first(&format!("n,,{bare}"), credentials)?;
	let fields: Vec<_> = first.split(',').collect();
	let nonce = fields[0].strip_prefix("r=").expect("nonce");
	let salt = BASE64
		.decode(fields[1].strip_prefix("s=").expect("salt"))
		.expect("base64 salt");
	let iterations = fields[2]
		.strip_prefix("i=")
		.expect("iterations")
		.parse()
		.expect("iteration count");
	let final_bare = format!("c=biws,r={nonce}");
	let message = format!("{bare},{first},{final_bare}");
	let mut salted = [0u8; 32];
	pbkdf2::derive(
		pbkdf2::PBKDF2_HMAC_SHA256,
		NonZeroU32::new(iterations).expect("nonzero iterations"),
		&salt,
		password.as_bytes(),
		&mut salted,
	);
	let client_key = mac(&salted, b"Client Key");
	let stored_key = digest::digest(&digest::SHA256, &client_key);
	let signature = mac(stored_key.as_ref(), message.as_bytes());
	let proof: Vec<_> = client_key
		.iter()
		.zip(signature)
		.map(|(a, b)| a ^ b)
		.collect();
	let result = server.finish(
		&format!("{final_bare},p={}", BASE64.encode(proof)),
		credentials,
	)?;
	let expected = format!(
		"v={}",
		BASE64.encode(mac(&mac(&salted, b"Server Key"), message.as_bytes()))
	);
	assert!(result == expected, "server signature must authenticate");
	Ok(result)
}

#[test]
fn scram_verifier_survives_upgrade() {
	let dir = copy_store();
	let directory = open(dir.path()).handle().current();
	let credentials = directory
		.scram_credentials("password")
		.expect("load frozen SCRAM verifier");
	assert!(
		exchange(&credentials, &value("password")).is_ok(),
		"SCRAM proof must authenticate"
	);
	assert!(
		matches!(
			exchange(&credentials, &value("wrong")),
			Err(ScramError::AuthenticationFailed)
		),
		"wrong SCRAM proof must fail"
	);
}

async fn status(app: &axum::Router, token: &str) -> StatusCode {
	app.clone()
		.oneshot(
			Request::builder()
				.uri("/api/v1/accounts")
				.header("authorization", format!("Bearer {token}"))
				.body(Body::empty())
				.expect("request"),
		)
		.await
		.expect("response")
		.status()
}

fn api(dir: &Path, hash: &str) -> axum::Router {
	router(ApiState::new(
		hash,
		dir.into(),
		vec!["example.test".into()],
		Arc::new(open(dir)),
		FsSpool::open(dir).expect("spool"),
	))
}

#[tokio::test]
async fn api_key_survives_upgrade() {
	let dir = copy_store();
	let keys = Arc::new(ApiKeySet::open(dir.path()).expect("load previous release API keys"));
	let state = ApiState::new(
		"",
		dir.path().into(),
		vec!["example.test".into()],
		Arc::new(open(dir.path())),
		FsSpool::open(dir.path()).expect("spool"),
	)
	.with_api_keys(keys);
	let app = router(state);
	assert_eq!(
		status(&app, &value("token")).await,
		StatusCode::OK,
		"API key must authenticate"
	);
	assert_eq!(
		status(&app, &value("wrong")).await,
		StatusCode::UNAUTHORIZED,
		"wrong API key must fail"
	);
}

#[tokio::test]
async fn both_static_token_forms_survive_upgrade() {
	#[derive(serde::Deserialize)]
	struct Tokens {
		hashes: Vec<String>,
	}
	let tokens: Tokens = toml::from_str(
		&std::fs::read_to_string(Path::new(FIXTURES).join("static_tokens.toml"))
			.expect("read static token fixture"),
	)
	.expect("load static token forms");
	assert_eq!(
		tokens.hashes.len(),
		2,
		"both previous forms must be exercised"
	);
	for hash in tokens.hashes {
		let dir = copy_store();
		// Keep API keys absent so they cannot mask a broken static-token reader.
		std::fs::remove_file(dir.path().join("api_keys.toml")).expect("isolate static token");
		let app = api(dir.path(), &hash);
		assert_eq!(
			status(&app, &value("token")).await,
			StatusCode::OK,
			"static token must authenticate"
		);
		assert_eq!(
			status(&app, &value("wrong")).await,
			StatusCode::UNAUTHORIZED,
			"wrong static token must fail"
		);
	}
}
