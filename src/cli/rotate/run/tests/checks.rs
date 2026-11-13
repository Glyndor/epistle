//! What a finished run must have left: every secret replaced exactly once,
//! and the new one handed over.

use serde_json::Value;

use crate::api::ApiKeyStore;
use crate::config::Config;
use crate::directory_store::app_passwords::AppPasswordStore;

use super::fixture::{APP, KEYS, Server, rotate_dir};

/// The secret the run handed over for `kind` and `item`.
fn handed<'a>(result: &'a Value, kind: &str, item: &str) -> &'a str {
	result["secrets"]
		.as_array()
		.expect("a secrets array")
		.iter()
		.find(|row| row["kind"] == kind && row["item"] == item)
		.and_then(|row| row["secret"].as_str())
		.unwrap_or_else(|| panic!("no new secret was handed over for {kind} {item}"))
}

/// Check the server after a finished run whose result is `out`.
pub(super) fn rotated_once(server: &Server, out: &str) -> Value {
	let result: Value = serde_json::from_str(out).expect("one JSON object");
	assert_eq!(result["result"], "rotated");
	let keys = ApiKeyStore::open(&server.data_dir).unwrap();
	for (label, before) in KEYS.iter().zip(&server.key_hashes) {
		let stored = keys.hash_of(label).expect("the key is still there");
		let secret = handed(&result, "api-key", label);
		assert_ne!(&stored, before, "API key {label} kept its old secret");
		assert!(
			stored == crate::api::api_keys::sha256_hash(secret),
			"the secret handed over for API key {label} is not the one stored"
		);
	}
	let apps = AppPasswordStore::open(&server.data_dir).unwrap();
	let stored = apps
		.for_account(APP.0)
		.iter()
		.find(|app| app.label == APP.1)
		.map(|app| app.hash.clone())
		.expect("the app password is still there");
	assert_ne!(
		stored, server.app_hash,
		"the app password kept its old secret"
	);
	assert!(
		crate::smtp::auth::verify_password(&stored, handed(&result, "app-password", APP.1)),
		"the secret handed over for the app password is not the one stored"
	);
	let config = Config::load(&server.config).unwrap();
	let webhook = config.webhook.as_ref().and_then(|hook| hook.secret.clone());
	assert!(
		webhook.as_deref() == Some(handed(&result, "webhook-secret", "")),
		"the webhook secret handed over is not the one in the file"
	);
	assert!(webhook.as_deref() != Some(server.webhook.as_str()));
	let srs = config.srs_domain("example.org").expect("the SRS entry");
	assert!(srs.secret != server.srs, "the SRS secret was not replaced");
	assert!(
		srs.previous_secret.as_deref() == Some(server.srs.as_str()),
		"the SRS secret the domain had is not its previous_secret: it was rotated twice, or not \
		 kept"
	);
	let dir = rotate_dir(server);
	assert!(
		!dir.join("journal.json").exists(),
		"the journal was not archived"
	);
	assert!(
		!dir.join("secrets.json").exists(),
		"the secrets file was left behind"
	);
	assert!(
		dir.join("last-run.json").exists(),
		"no record of the finished run"
	);
	result
}
