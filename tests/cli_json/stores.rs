//! `--json` on the commands that write a store under `data_dir`:
//! suppression, masked addresses, the queue, app passwords, API keys and
//! the archive.

use serde_json::{Value, json};

use crate::harness::{add_account, env, epistle, json};

fn run(config: &str, args: &[&str]) -> (i32, Value) {
	let mut full: Vec<&str> = args.to_vec();
	full.insert(1, "--config");
	full.insert(2, config);
	full.push("--json");
	json(&epistle(&full, b""))
}

#[test]
fn suppression_add_and_remove() {
	let env = env("");
	assert_eq!(
		run(&env.config, &["suppression", "add", "Gone@Example.NET"]),
		(
			0,
			json!({"result": "saved", "action": "add", "address": "gone@example.net", "account": null})
		)
	);
	assert_eq!(
		run(&env.config, &["suppression", "remove", "gone@example.net"]),
		(
			0,
			json!({"result": "saved", "action": "remove", "address": "gone@example.net", "account": null})
		)
	);
}

#[test]
fn masked_add_names_the_address_it_minted() {
	let env = env("");
	add_account(&env, "bob");
	let (code, added) = run(&env.config, &["masked", "add", "bob", "--label", "shop"]);
	assert_eq!(code, 0);
	let address = added["address"].as_str().expect("address").to_string();
	assert!(
		address.starts_with("shop") && address.ends_with("@example.org"),
		"address {address}"
	);
	assert_eq!(
		added,
		json!({"result": "saved", "action": "add", "account": "bob", "address": address, "label": "shop"})
	);
	for (verb, enabled) in [("disable", false), ("enable", true)] {
		assert_eq!(
			run(&env.config, &["masked", verb, "bob", &address]),
			(
				0,
				json!({"result": "saved", "action": verb, "account": "bob", "address": address, "enabled": enabled})
			)
		);
	}
	assert_eq!(
		run(&env.config, &["masked", "remove", "bob", &address, "--yes"]),
		(
			0,
			json!({"result": "saved", "action": "remove", "account": "bob", "address": address})
		)
	);
}

#[test]
fn queue_hold_on_an_empty_queue_changes_nothing() {
	let env = env("");
	assert_eq!(
		run(&env.config, &["queue", "hold", "--all"]),
		(
			0,
			json!({"result": "unchanged", "action": "hold", "entries": 0})
		)
	);
	assert_eq!(
		run(&env.config, &["queue", "release-destination", "--all"]),
		(
			0,
			json!({"result": "unchanged", "action": "release-destination", "released": []})
		)
	);
}

#[test]
fn app_password_create_shows_the_secret_once_then_revoke() {
	let env = env("");
	add_account(&env, "bob");
	let (code, mut created) = run(&env.config, &["app-password", "create", "bob", "phone"]);
	assert_eq!(code, 0);
	let secret = created["secret"].take();
	assert!(
		secret.as_str().is_some_and(|secret| secret.len() >= 20),
		"the secret is missing or short"
	);
	assert_eq!(
		created,
		json!({
			"result": "saved", "action": "create", "account": "bob", "label": "phone",
			"secret": null, "expires_at": null, "ip_cidr": null, "save_sent": null,
		})
	);
	assert_eq!(
		run(
			&env.config,
			&["app-password", "revoke", "bob", "phone", "--yes"]
		),
		(
			0,
			json!({"result": "saved", "action": "revoke", "account": "bob", "label": "phone"})
		)
	);
}

#[test]
fn api_key_create_rotate_revoke() {
	let env = env("");
	let (code, mut created) = run(&env.config, &["api-key", "create", "ci", "--scope", "read"]);
	assert_eq!(code, 0);
	let first = created["key"].take();
	assert_eq!(
		created,
		json!({
			"result": "saved", "action": "create", "label": "ci", "key": null,
			"scopes": ["read"], "domains": [], "account": null, "expires_at": null, "ip_cidr": null,
		})
	);
	let (code, mut rotated) = run(&env.config, &["api-key", "rotate", "ci"]);
	assert_eq!(code, 0);
	let second = rotated["key"].take();
	assert!(
		first.is_string() && second.is_string() && first != second,
		"the key did not change"
	);
	assert_eq!(
		rotated,
		json!({"result": "saved", "action": "rotate", "label": "ci", "key": null})
	);
	assert_eq!(
		run(&env.config, &["api-key", "revoke", "ci", "--yes"]),
		(
			0,
			json!({"result": "saved", "action": "revoke", "label": "ci"})
		)
	);
}

#[test]
fn archive_purge_of_an_empty_archive() {
	let env = env("[storage]\ndeleted_retention_days = 7\n");
	add_account(&env, "bob");
	let output = epistle(
		&[
			"archive",
			"purge",
			"--config",
			&env.config,
			"bob",
			"--yes",
			"--json",
		],
		b"",
	);
	assert_eq!(
		json(&output),
		(
			0,
			json!({"result": "unchanged", "action": "purge", "account": "bob", "purged": 0})
		)
	);
}
