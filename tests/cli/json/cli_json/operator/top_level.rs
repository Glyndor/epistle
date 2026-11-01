//! `--json` on the flat commands: checks, key generators, record
//! listings, reports, import and restore.

use serde_json::{Value, json};

use crate::harness::{add_account, env, epistle, json};

fn run(args: &[&str], stdin: &[u8]) -> (i32, Value) {
	let mut full = args.to_vec();
	full.push("--json");
	json(&epistle(&full, stdin))
}

#[test]
fn config_check_lists_its_warnings() {
	let env = env("[domain_aliases]\n\"Example.net\" = \"example.org\"\n");
	assert_eq!(
		run(&["config-check", "--config", &env.config], b""),
		(
			0,
			json!({
				"result": "valid",
				"warnings": [
					"domain_aliases: \"Example.net\" = \"example.org\" (used as \"example.net\" = \"example.org\") is not lowercase in the configuration file"
				],
			})
		)
	);
	let clean = crate::harness::env("");
	assert_eq!(
		run(&["config-check", "--config", &clean.config], b""),
		(0, json!({"result": "valid", "warnings": []}))
	);
}

#[test]
fn token_hash_is_the_sha256_of_the_line() {
	// sha256("hunter2"), the value `token_hash_from` is pinned to.
	assert_eq!(
		run(&["token-hash"], b"hunter2\n"),
		(
			0,
			json!({ "token_hash": "sha256:f52fbd32b2b3b86ff88ef6c490628285f482af15ddcb29541f94bcf526a3f6c7" })
		)
	);
}

#[test]
fn key_generators_name_what_they_wrote() {
	let env = env("");
	let (code, key) = run(&["storage-keygen"], b"");
	assert_eq!(code, 0);
	assert_eq!(key.as_object().map(|object| object.len()), Some(1));
	assert_eq!(
		key["key"].as_str().map(str::len),
		Some(44),
		"a base64 32-byte key"
	);

	let dkim = env.dir.path().join("dkim.pem");
	let dkim_path = dkim.to_string_lossy().into_owned();
	let (code, mut generated) = run(&["dkim-keygen", "--out", &dkim_path], b"");
	assert_eq!(code, 0);
	let record = generated["record"].take();
	assert!(
		record
			.as_str()
			.is_some_and(|record| record.starts_with("v=DKIM1; k=ed25519; p=")),
		"record {record}"
	);
	assert_eq!(
		generated,
		json!({"result": "saved", "action": "dkim-keygen", "out": dkim_path, "algorithm": "ed25519", "record": null})
	);

	let oauth = env.dir.path().join("oauth.toml");
	let oauth_path = oauth.to_string_lossy().into_owned();
	let (code, mut generated) = run(&["oauth-keygen", "--out", &oauth_path], b"");
	assert_eq!(code, 0);
	let public = generated["public_key"].take();
	assert!(public.is_string(), "no public key");
	let written = std::fs::read_to_string(&oauth).expect("key file");
	assert!(
		written.contains(public.as_str().expect("string")),
		"the public key printed is not the one written"
	);
	assert_eq!(
		generated,
		json!({"result": "saved", "action": "oauth-keygen", "out": oauth_path, "public_key": null, "algorithm": "ES256"})
	);
	assert!(
		!generated.to_string().contains("signing_key"),
		"the private key reached stdout"
	);
}

#[test]
fn srv_records_are_objects() {
	let env = env("");
	let (code, records) = run(&["srv-records", "--config", &env.config], b"");
	assert_eq!(code, 0);
	let records = records.as_array().expect("array");
	assert!(records.contains(
		&json!({"name": "_imaps._tcp.example.org.", "ttl": 3600, "type": "SRV", "value": "10 1 993 mail.example.org."})
	));
	assert_eq!(
		records.last(),
		Some(
			&json!({"name": "_pop3._tcp.example.org.", "ttl": 3600, "type": "SRV", "value": "0 0 0 ."})
		)
	);
}

#[test]
fn dns_records_are_objects() {
	let env = env("");
	let (code, records) = run(&["dns-records", "--config", &env.config], b"");
	assert_eq!(code, 0);
	assert!(
		records.as_array().expect("array").contains(
			&json!({"name": "example.org", "ttl": 3600, "type": "MX", "value": "10 mail.example.org"})
		),
		"{records}"
	);
}

#[test]
fn verify_and_reports_on_an_empty_store() {
	let env = env("");
	assert_eq!(
		run(&["verify", "--config", &env.config], b""),
		(0, json!({"accounts": 0, "messages": 0, "problems": []}))
	);
	assert_eq!(
		run(&["reports", "--config", &env.config], b""),
		(
			0,
			json!({
				"dmarc": {"ingested": 0, "domains": []},
				"tlsrpt": {"ingested": 0, "domains": []},
			})
		)
	);
}

#[test]
fn import_counts_what_it_stored() {
	let env = env("");
	add_account(&env, "bob");
	let mbox = b"From a@example.net Mon Jan  1 00:00:00 2024\nSubject: one\n\nbody\n\n\
		From b@example.net Mon Jan  1 00:00:00 2024\nSubject: two\n\nbody\n";
	assert_eq!(
		run(
			&["import", "--config", &env.config, "--account", "bob"],
			mbox
		),
		(
			0,
			json!({"result": "saved", "action": "import", "account": "bob", "imported": 2})
		)
	);
}

#[test]
fn restore_dry_run_lists_the_entries() {
	let env = env("");
	add_account(&env, "bob");
	let backup = epistle(&["backup", "--config", &env.config], b"");
	assert!(backup.status.success(), "backup failed");
	let (code, value) = run(
		&["restore", "--config", &env.config, "--dry-run", "--force"],
		&backup.stdout,
	);
	assert_eq!(code, 0);
	// The archive is rooted at `data/`, and the dry run prefixes each entry
	// with the `data/` it lands under.
	assert_eq!(
		value,
		json!({
			"result": "dry-run", "action": "restore", "entries": 2,
			"paths": ["data/data/.accounts.toml.lock", "data/data/accounts.toml"],
		})
	);
}

#[test]
fn init_prints_the_answers_template_as_a_string() {
	let (code, value) = run(&["init", "--print-answers"], b"");
	assert_eq!(code, 0);
	let template = value["answers_template"].as_str().expect("template");
	assert!(template.contains("hostname"), "template: {template}");
}
