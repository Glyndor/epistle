//! `--json` on the commands that edit the configuration file. No stack
//! runs here, so a change reports `reload: restart-needed`.

use serde_json::{Value, json};

use crate::harness::{env, epistle, json};

fn run(config: &str, resource: &str, args: &[&str], stdin: &[u8]) -> (i32, Value) {
	let mut full = vec![resource, "--config", config];
	full.extend_from_slice(args);
	full.push("--json");
	json(&epistle(&full, stdin))
}

fn saved(action: &str, fields: Value) -> Value {
	let mut object = json!({ "result": "saved", "action": action });
	object
		.as_object_mut()
		.expect("object")
		.extend(fields.as_object().expect("fields").clone());
	object["reload"] = "restart-needed".into();
	object
}

#[test]
fn relay_add_and_remove() {
	let env = env("");
	assert_eq!(
		run(
			&env.config,
			"relay",
			&[
				"add",
				"--domain",
				"example.net",
				"--host",
				"relay.example.net"
			],
			b""
		),
		(
			0,
			saved(
				"add",
				json!({"account": null, "domain": "example.net", "host": "relay.example.net"})
			)
		)
	);
	assert_eq!(
		run(
			&env.config,
			"relay",
			&["remove", "--domain", "example.net"],
			b""
		),
		(
			0,
			saved("remove", json!({"account": null, "domain": "example.net"}))
		)
	);
}

#[test]
fn webhook_set_never_prints_the_secret() {
	let env = env("");
	let (code, value) = run(
		&env.config,
		"webhook",
		&["set", "https://hooks.example/mail", "--secret-stdin"],
		b"s3cr3t-webhook-value\n",
	);
	assert_eq!(code, 0);
	assert_eq!(
		value,
		saved(
			"set",
			json!({"url": "https://hooks.example/mail", "secret": "set"})
		)
	);
	assert!(
		!value.to_string().contains("s3cr3t"),
		"the secret reached stdout"
	);
	assert_eq!(
		run(&env.config, "webhook", &["unset"], b""),
		(0, saved("unset", json!({})))
	);
}

#[test]
fn alert_add_and_remove() {
	let env = env("[[listeners]]\nkind = \"smtp\"\naddr = \"0.0.0.0\"\n");
	let add = [
		"add",
		"bounces",
		"--metric",
		"bounced",
		"--op",
		">=",
		"--threshold",
		"5",
		"--window",
		"5m",
		"--email",
		"ops@example.org",
	];
	assert_eq!(
		run(&env.config, "alert", &add, b""),
		(0, saved("add", json!({"alert": "bounces"})))
	);
	assert_eq!(
		run(&env.config, "alert", &["remove", "bounces"], b""),
		(0, saved("remove", json!({"alert": "bounces"})))
	);
}

#[test]
fn dns_provider_set_and_unset() {
	let env = env("");
	let set = ["provider", "set", "manual", "--zone", "example.org"];
	assert_eq!(
		run(&env.config, "dns", &set, b""),
		(0, saved("provider set", json!({"provider": "manual"})))
	);
	assert_eq!(
		run(&env.config, "dns", &["provider", "unset"], b""),
		(0, saved("provider unset", json!({})))
	);
}

#[test]
fn storage_blobs_set_fs() {
	let env = env("");
	assert_eq!(
		run(&env.config, "storage", &["blobs", "set", "fs"], b""),
		(0, saved("blobs set", json!({"backend": "fs"})))
	);
}

#[test]
fn service_disable_then_again() {
	let env = env(
		"[[listeners]]\nkind = \"smtp\"\naddr = \"0.0.0.0\"\n[[listeners]]\nkind = \"web-dav\"\n",
	);
	assert_eq!(
		run(&env.config, "service", &["disable", "webdav"], b""),
		(
			0,
			saved("disable", json!({"service": "webdav", "enabled": false}))
		)
	);
	assert_eq!(
		run(&env.config, "service", &["disable", "webdav"], b""),
		(
			0,
			json!({
				"result": "unchanged", "action": "disable", "service": "webdav",
				"enabled": false, "reload": "none",
			})
		)
	);
}

#[test]
fn antispam_set_add_remove_unset() {
	let env = env("");
	let key = |action: &str, key: &str| saved(action, json!({ "key": key }));
	assert_eq!(
		run(
			&env.config,
			"antispam",
			&["set", "greylist-delay", "5m"],
			b""
		),
		(0, key("set", "greylist-delay"))
	);
	assert_eq!(
		run(
			&env.config,
			"antispam",
			&["add", "dnsbl-zones", "zen.spamhaus.org"],
			b""
		),
		(0, key("add", "dnsbl-zones"))
	);
	assert_eq!(
		run(
			&env.config,
			"antispam",
			&["remove", "dnsbl-zones", "zen.spamhaus.org"],
			b""
		),
		(0, key("remove", "dnsbl-zones"))
	);
	assert_eq!(
		run(&env.config, "antispam", &["unset", "greylist-delay"], b""),
		(0, key("unset", "greylist-delay"))
	);
}

#[test]
fn a_dry_run_prints_the_diff_inside_the_object() {
	let env = env("");
	let before = std::fs::read_to_string(&env.config).expect("config");
	let (code, value) = run(
		&env.config,
		"relay",
		&[
			"add",
			"--domain",
			"example.net",
			"--host",
			"relay.example.net",
			"--dry-run",
		],
		b"",
	);
	assert_eq!(code, 0);
	assert_eq!(value["result"], "dry-run");
	assert_eq!(value["action"], "add");
	assert!(
		value["diff"]
			.as_str()
			.is_some_and(|diff| diff.contains("relay.example.net")),
		"diff: {}",
		value["diff"]
	);
	assert_eq!(
		std::fs::read_to_string(&env.config).expect("config"),
		before
	);
}
