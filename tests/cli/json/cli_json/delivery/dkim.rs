//! `epistle dkim rotate --json`: the plan of a rotation, and the request
//! that hands it to the running server. Neither reaches DNS: the server
//! publishes the new record when it picks the request up.

use std::fs::OpenOptions;
use std::io::Write;

use serde_json::{Value, json};

use crate::harness::{Env, env, epistle, json};

/// A configuration with a freshly generated DKIM key and a DNS provider,
/// which is what makes the rotation automatic.
fn rotating_env() -> Env {
	let env = env("");
	let key = env.dir.path().join("dkim.pem");
	let key = key.to_string_lossy().into_owned();
	let generated = epistle(&["dkim-keygen", "--out", &key, "--json"], b"");
	assert!(generated.status.success(), "dkim-keygen failed");
	let mut config = OpenOptions::new()
		.append(true)
		.open(&env.config)
		.expect("open config");
	write!(
		config,
		"[dkim]\nselector = \"mail\"\nkey_file = {key:?}\n\n\
		 [dns]\nprovider = \"cloudflare\"\nzone = \"example.org\"\ntoken = \"not-a-real-token\"\n"
	)
	.expect("append config");
	env
}

fn rotate(env: &Env, extra: &[&str]) -> (i32, Value) {
	let mut args = vec!["dkim", "rotate", "--config", &env.config, "--json"];
	args.extend_from_slice(extra);
	json(&epistle(&args, b""))
}

#[test]
fn a_dry_run_names_the_selector_it_would_publish() {
	let env = rotating_env();
	let (code, plan) = rotate(&env, &["--dry-run"]);
	assert_eq!(code, 0);
	let next = plan["next"].as_str().expect("next selector").to_string();
	assert!(
		next.starts_with("ed") && next[2..].chars().all(|c| c.is_ascii_digit()),
		"selector {next}"
	);
	assert_eq!(
		plan,
		json!({
			"result": "dry-run", "action": "rotate", "active": "mail", "next": next,
			"publish": [format!("{next}._domainkey.example.org")],
			"retires": null, "rsa": null,
		})
	);
	assert!(
		!env.data_dir().join("dkim-rotate.request").exists(),
		"a dry run wrote the request"
	);
}

#[test]
fn a_rotation_is_queued_for_the_server() {
	let env = rotating_env();
	let (code, queued) = rotate(&env, &[]);
	assert_eq!(code, 0);
	assert_eq!(queued["result"], "queued");
	assert_eq!(queued["action"], "rotate");
	assert_eq!(queued["active"], "mail");
	assert!(
		env.data_dir().join("dkim-rotate.request").is_file(),
		"the request for the server is missing"
	);
}
