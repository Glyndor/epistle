//! A re-run of `init` keeps a list of `[[dns]]` tables in `mail.toml`, so the
//! compose file it renders has to carry the credential of every one of them.

use super::{minimal_answers, render};
use crate::cli::init::answers::DnsAnswers;
use serde_json::json;

const LIST: &str = "[[dns]]\nprovider = 'cloudflare'\nzone = 'example.org'\ntoken_file = '/secure/org.token'\n\n[[dns]]\nprovider = 'desec'\nzone = 'client.net'\ntoken_env = 'CLIENT_TOKEN'\n\n[[dns]]\nprovider = 'bunny'\nzone = 'shop.net'\ntoken_file = '/secure/org.token'\n";

fn mount(path: &str) -> serde_json::Value {
	json!({"type": "bind", "source": path, "target": path, "read_only": true, "bind": {"selinux": "Z"}})
}

#[test]
fn the_compose_file_carries_the_credential_of_every_kept_zone() {
	let dir = tempfile::tempdir().unwrap();
	let mut answers = minimal_answers();
	answers.config_path = dir.path().join("mail.toml");
	std::fs::write(&answers.config_path, LIST).unwrap();
	// The answers carry their own single entry; the kept list wins.
	answers.dns = Some(DnsAnswers {
		provider: "cloudflare".into(),
		zone: "other.example".into(),
		token_file: Some("/secure/answers.token".into()),
		..Default::default()
	});
	let value = render(&answers, false);
	let mail = &value["services"]["mail"];
	let mounts = mail["volumes"].as_array().unwrap();
	assert!(mounts.contains(&mount("/secure/org.token")));
	assert!(
		!mounts.contains(&mount("/secure/answers.token")),
		"the ignored answers were mounted"
	);
	assert_eq!(mail["environment"]["CLIENT_TOKEN"], "${CLIENT_TOKEN}");
	let once = mounts
		.iter()
		.filter(|m| m["source"] == "/secure/org.token")
		.count();
	assert_eq!(once, 1, "a file two zones read is mounted once");
}

#[test]
fn a_single_dns_table_still_follows_the_answers() {
	let dir = tempfile::tempdir().unwrap();
	let mut answers = minimal_answers();
	answers.config_path = dir.path().join("mail.toml");
	std::fs::write(
		&answers.config_path,
		"[dns]\nprovider = 'cloudflare'\nzone = 'example.org'\ntoken_file = '/secure/old.token'\n",
	)
	.unwrap();
	answers.dns = Some(DnsAnswers {
		provider: "cloudflare".into(),
		zone: "example.org".into(),
		token_file: Some("/secure/new.token".into()),
		..Default::default()
	});
	let value = render(&answers, false);
	let mounts = value["services"]["mail"]["volumes"].as_array().unwrap();
	assert!(mounts.contains(&mount("/secure/new.token")));
	assert!(!mounts.contains(&mount("/secure/old.token")));
}
