//! The split stack: `certs` holds the DNS credential and the ACME account
//! key, `mail` reads the pair read-only and holds neither.

use super::*;
use crate::cli::init::answers::DnsAnswers;
use serde_json::{Value, json};

fn split_answers(token_file: &str) -> crate::cli::init::Answers {
	let mut answers = stack_answers();
	answers.services.certs = true;
	answers.dns = Some(DnsAnswers {
		provider: "cloudflare".into(),
		zone: "example.org".into(),
		token_env: Some("EPI_DNS_TOKEN".into()),
		token_file: Some(token_file.into()),
		..Default::default()
	});
	answers
}

fn bind(source: &str, read_only: bool) -> Value {
	json!({"type": "bind", "source": source, "target": source, "read_only": read_only, "bind": {"selinux": "Z"}})
}

fn mounts<'a>(value: &'a Value, service: &str) -> &'a Vec<Value> {
	value["services"][service]["volumes"]
		.as_array()
		.expect("volumes")
}

#[test]
fn mail_holds_neither_the_dns_credential_nor_the_account_key() {
	let value = render(&split_answers("/secure/dns/token"), true);
	let mail = &value["services"]["mail"];
	assert_eq!(mail["environment"].get("EPI_DNS_TOKEN"), None);
	assert!(
		!mounts(&value, "mail").contains(&bind("/secure/dns/token", true)),
		"{:?}",
		mounts(&value, "mail")
	);
	let sources: Vec<&str> = mail["secrets"]
		.as_array()
		.expect("secrets")
		.iter()
		.filter_map(|secret| secret["source"].as_str())
		.collect();
	assert!(
		!sources.contains(&"epistle_acme_account_key"),
		"mail mounts the account key"
	);
}

#[test]
fn mail_reads_the_pair_read_only_and_runs_the_mail_role() {
	let value = render(&split_answers("/secure/dns/token"), true);
	for dir in [
		"/var/lib/epistle/acme",
		"/var/lib/epistle/dns-tlsa",
		"/var/lib/epistle/compose",
	] {
		assert!(
			mounts(&value, "mail").contains(&bind(dir, true)),
			"{dir} must be read-only in mail: certs acts on it"
		);
	}
	assert_eq!(
		value["services"]["mail"]["command"],
		json!([
			"serve",
			"--config",
			"/etc/epistle/mail.toml",
			"--role",
			"mail"
		])
	);
	assert_eq!(
		value["services"]["mail"]["depends_on"].get("certs"),
		None,
		"mail keeps serving when certs is down"
	);
}

#[test]
fn certs_holds_the_credential_the_key_and_writes_the_pair() {
	let value = render(&split_answers("/secure/dns/token"), true);
	let certs = &value["services"]["certs"];
	assert_eq!(
		certs["command"],
		json!([
			"serve",
			"--config",
			"/etc/epistle/mail.toml",
			"--role",
			"certs"
		])
	);
	assert_eq!(certs["environment"]["EPI_DNS_TOKEN"], "${EPI_DNS_TOKEN}");
	let volumes = mounts(&value, "certs");
	assert!(volumes.contains(&bind("/secure/dns/token", true)));
	assert!(volumes.contains(&bind("/var/lib/epistle/acme", false)));
	assert!(volumes.contains(&bind("/var/lib/epistle/dns-tlsa", false)));
	assert!(
		!volumes.contains(&bind("/var/lib/epistle", false)),
		"the rest of data_dir stays out of certs"
	);
	assert_eq!(certs.get("ports"), None, "no listener, nothing published");
	assert_eq!(certs["read_only"], true);
	assert_eq!(certs["cap_drop"], json!(["ALL"]));
	assert_eq!(certs["user"], value["services"]["mail"]["user"]);
	assert_eq!(
		certs["userns_mode"],
		value["services"]["mail"]["userns_mode"]
	);
	assert_eq!(
		certs["secrets"],
		json!([{"source": "epistle_acme_account_key", "target": "/var/lib/secrets/acme_account.key", "uid": "65532", "gid": "65532", "mode": 400}])
	);
	assert_eq!(
		value["secrets"]["epistle_acme_account_key"]["file"],
		"/var/lib/secrets/acme_account.key"
	);
}

/// The default: the stack that never turns it on renders as before.
#[test]
fn without_certs_mail_keeps_the_credential_and_no_certs_service_exists() {
	let mut answers = split_answers("/secure/dns/token");
	answers.services.certs = false;
	let value = render(&answers, true);
	assert_eq!(value["services"].get("certs"), None);
	assert_eq!(value["secrets"].get("epistle_acme_account_key"), None);
	assert_eq!(
		value["services"]["mail"]["command"],
		json!(["serve", "--config", "/etc/epistle/mail.toml"])
	);
	assert!(mounts(&value, "mail").contains(&bind("/secure/dns/token", true)));
	assert!(!mounts(&value, "mail").contains(&bind("/var/lib/epistle/acme", true)));
}
