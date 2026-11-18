//! The public HTTPS endpoint `init` leaves behind: the `[mta_sts]` policy
//! directory, the `autoconfigs` listener and the names the certificate
//! covers. A re-run and a configuration the operator already shaped must
//! keep what the operator set.

use std::net::{IpAddr, Ipv6Addr};

use super::super::helpers::answers::answers_minimal;
use super::*;
use crate::config::ListenerKind;

fn desired_for(answers: &Answers) -> apply_config::DesiredConfig {
	let mail_addr: IpAddr = Ipv6Addr::UNSPECIFIED.into();
	let dir = std::path::PathBuf::from("/var/lib/epistle/keys");
	apply_config::build_config(
		answers,
		mail_addr,
		Some(&dir.join("s1.pem")),
		None,
		&dir.join("cert.pem"),
		&dir.join("key.pem"),
	)
	.expect("build_config")
}

fn as_value(desired: &apply_config::DesiredConfig) -> toml::Value {
	toml::from_str(&toml::to_string(desired).expect("serialise")).expect("parse")
}

#[test]
fn build_config_points_the_policy_directory_into_the_data_directory() {
	let desired = desired_for(&answers_minimal());
	assert_eq!(desired.mta_sts.policy_dir, "/var/lib/epistle/mta-sts");
	let value = as_value(&desired);
	let section = value
		.get("mta_sts")
		.and_then(toml::Value::as_table)
		.expect("[mta_sts] is written");
	// `mode` and `max_age` stay the operator's: writing them would put
	// back the default over a value set by hand on every re-run.
	let keys: Vec<&str> = section.keys().map(String::as_str).collect();
	assert_eq!(keys, vec!["policy_dir"], "{section:?}");
}

#[test]
fn build_config_writes_the_autoconfigs_listener_on_the_mail_address() {
	let desired = desired_for(&answers_minimal());
	let listener = desired
		.listeners
		.iter()
		.find(|l| l.kind == "autoconfigs")
		.expect("the public endpoint listener");
	assert_eq!(listener.addr, IpAddr::from(Ipv6Addr::UNSPECIFIED));
	let parsed: crate::config::Listener =
		toml::from_str(&format!("kind = {:?}", listener.kind)).expect("kind round-trips");
	assert_eq!(parsed.kind.default_port(), 443);
}

#[test]
fn the_listeners_init_writes_and_publishes_include_the_public_endpoint() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut answers = answers_minimal();
	answers.config_path = dir.path().join("mail.toml");
	let listeners = apply_config::listeners_to_write(&answers).expect("listeners");
	let endpoint: Vec<_> = listeners
		.iter()
		.filter(|l| l.kind == ListenerKind::Autoconfigs)
		.collect();
	assert_eq!(endpoint.len(), 1, "{listeners:?}");
	assert_eq!(endpoint[0].socket_addr().port(), 443);
}

#[test]
fn an_operator_listener_list_is_not_given_the_public_endpoint() {
	// A server that already has a listener list keeps it as it is: a
	// re-run or `stack update` must not open port 443 on it.
	let dir = tempfile::tempdir().expect("tempdir");
	let path = dir.path().join("mail.toml");
	std::fs::write(
		&path,
		"hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/epistle\"\n\
		 domains = [\"example.org\"]\n\n[[listeners]]\nkind = \"smtp\"\naddr = \"::\"\n",
	)
	.expect("config");
	let mut answers = answers_minimal();
	answers.config_path = path;
	let listeners = apply_config::listeners_to_write(&answers).expect("listeners");
	assert_eq!(listeners.len(), 1, "{listeners:?}");
	assert!(listeners[0].kind == ListenerKind::Smtp);
}

#[test]
fn the_plan_lists_the_public_endpoint_with_its_port() {
	let plan = plan(&answers_minimal()).expect("plan");
	let entries = plan
		.steps
		.iter()
		.find_map(|step| match step {
			PlanStep::Listeners { entries, .. } => Some(entries),
			_ => None,
		})
		.expect("listeners step");
	let entry = entries
		.iter()
		.find(|e| e.kind == "autoconfigs")
		.expect("the plan names the public endpoint");
	assert_eq!(entry.port, 443);
}

#[test]
fn merging_updates_the_policy_directory_and_keeps_the_operators_mode() {
	let existing: toml::Value = toml::from_str(
		"hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/epistle\"\n\
		 domains = [\"example.org\"]\n\n[mta_sts]\npolicy_dir = \"/old/place\"\n\
		 mode = \"enforce\"\nmax_age = 86400\n",
	)
	.expect("existing");
	let desired = as_value(&desired_for(&answers_minimal()));
	let merged = apply_config::reconcile(existing, desired.clone(), false);
	let section = merged.get("mta_sts").expect("[mta_sts]");
	assert_eq!(
		section.get("policy_dir").and_then(toml::Value::as_str),
		Some("/var/lib/epistle/mta-sts")
	);
	assert_eq!(
		section.get("mode").and_then(toml::Value::as_str),
		Some("enforce")
	);
	assert_eq!(
		section.get("max_age").and_then(toml::Value::as_integer),
		Some(86400)
	);
	// A second run on its own output changes nothing.
	assert_eq!(
		apply_config::reconcile(merged.clone(), desired, false),
		merged
	);
}

#[test]
fn the_certificate_covers_the_hostname_first_and_the_public_names_of_each_domain() {
	let mut answers = answers_minimal();
	answers.domains = vec!["example.org".to_string(), "example.net".to_string()];
	assert_eq!(
		apply_config_acme::certificate_domains(&answers),
		vec![
			"mail.example.org",
			"autoconfig.example.org",
			"autodiscover.example.org",
			"mta-sts.example.org",
			"autoconfig.example.net",
			"autodiscover.example.net",
			"mta-sts.example.net",
		]
	);
}

#[test]
fn a_domain_with_accents_or_capitals_gets_the_same_names_as_the_rest() {
	let mut answers = answers_minimal();
	answers.hostname = "Mail.Example.ORG".to_string();
	answers.domains = vec!["BÜCHER.example".to_string()];
	answers.normalise();
	let names = apply_config_acme::certificate_domains(&answers);
	assert_eq!(names[0], "mail.example.org");
	for name in &names[1..] {
		assert!(
			name.is_ascii() && *name == name.to_ascii_lowercase(),
			"every public name is lower-case ASCII"
		);
	}
	assert!(
		names.contains(&"autoconfig.xn--bcher-kva.example".to_string()),
		"the internationalised name must be listed in ASCII form"
	);
}
