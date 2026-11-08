//! Where the DNS credential goes when the certificates container is on: to
//! `certs`, and out of `mail`, which no longer builds the provider.

use super::write::{
	TOKEN, action, forwarded_by, mounted, mounted_by, split_stack_with, stack, unset_of,
};
use super::*;

#[test]
fn with_the_certificates_container_the_token_goes_to_certs_only() {
	let (_dir, path, compose) = stack();
	let mut document: serde_json::Value =
		serde_json::from_str(&std::fs::read_to_string(&compose).unwrap()).unwrap();
	document["services"]["certs"] =
		serde_json::json!({"environment": {"TZ": "UTC"}, "volumes": []});
	std::fs::write(&compose, document.to_string()).unwrap();
	let (mut out, mut status) = (Vec::new(), Vec::new());
	let mut reached = None;
	let result = execute_with(
		&path,
		action(&["--token-file", TOKEN]),
		false,
		false,
		&mut out,
		&mut status,
		|_, action| {
			reached = Some(action);
			ExitCode::SUCCESS
		},
	);
	assert_eq!(result.unwrap(), ExitCode::SUCCESS);
	assert!(!mounted(&compose, TOKEN), "mail must not get the token");
	let after: serde_json::Value =
		serde_json::from_str(&std::fs::read_to_string(&compose).unwrap()).unwrap();
	assert!(
		after["services"]["certs"]["volumes"]
			.as_array()
			.unwrap()
			.iter()
			.any(|mount| mount["source"] == TOKEN && mount["read_only"] == true),
		"{after}"
	);
	assert!(
		matches!(&reached, Some(StackAction::Recreate { service }) if service == "certs"),
		"{reached:?}"
	);
}

/// The split's promise: with the certificates container running, `mail` must
/// not keep the credential. A compose file that carries the token in `mail`
/// as well has to lose it there, or the operator believes the zone token is
/// out of the container that takes SMTP from the internet.
#[test]
fn with_the_certificates_container_the_token_leaves_mail() {
	let (_dir, path, compose) = split_stack_with(
		&format!(
			"hostname = 'mail.example.org'\ndata_dir = {{data:?}}\n[dns]\nprovider = 'cloudflare'\nzone = 'example.org'\ntoken_file = '{TOKEN}'\n"
		),
		&[(TOKEN, TOKEN)],
	);
	let (mut out, mut status) = (Vec::new(), Vec::new());
	let mut reached = None;
	let result = execute_with(
		&path,
		action(&["--token-file", TOKEN]),
		false,
		false,
		&mut out,
		&mut status,
		|_, action| {
			reached = Some(action);
			ExitCode::SUCCESS
		},
	);
	assert_eq!(result.unwrap(), ExitCode::SUCCESS);
	let after = std::fs::read_to_string(&compose).unwrap();
	assert!(
		!mounted_by(&compose, "mail", TOKEN),
		"mail must not keep the token: {after}"
	);
	assert!(
		mounted_by(&compose, "certs", TOKEN),
		"the certificates container holds the token: {after}"
	);
	assert!(
		matches!(&reached, Some(StackAction::RecreateServices { services })
			if services == &["certs".to_string(), "mail".to_string()]),
		"both containers have to be recreated, or mail keeps the mount it had: {reached:?}"
	);
}

/// The same for the variable: with the certificates container running,
/// `mail` must not forward the token variable.
#[test]
fn with_the_certificates_container_the_token_variable_leaves_mail() {
	let (_dir, path, compose) = split_stack_with(
		"hostname = 'mail.example.org'\ndata_dir = {data:?}\n[dns]\nprovider = 'cloudflare'\nzone = 'example.org'\ntoken_env = 'EPI_DNS_TOKEN'\n",
		&[],
	);
	let mut document: serde_json::Value =
		serde_json::from_str(&std::fs::read_to_string(&compose).unwrap()).unwrap();
	document["services"]["mail"]["environment"]["EPI_DNS_TOKEN"] = "${EPI_DNS_TOKEN}".into();
	std::fs::write(&compose, document.to_string()).unwrap();
	let (mut out, mut status) = (Vec::new(), Vec::new());
	let result = execute_with(
		&path,
		action(&["--token-env", "EPI_DNS_TOKEN"]),
		false,
		false,
		&mut out,
		&mut status,
		|_, _| ExitCode::SUCCESS,
	);
	assert_eq!(result.unwrap(), ExitCode::SUCCESS);
	let after = std::fs::read_to_string(&compose).unwrap();
	assert!(
		!forwarded_by(&compose, "mail", "EPI_DNS_TOKEN"),
		"mail must not forward the token variable: {after}"
	);
	assert!(
		forwarded_by(&compose, "certs", "EPI_DNS_TOKEN"),
		"the certificates container holds the token variable: {after}"
	);
}

/// `unset` takes the credential out of the container that holds it and out
/// of the one that still carries it.
#[test]
fn unset_takes_the_credential_out_of_the_service_that_carries_it() {
	let (_dir, path, compose) = split_stack_with(
		&format!(
			"hostname = 'mail.example.org'\ndata_dir = {{data:?}}\n[dns]\nprovider = 'cloudflare'\nzone = 'example.org'\ntoken_file = '{TOKEN}'\n"
		),
		&[(TOKEN, TOKEN)],
	);
	let (mut out, mut status) = (Vec::new(), Vec::new());
	let mut reached = None;
	let result = execute_with(
		&path,
		unset_of("example.org"),
		false,
		false,
		&mut out,
		&mut status,
		|_, action| {
			reached = Some(action);
			ExitCode::SUCCESS
		},
	);
	assert_eq!(result.unwrap(), ExitCode::SUCCESS);
	let after = std::fs::read_to_string(&compose).unwrap();
	assert!(
		!mounted_by(&compose, "mail", TOKEN),
		"mail must not keep the token: {after}"
	);
	assert!(
		!mounted_by(&compose, "certs", TOKEN),
		"the token has to leave the container that held it too: {after}"
	);
	assert!(
		matches!(&reached, Some(StackAction::RecreateServices { services })
			if services.contains(&"mail".to_string())),
		"the container that carried the token has to be recreated: {reached:?}"
	);
}

/// The override the operator keeps beside the generated file is merged with
/// it, so a credential it hands back to `mail` is a credential the container
/// that takes SMTP still has, whatever the generated file says. The command
/// has to name it.
#[test]
fn the_override_that_hands_the_token_back_to_mail_is_named() {
	let (_dir, path, compose) = split_stack_with(
		&format!(
			"hostname = 'mail.example.org'\ndata_dir = {{data:?}}\n[dns]\nprovider = 'cloudflare'\nzone = 'example.org'\ntoken_file = '{TOKEN}'\n"
		),
		&[],
	);
	std::fs::write(
		compose.with_file_name("compose.override.yaml"),
		format!(
			"services:\n  mail:\n    volumes:\n      - type: bind\n        source: {TOKEN}\n        \
			 target: {TOKEN}\n        read_only: true\n"
		),
	)
	.expect("override");
	let (mut out, mut status) = (
		Vec::new(),
		anstream::AutoStream::new(Vec::new(), anstream::ColorChoice::Auto),
	);
	let result = execute_with(
		&path,
		action(&["--token-file", TOKEN]),
		false,
		false,
		&mut out,
		&mut status,
		|_, _| ExitCode::SUCCESS,
	);
	assert_eq!(result.unwrap(), ExitCode::SUCCESS);
	let printed = String::from_utf8(status.into_inner()).unwrap();
	assert!(
		printed.contains("compose.override.yaml") && printed.contains("mail"),
		"the override that hands the credential back to mail has to be named: {printed}"
	);
}
