use super::{minimal_answers, render};
use crate::cli::init::answers::DnsAnswers;
use serde_json::json;

#[test]
fn dns_token_env_is_forwarded_by_interpolation() {
	let mut answers = minimal_answers();
	answers.dns = Some(DnsAnswers {
		provider: "cloudflare".into(),
		zone: "example.org".into(),
		token_env: Some("EPI_DNS_TOKEN".into()),
		..Default::default()
	});
	let value = render(&answers, false);
	assert_eq!(
		value["services"]["mail"]["environment"]["EPI_DNS_TOKEN"], "${EPI_DNS_TOKEN}",
		"DNS token environment must be forwarded without persisting its value"
	);
	assert_eq!(value["services"]["mail"]["environment"]["TZ"], "UTC");
}

#[test]
fn external_dns_token_file_is_visible_at_same_read_only_path() {
	let mut answers = minimal_answers();
	answers.dns = Some(DnsAnswers {
		provider: "cloudflare".into(),
		zone: "example.org".into(),
		token_file: Some("/secure/dns:prod/token".into()),
		..Default::default()
	});
	let value = render(&answers, false);
	let mounts = value["services"]["mail"]["volumes"].as_array().unwrap();
	assert!(mounts.contains(&json!({"type": "bind", "source": "/secure/dns:prod/token", "target": "/secure/dns:prod/token", "read_only": true, "bind": {"selinux": "Z"}})), "DNS token file must be mounted read-only at its configured path");
}
