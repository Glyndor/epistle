//! The network each service of the split layout runs on: `certs` on one of
//! its own with the routes to the host closed, `mail` on the plain pasta mode
//! it needs to keep the client's address.

use super::*;
use crate::cli::init::answers::DnsAnswers;

/// The answers of a split stack: the DNS credential lives in `certs`.
fn split_answers() -> crate::cli::init::Answers {
	let mut answers = stack_answers();
	answers.services.certs = true;
	answers.dns = Some(DnsAnswers {
		provider: "cloudflare".into(),
		zone: "example.org".into(),
		token_env: Some("EPI_DNS_TOKEN".into()),
		token_file: Some("/secure/dns/token".into()),
		..Default::default()
	});
	answers
}

#[test]
fn certs_runs_on_a_network_of_its_own_with_the_routes_to_the_host_closed() {
	let value = render(&split_answers(), true);
	assert_eq!(
		value["services"]["certs"]["network_mode"], "pasta:--no-map-gw,--map-guest-addr,none",
		"certs must reach the internet and nothing of the host"
	);
}

#[test]
fn mail_keeps_the_plain_pasta_mode() {
	let value = render(&split_answers(), true);
	assert_eq!(
		value["services"]["mail"]["network_mode"], "pasta",
		"mail keeps the plain mode: the client's address survives pasta, and the split does not narrow what mail reaches"
	);
}

/// The layout that never turns the split on renders as it did before: the
/// change lives in the `certs` service, which that layout has no use for.
#[test]
fn the_layout_without_certs_carries_none_of_the_change() {
	let mut answers = split_answers();
	answers.services.certs = false;
	let text = render_for(&answers, true).expect("render");
	assert!(
		!text.contains("map-guest-addr") && !text.contains("no-map-gw"),
		"the layout without certs must not mention the options: {text}"
	);
	let value: serde_json::Value = serde_json::from_str(&text).expect("json");
	assert_eq!(value["services"].get("certs"), None);
	assert_eq!(value["services"]["mail"]["network_mode"], "pasta");
	assert_eq!(
		value.get("networks"),
		None,
		"the generator declares no network of its own"
	);
}
