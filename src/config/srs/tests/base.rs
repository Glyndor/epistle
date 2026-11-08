//! `[[srs_domain]]`: what the loader accepts and refuses, and what `status`
//! and `config-check` say while domains still share a secret.

use crate::config::{Config, ConfigError};
use crate::test_fixtures::fresh_secret;

const HEAD: &str = "hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\n";

fn load(body: &str) -> Result<Config, ConfigError> {
	let config: Config = toml::from_str(&format!("{HEAD}{body}"))
		.map_err(|error| ConfigError::Invalid(error.to_string()))?;
	config.validate()?;
	Ok(config)
}

fn refusal(body: &str) -> String {
	load(body).expect_err("the loader refuses this").to_string()
}

fn entry(domain: &str, secret: &str) -> String {
	format!("[[srs_domain]]\nname = \"{domain}\"\nsecret = \"{secret}\"\n")
}

#[test]
fn the_server_wide_secret_alone_loads_as_it_always_did() {
	let secret = fresh_secret();
	let config = load(&format!(
		"domains = [\"a.example\", \"b.example\"]\nsrs_secret = \"{secret}\"\n\
		 [[accounts]]\nname = \"alice\"\naddresses = [\"alice@a.example\"]\n\
		 forward = [\"x@elsewhere.example\"]\n"
	))
	.expect("an installation with one secret still loads");
	assert!(config.srs_domain.is_empty());
	assert!(config.srs_enabled());
}

#[test]
fn each_domain_with_its_own_secret_loads_and_the_global_may_stay() {
	let (a, b, global) = (fresh_secret(), fresh_secret(), fresh_secret());
	let config = load(&format!(
		"domains = [\"a.example\", \"b.example\"]\nsrs_secret = \"{global}\"\n{}{}",
		entry("a.example", &a),
		entry("B.Example", &b),
	))
	.expect("two secrets of their own");
	assert!(config.srs_domain("b.example").is_some());
	assert!(config.srs_notices().is_empty());
}

#[test]
fn two_domains_sharing_a_secret_are_refused_and_both_are_named() {
	let shared = fresh_secret();
	let message = refusal(&format!(
		"domains = [\"a.example\", \"b.example\"]\n{}{}",
		entry("a.example", &shared),
		entry("b.example", &shared),
	));
	assert!(message.contains("\"b.example\""), "{message}");
	assert!(message.contains("a.example"), "{message}");
	assert!(message.contains("shares a secret"), "{message}");
}

#[test]
fn a_domain_secret_equal_to_the_global_one_is_refused() {
	let shared = fresh_secret();
	let message = refusal(&format!(
		"domains = [\"a.example\"]\nsrs_secret = \"{shared}\"\n{}",
		entry("a.example", &shared),
	));
	assert!(message.contains("server-wide `srs_secret`"), "{message}");
}

#[test]
fn a_previous_secret_cannot_be_another_domains_secret() {
	let (a, b) = (fresh_secret(), fresh_secret());
	let message = refusal(&format!(
		"domains = [\"a.example\", \"b.example\"]\n{}{}previous_secret = \"{a}\"\n",
		entry("a.example", &a),
		entry("b.example", &b),
	));
	assert!(message.contains("shares a secret"), "{message}");
}

#[test]
fn a_secret_that_replaces_itself_is_refused() {
	let a = fresh_secret();
	let message = refusal(&format!(
		"domains = [\"a.example\"]\n{}previous_secret = \"{a}\"\n",
		entry("a.example", &a),
	));
	assert!(message.contains("previous_secret"), "{message}");
}

#[test]
fn an_entry_for_a_domain_the_server_does_not_host_is_refused() {
	let message = refusal(&format!(
		"domains = [\"a.example\"]\n{}",
		entry("other.example", &fresh_secret()),
	));
	assert!(message.contains("not in `domains`"), "{message}");
}

#[test]
fn a_domain_listed_twice_is_refused() {
	let message = refusal(&format!(
		"domains = [\"a.example\"]\n{}{}",
		entry("a.example", &fresh_secret()),
		entry("A.example", &fresh_secret()),
	));
	assert!(message.contains("listed more than once"), "{message}");
}

#[test]
fn a_placeholder_secret_is_refused() {
	let message = refusal(&format!(
		"domains = [\"a.example\"]\n{}",
		entry("a.example", "short"),
	));
	assert!(message.contains("shorter than"), "{message}");
}

#[test]
fn forwarding_is_covered_by_the_domains_own_secret_without_a_global_one() {
	let body = |covered: bool| {
		let own = if covered {
			entry("a.example", &fresh_secret())
		} else {
			String::new()
		};
		format!(
			"domains = [\"a.example\"]\n{own}[[accounts]]\nname = \"alice\"\n\
			 addresses = [\"alice@a.example\"]\nforward = [\"x@elsewhere.example\"]\n"
		)
	};
	load(&body(true)).expect("covered by its own secret");
	let message = refusal(&body(false));
	assert!(message.contains("srs_secret"), "{message}");
	assert!(message.contains("[[srs_domain]]"), "{message}");
}

#[test]
fn forwarding_from_a_domain_without_a_secret_is_refused_while_another_has_one() {
	let message = refusal(&format!(
		"domains = [\"a.example\", \"b.example\"]\n{}[[accounts]]\nname = \"bob\"\n\
		 addresses = [\"bob@b.example\"]\nforward = [\"x@elsewhere.example\"]\n",
		entry("a.example", &fresh_secret()),
	));
	assert!(message.contains("\"bob\""), "{message}");
}

#[test]
fn two_domains_on_the_global_secret_are_reported_and_one_is_not() {
	let global = fresh_secret();
	let shared = load(&format!(
		"domains = [\"a.example\", \"b.example\"]\nsrs_secret = \"{global}\"\n"
	))
	.expect("loads");
	let notices = shared.srs_notices();
	assert_eq!(notices.len(), 1, "{notices:?}");
	assert!(notices[0].contains("a.example, b.example"), "{notices:?}");
	assert!(notices[0].contains("epistle srs split"), "{notices:?}");

	let one_split = load(&format!(
		"domains = [\"a.example\", \"b.example\"]\nsrs_secret = \"{global}\"\n{}",
		entry("a.example", &fresh_secret()),
	))
	.expect("loads");
	assert!(one_split.srs_notices().is_empty());

	let single = load(&format!(
		"domains = [\"a.example\"]\nsrs_secret = \"{global}\"\n"
	))
	.expect("loads");
	assert!(single.srs_notices().is_empty());
	let none = load("domains = [\"a.example\", \"b.example\"]\n").expect("loads");
	assert!(none.srs_notices().is_empty());
}

#[test]
fn a_disabled_domain_does_not_count_as_sharing() {
	let global = fresh_secret();
	let config = load(&format!(
		"domains = [\"a.example\", \"b.example\"]\ndisabled_domains = [\"b.example\"]\n\
		 srs_secret = \"{global}\"\n"
	))
	.expect("loads");
	assert!(config.srs_notices().is_empty());
}

#[test]
fn debug_never_prints_a_secret() {
	let (own, previous) = (fresh_secret(), fresh_secret());
	let config = load(&format!(
		"domains = [\"a.example\"]\n{}previous_secret = \"{previous}\"\n",
		entry("a.example", &own),
	))
	.expect("loads");
	let shown = format!("{config:?}");
	assert!(!shown.contains(&own), "the secret was printed");
	assert!(
		!shown.contains(&previous),
		"the previous secret was printed"
	);
	assert!(shown.contains("a.example"));
}
