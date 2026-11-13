//! `[tenant.webhook]`: what the loader accepts and refuses.

use crate::config::{Config, ConfigError};
use crate::test_support::fixtures::fresh_secret;

const HEAD: &str = "hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\n\
	domains = [\"a.example\", \"b.example\"]\n";

fn load(body: &str) -> Result<Config, ConfigError> {
	let config: Config = toml::from_str(&format!("{HEAD}{body}"))
		.map_err(|error| ConfigError::Invalid(error.to_string()))?;
	config.validate()?;
	Ok(config)
}

fn refusal(body: &str) -> String {
	load(body).expect_err("the loader refuses this").to_string()
}

fn tenant(name: &str, domain: &str, webhook: &str) -> String {
	format!("[[tenant]]\nname = \"{name}\"\ndomains = [\"{domain}\"]\n{webhook}")
}

fn hook(url: &str, secret: &str) -> String {
	format!("[tenant.webhook]\nurl = \"{url}\"\nsecret = \"{secret}\"\n")
}

#[test]
fn a_tenant_may_carry_its_own_webhook() {
	let config = load(&format!(
		"{}{}",
		tenant(
			"alpha",
			"a.example",
			&hook("https://alpha.example/hook", &fresh_secret())
		),
		tenant("beta", "b.example", ""),
	))
	.expect("loads");
	let alpha = config.tenants[0].webhook.as_ref().expect("alpha's webhook");
	assert_eq!(alpha.url, "https://alpha.example/hook");
	assert!(alpha.enabled);
	assert!(config.tenants[1].webhook.is_none());
	assert!(
		config.webhook.is_none(),
		"the server-wide webhook is untouched"
	);
}

#[test]
fn an_install_without_tenant_webhooks_loads_as_it_did() {
	let config = load(&format!(
		"[webhook]\nurl = \"https://ops.example/hook\"\n{}",
		tenant("alpha", "a.example", "")
	))
	.expect("loads");
	assert!(config.active_webhook().is_some());
	assert!(config.tenants[0].webhook.is_none());
}

#[test]
fn the_secret_of_a_tenant_webhook_is_never_printed() {
	let secret = fresh_secret();
	let config = load(&tenant(
		"alpha",
		"a.example",
		&hook("https://alpha.example/hook", &secret),
	))
	.expect("loads");
	assert!(!format!("{config:?}").contains(&secret));
}

#[test]
fn a_tenant_url_passes_the_checks_the_servers_does() {
	for url in [
		"http://alpha.example/hook",
		"ftp://alpha.example/hook",
		"not a url",
	] {
		let message = refusal(&tenant("alpha", "a.example", &hook(url, &fresh_secret())));
		assert!(message.contains("[tenant.webhook]"), "{url}: {message}");
		assert!(message.contains("alpha"), "{url}: {message}");
		assert!(message.contains("must be https"), "{url}: {message}");
	}
	// A loopback endpoint may be plain http, as for the server-wide one.
	load(&tenant(
		"alpha",
		"a.example",
		&hook("http://127.0.0.1:9000/hook", &fresh_secret()),
	))
	.expect("loopback http");
}

#[test]
fn two_webhooks_may_not_sign_with_one_secret() {
	let shared = fresh_secret();
	let message = refusal(&format!(
		"{}{}",
		tenant(
			"alpha",
			"a.example",
			&hook("https://alpha.example/hook", &shared)
		),
		tenant(
			"beta",
			"b.example",
			&hook("https://beta.example/hook", &shared)
		),
	));
	assert!(message.contains("tenant \"beta\""), "{message}");
	assert!(message.contains("tenant \"alpha\""), "{message}");
	assert!(message.contains("secret of its own"), "{message}");
}

#[test]
fn a_tenant_may_not_sign_with_the_servers_secret() {
	let shared = fresh_secret();
	let message = refusal(&format!(
		"[webhook]\nurl = \"https://ops.example/hook\"\nsecret = \"{shared}\"\n{}",
		tenant(
			"alpha",
			"a.example",
			&hook("https://alpha.example/hook", &shared)
		),
	));
	assert!(message.contains("server-wide [webhook]"), "{message}");
}

#[test]
fn a_tenant_webhook_with_no_domains_receives_nothing_and_is_refused() {
	let message = refusal(&format!(
		"[[tenant]]\nname = \"alpha\"\n{}",
		hook("https://alpha.example/hook", &fresh_secret())
	));
	assert!(message.contains("lists no domains"), "{message}");
}

#[test]
fn unknown_keys_in_a_tenant_webhook_are_refused() {
	let message = refusal(&tenant(
		"alpha",
		"a.example",
		"[tenant.webhook]\nurl = \"https://alpha.example/hook\"\ntoken = \"x\"\n",
	));
	assert!(message.contains("token"), "{message}");
}

#[test]
fn an_alert_still_needs_the_servers_own_webhook() {
	let message = refusal(&format!(
		"[[alerts]]\nname = \"storm\"\nmetric = \"bounced\"\nop = \">\"\nthreshold = 1\n\
		 window_secs = 60\ncooldown_secs = 60\nwebhook = true\n{}",
		tenant(
			"alpha",
			"a.example",
			&hook("https://alpha.example/hook", &fresh_secret())
		),
	));
	assert!(message.contains("no [webhook] section"), "{message}");
}
