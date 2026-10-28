//! `[acme] challenge` parsing and the combinations validation refuses.

use crate::config::{AcmeChallenge, Config};

const BASE: &str =
	"hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\ndomains = [\"example.org\"]\n";

/// A `[tls]` section so implicit-TLS listeners pass their own check.
const TLS: &str =
	"[tls]\ncert_file = \"/etc/epistle/cert.pem\"\nkey_file = \"/etc/epistle/key.pem\"\n";

fn acme(challenge: &str) -> String {
	format!(
		"[acme]\ndirectory_url = \"https://acme.example/dir\"\ndomains = [\"mail.example.org\"]\nchallenge = \"{challenge}\"\n"
	)
}

fn validation_error(toml: &str) -> Option<String> {
	let config: Config = toml::from_str(toml).expect("parses");
	config.validate().err().map(|error| error.to_string())
}

#[test]
fn challenge_defaults_to_http01() {
	let config: Config = toml::from_str(&format!(
		"{BASE}[acme]\ndirectory_url = \"https://acme.example/dir\"\ndomains = [\"mail.example.org\"]\n"
	))
	.expect("parses");
	assert_eq!(config.acme.expect("acme").challenge, AcmeChallenge::Http01);
}

#[test]
fn unknown_challenge_is_a_parse_error() {
	let parsed: Result<Config, _> = toml::from_str(&format!("{BASE}{}", acme("dns-02")));
	assert!(parsed.is_err(), "dns-02 must not parse");
}

#[test]
fn dns01_without_dns_section_is_refused() {
	assert_eq!(
		validation_error(&format!("{BASE}{}", acme("dns-01"))).as_deref(),
		Some(
			"invalid configuration: [acme] challenge = \"dns-01\" needs a [dns] provider that can publish records (any provider other than \"manual\")"
		)
	);
}

#[test]
fn dns01_with_manual_dns_is_refused() {
	let toml = format!(
		"{BASE}{}[dns]\nprovider = \"manual\"\nzone = \"example.org\"\n",
		acme("dns-01")
	);
	assert_eq!(
		validation_error(&toml).as_deref(),
		Some(
			"invalid configuration: [acme] challenge = \"dns-01\" needs a [dns] provider that can publish records (any provider other than \"manual\")"
		)
	);
}

#[test]
fn dns01_with_a_publishing_provider_is_accepted() {
	let toml = format!(
		"{BASE}{}[dns]\nprovider = \"cloudflare\"\nzone = \"example.org\"\ntoken_env = \"CF_TOKEN\"\n",
		acme("dns-01")
	);
	assert_eq!(validation_error(&toml), None);
}

#[test]
fn tls_alpn01_without_a_tls_listener_on_443_is_refused() {
	let expected = "invalid configuration: [acme] challenge = \"tls-alpn-01\" needs a listener that terminates TLS on port 443 (kind submissions, imaps or pop3s with port = 443)";
	assert_eq!(
		validation_error(&format!("{BASE}{}", acme("tls-alpn-01"))).as_deref(),
		Some(expected)
	);
	// Port 443 on a listener that does not terminate TLS itself does not count.
	let plaintext = format!(
		"{BASE}[[listeners]]\nkind = \"submission\"\nport = 443\n{}",
		acme("tls-alpn-01")
	);
	assert_eq!(validation_error(&plaintext).as_deref(), Some(expected));
	// A TLS listener on its own port does not count either.
	let elsewhere = format!(
		"{BASE}{TLS}[[listeners]]\nkind = \"imaps\"\n{}",
		acme("tls-alpn-01")
	);
	assert_eq!(validation_error(&elsewhere).as_deref(), Some(expected));
}

#[test]
fn tls_alpn01_with_an_implicit_tls_listener_on_443_is_accepted() {
	let toml = format!(
		"{BASE}{TLS}[[listeners]]\nkind = \"submissions\"\nport = 443\n{}",
		acme("tls-alpn-01")
	);
	assert_eq!(validation_error(&toml), None);
}
