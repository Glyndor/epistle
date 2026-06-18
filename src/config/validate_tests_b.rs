//! Configuration validation tests: secret, ACME, alias and listener errors.

use super::*;

fn invalid(toml: &str) -> bool {
	let parsed: Result<Config, _> = toml::from_str(toml);
	match parsed {
		Ok(config) => config.validate().is_err(),
		Err(_) => true,
	}
}

const BASE: &str =
	"hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\ndomains = [\"example.org\"]\n";

#[test]
fn rejects_non_argon2id_secrets() {
	// [api] token_hash must be argon2id.
	assert!(invalid(&format!(
		"{BASE}\n[api]\ntoken_hash = \"sha256:deadbeef\"\n"
	)));
	// account password_hash must be argon2id.
	assert!(invalid(&format!(
		"{BASE}\n[[accounts]]\nname = \"alice\"\naddresses = [\"alice@example.org\"]\npassword_hash = \"plaintext\"\n"
	)));
}

#[test]
fn rejects_bad_acme_sections() {
	// Non-https directory URL.
	assert!(invalid(&format!(
		"{BASE}\n[acme]\ndirectory_url = \"http://acme.example/dir\"\ndomains = [\"example.org\"]\n"
	)));
	// No domains.
	assert!(invalid(&format!(
		"{BASE}\n[acme]\ndirectory_url = \"https://acme.example/dir\"\ndomains = []\n"
	)));
	// Domain not configured.
	assert!(invalid(&format!(
		"{BASE}\n[acme]\ndirectory_url = \"https://acme.example/dir\"\ndomains = [\"other.example\"]\n"
	)));
}

#[test]
fn rejects_bad_domain_aliases() {
	// Alias targets an unconfigured domain.
	assert!(invalid(&format!(
		"{BASE}\n[domain_aliases]\n\"alias.example\" = \"missing.example\"\n"
	)));
	// Alias that equals its target.
	assert!(invalid(&format!(
		"{BASE}\n[domain_aliases]\n\"example.org\" = \"example.org\"\n"
	)));
}

#[test]
fn rejects_listeners_missing_required_sections() {
	// submissions (implicit TLS) without [tls].
	assert!(invalid(&format!(
		"{BASE}\n[[listeners]]\nkind = \"submissions\"\n"
	)));
	// imaps without [tls].
	assert!(invalid(&format!(
		"{BASE}\n[[listeners]]\nkind = \"imaps\"\n"
	)));
	// api listener without [api].
	assert!(invalid(&format!("{BASE}\n[[listeners]]\nkind = \"api\"\n")));
}

#[test]
fn webhook_url_must_be_https_or_loopback() {
	use super::*;
	fn ok(toml: &str) -> bool {
		toml::from_str::<Config>(toml).is_ok_and(|c| c.validate().is_ok())
	}
	// Plaintext http to a remote host is rejected (leaks metadata).
	assert!(invalid(&format!(
		"{BASE}\n[webhook]\nurl = \"http://hooks.example/x\"\n"
	)));
	// https is accepted.
	assert!(ok(&format!(
		"{BASE}\n[webhook]\nurl = \"https://hooks.example/x\"\n"
	)));
	// Loopback http is allowed (never leaves the host).
	assert!(ok(&format!(
		"{BASE}\n[webhook]\nurl = \"http://127.0.0.1:9000/x\"\n"
	)));
	assert!(ok(&format!(
		"{BASE}\n[webhook]\nurl = \"http://localhost/x\"\n"
	)));
}
