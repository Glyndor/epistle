//! The certificate files are watched only when nothing else manages them.

use super::*;

fn config(tls: bool, acme: bool) -> Config {
	let mut text = "hostname = 'mail.example.org'\ndata_dir = '.'\n".to_string();
	if tls {
		text.push_str("[tls]\ncert_file = '/etc/mail/cert.pem'\nkey_file = '/etc/mail/key.pem'\n");
	}
	if acme {
		text.push_str(
			"[acme]\ndirectory_url = 'https://acme.invalid/dir'\ndomains = ['mail.example.org']\n",
		);
	}
	toml::from_str(&text).expect("config")
}

#[test]
fn only_a_static_pair_is_watched() {
	assert!(
		watches_files(&config(true, false)),
		"the operator's own pair"
	);
	assert!(
		!watches_files(&config(true, true)),
		"ACME renews and reloads its own pair"
	);
	assert!(!watches_files(&config(false, false)), "no [tls] at all");
}

/// The listeners of a split stack reload the pair the certificates container
/// writes; every other process either renews it or watches a static pair.
#[test]
fn only_the_mail_role_follows_the_acme_files() {
	use crate::cli::serve::ServeRole;
	assert!(follows_acme_files(&config(true, true), ServeRole::Mail));
	assert!(!follows_acme_files(&config(true, true), ServeRole::All));
	assert!(!follows_acme_files(&config(true, true), ServeRole::Certs));
	assert!(
		!follows_acme_files(&config(true, false), ServeRole::Mail),
		"no [acme]: the static pair is watched as before"
	);
}

#[test]
fn the_roles_that_hold_the_dns_credential() {
	use crate::cli::serve::ServeRole;
	assert!(ServeRole::All.writes_dns() && ServeRole::All.renews_certificates());
	assert!(ServeRole::Certs.writes_dns() && ServeRole::Certs.renews_certificates());
	assert!(!ServeRole::Mail.writes_dns() && !ServeRole::Mail.renews_certificates());
	assert_eq!(
		[ServeRole::All, ServeRole::Mail, ServeRole::Certs].map(ServeRole::as_str),
		["all", "mail", "certs"]
	);
}
