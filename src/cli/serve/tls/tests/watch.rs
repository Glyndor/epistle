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
