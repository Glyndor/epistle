//! `dns-records` per-domain: a domain with `[[dkim.domain]]` publishes its
//! override's key only, every other hosted domain keeps the default.

use super::*;

/// The `p=` value of a DKIM TXT record.
fn public(record: &str) -> &str {
	record
		.split(';')
		.find_map(|tag| tag.trim().strip_prefix("p="))
		.expect("a p= tag")
}

#[test]
fn an_override_publishes_its_own_key_even_under_the_default_selector_name() {
	let dir = tempfile::tempdir().expect("dir");
	let (default_pem, default_txt) = crate::dkim::generate_key().expect("default key");
	let (override_pem, override_txt) = crate::dkim::generate_key().expect("override key");
	std::fs::write(dir.path().join("default.key"), default_pem).expect("write default");
	std::fs::write(dir.path().join("override.key"), override_pem).expect("write override");
	let config: Config = toml::from_str(&format!(
		"hostname = 'mail.example.org'\ndata_dir = {:?}\ndomains = ['example.org', 'example.net']\n\
		 [dkim]\nselector = 'mail'\nkey_file = {:?}\n\
		 [[dkim.domain]]\nname = 'Example.ORG'\nselector = 'mail'\nkey_file = {:?}\n",
		dir.path(),
		dir.path().join("default.key"),
		dir.path().join("override.key"),
	))
	.expect("config");
	let mut out = Vec::new();
	assert_eq!(run(&config, false, &mut out), ExitCode::SUCCESS);
	let text = String::from_utf8(out).expect("utf-8");
	let record = |name: &str| -> Vec<&str> {
		text.lines()
			.filter(|line| line.starts_with(&format!("{name} ")))
			.collect()
	};
	let org = record("mail._domainkey.example.org");
	let net = record("mail._domainkey.example.net");
	assert_eq!(org.len(), 1, "one DKIM record for example.org");
	assert_eq!(net.len(), 1, "one DKIM record for example.net");
	assert!(
		org[0].contains(public(&override_txt)) && !org[0].contains(public(&default_txt)),
		"example.org publishes its override's key, not the default's"
	);
	assert!(
		net[0].contains(public(&default_txt)) && !net[0].contains(public(&override_txt)),
		"example.net publishes the default's key"
	);
}
