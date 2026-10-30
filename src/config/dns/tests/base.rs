use super::*;

fn cfg(extra: &str) -> Dns {
	toml::from_str(&format!(
		"provider = \"cloudflare\"\nzone = \"example.org\"\n{extra}"
	))
	.expect("parse")
}

#[test]
fn manual_provider_builds_nothing() {
	let dns: Dns = toml::from_str("provider = \"manual\"\nzone = \"example.org\"").unwrap();
	assert!(dns.build().is_none());
}

#[test]
fn cloudflare_with_inline_token_builds() {
	let dns = cfg("token = \"abc\"");
	assert!(dns.build().is_some());
}

#[test]
fn cloudflare_without_token_builds_nothing() {
	let dns = cfg("");
	assert!(dns.build().is_none());
}

#[test]
fn debug_redacts_every_credential_field() {
	// Every field that carries a secret must show `***` in the
	// Debug output, not the secret itself. The original test
	// checked only `token`, so a regression that re-introduced a
	// plaintext `access_key` (the value GoDaddy and Porkbun store
	// there) would still pass. The list below matches the
	// credential fields on the struct.
	let cases: &[(&str, &str)] = &[
		("token", "token = \"super-secret-token\""),
		(
			"access_key",
			"access_key = \"AKIA-super-secret-access-key\"",
		),
		("secret_key", "secret_key = \"super-secret-key\""),
	];
	for (field, extra) in cases {
		let dns = cfg(extra);
		let rendered = format!("{dns:?}");
		assert!(
			rendered.contains("***"),
			"redaction marker missing for {field}: {rendered}"
		);
		let secret = match *field {
			"token" => "super-secret-token",
			"access_key" => "AKIA-super-secret-access-key",
			"secret_key" => "super-secret-key",
			_ => unreachable!(),
		};
		assert!(
			!rendered.contains(secret),
			"credential {field} leaked through Debug: {rendered}"
		);
	}
}

#[test]
fn desec_with_token_builds() {
	let dns: Dns =
		toml::from_str("provider = \"desec\"\nzone = \"example.org\"\ntoken = \"t\"").unwrap();
	assert!(dns.build().is_some());
}

#[test]
fn route53_with_credentials_builds() {
	let dns: Dns = toml::from_str(
			"provider = \"route53\"\nzone = \"example.org\"\naccess_key = \"AKIA\"\nsecret_key = \"s\"\nhosted_zone_id = \"Z1\"",
		)
		.unwrap();
	assert!(dns.build().is_some());
}

#[test]
fn route53_without_zone_id_builds_nothing() {
	let dns: Dns = toml::from_str(
		"provider = \"route53\"\nzone = \"example.org\"\naccess_key = \"AKIA\"\nsecret_key = \"s\"",
	)
	.unwrap();
	assert!(dns.build().is_none());
}

#[test]
fn env_token_takes_effect() {
	unsafe { std::env::set_var("EPISTLE_TEST_DNS_PROVIDER_TOKEN", "tok") };
	let dns = cfg("token_env = \"EPISTLE_TEST_DNS_PROVIDER_TOKEN\"");
	assert!(dns.build().is_some());
}

#[test]
fn namecheap_with_inline_token_builds() {
	let dns: Dns = toml::from_str(
			"provider = \"namecheap\"\nzone = \"example.org\"\ntoken = \"user:key\"\nclient_ip = \"192.0.2.10\"",
		)
		.unwrap();
	assert!(dns.build().is_some());
}

/// Namecheap documents `ClientIp` as required, and IPv4 only.
#[test]
fn namecheap_without_an_ipv4_client_ip_builds_nothing() {
	for extra in ["", "\nclient_ip = \"2001:db8::1\"", "\nclient_ip = \"\""] {
		let dns: Dns = toml::from_str(&format!(
			"provider = \"namecheap\"\nzone = \"example.org\"\ntoken = \"user:key\"{extra}"
		))
		.unwrap();
		assert!(dns.build().is_none(), "{extra}");
	}
}

#[test]
fn namecheap_without_token_builds_nothing() {
	let dns: Dns = toml::from_str("provider = \"namecheap\"\nzone = \"example.org\"").unwrap();
	assert!(dns.build().is_none());
}

#[test]
fn namecheap_malformed_token_builds_nothing() {
	let dns: Dns =
		toml::from_str("provider = \"namecheap\"\nzone = \"example.org\"\ntoken = \"nocolon\"")
			.unwrap();
	assert!(dns.build().is_none());
}

#[test]
fn gcloud_with_credentials_file_builds() {
	let path =
		std::env::temp_dir().join(format!("epistle-gcloud-test-{}.json", std::process::id()));
	std::fs::write(
			&path,
			br#"{"client_email":"sa@p.iam.gserviceaccount.com","private_key":"-----BEGIN PRIVATE KEY-----\nMIIE...fake...\n-----END PRIVATE KEY-----","project_id":"p"}"#,
		)
		.unwrap();
	let toml = format!(
		"provider = \"gcloud\"\nzone = \"example.org\"\ntoken = \"x\"\ncredentials_file = \"{}\"",
		path.display()
	);
	let dns: Dns = toml::from_str(&toml).unwrap();
	assert!(dns.build().is_some());
	let _ = std::fs::remove_file(&path);
}

#[test]
fn gcloud_without_credentials_file_builds_nothing() {
	let dns: Dns =
		toml::from_str("provider = \"gcloud\"\nzone = \"example.org\"\ntoken = \"x\"").unwrap();
	assert!(dns.build().is_none());
}

#[test]
fn dnsimple_with_token_and_account_id_builds() {
	let dns: Dns = toml::from_str(
		"provider = \"dnsimple\"\nzone = \"example.org\"\ntoken = \"t\"\naccount_id = \"1010\"",
	)
	.unwrap();
	assert!(dns.build().is_some());
}
#[test]
fn dnsimple_without_account_id_builds_nothing() {
	let dns: Dns =
		toml::from_str("provider = \"dnsimple\"\nzone = \"example.org\"\ntoken = \"t\"").unwrap();
	assert!(dns.build().is_none());
}
#[test]
fn dnsimple_without_token_builds_nothing() {
	let dns: Dns =
		toml::from_str("provider = \"dnsimple\"\nzone = \"example.org\"\naccount_id = \"1010\"")
			.unwrap();
	assert!(dns.build().is_none());
}

#[test]
fn spaceship_with_keys_builds() {
	let dns: Dns = toml::from_str(
		"provider = \"spaceship\"\nzone = \"example.org\"\naccess_key = \"AK\"\nsecret_key = \"SK\"",
	)
	.unwrap();
	assert!(dns.build().is_some());
}
#[test]
fn spaceship_without_access_key_builds_nothing() {
	let dns: Dns =
		toml::from_str("provider = \"spaceship\"\nzone = \"example.org\"\nsecret_key = \"SK\"")
			.unwrap();
	assert!(dns.build().is_none());
}
#[test]
fn spaceship_without_secret_key_builds_nothing() {
	let dns: Dns =
		toml::from_str("provider = \"spaceship\"\nzone = \"example.org\"\naccess_key = \"AK\"")
			.unwrap();
	assert!(dns.build().is_none());
}
