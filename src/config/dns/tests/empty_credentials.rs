//! Providers that must build nothing when a credential, key or endpoint is empty or unsafe.

use super::*;

#[test]
fn godaddy_with_empty_access_key_builds_nothing() {
	// `access_key = ""` is a TOML placeholder while authoring; the
	// build must not turn it into a working provider that would then
	// send `sso-key :` on every call. The missing-field test only
	// exercises the `None` case, so this pins the empty-string case
	// explicitly.
	let dns: Dns = toml::from_str(
		"provider = \"godaddy\"\nzone = \"example.org\"\naccess_key = \"\"\nsecret_key = \"sk\"",
	)
	.unwrap();
	assert!(dns.build().is_none());
}

#[test]
fn godaddy_with_whitespace_access_key_builds_nothing() {
	let dns: Dns = toml::from_str(
		"provider = \"godaddy\"\nzone = \"example.org\"\naccess_key = \"   \"\nsecret_key = \"sk\"",
	)
	.unwrap();
	assert!(dns.build().is_none());
}

#[test]
fn godaddy_with_empty_secret_key_builds_nothing() {
	let dns: Dns = toml::from_str(
		"provider = \"godaddy\"\nzone = \"example.org\"\naccess_key = \"ak\"\nsecret_key = \"\"",
	)
	.unwrap();
	assert!(dns.build().is_none());
}

#[test]
fn porkbun_with_empty_access_key_builds_nothing() {
	let dns: Dns = toml::from_str(
		"provider = \"porkbun\"\nzone = \"example.org\"\naccess_key = \"\"\nsecret_key = \"sk1\"",
	)
	.unwrap();
	assert!(dns.build().is_none());
}

#[test]
fn porkbun_with_empty_secret_key_builds_nothing() {
	let dns: Dns = toml::from_str(
		"provider = \"porkbun\"\nzone = \"example.org\"\naccess_key = \"pk1\"\nsecret_key = \"\"",
	)
	.unwrap();
	assert!(dns.build().is_none());
}

#[test]
fn digitalocean_with_empty_token_builds_nothing() {
	let dns: Dns =
		toml::from_str("provider = \"digitalocean\"\nzone = \"example.org\"\ntoken = \"\"")
			.unwrap();
	assert!(dns.build().is_none());
}

#[test]
fn digitalocean_with_whitespace_token_builds_nothing() {
	let dns: Dns =
		toml::from_str("provider = \"digitalocean\"\nzone = \"example.org\"\ntoken = \"   \"")
			.unwrap();
	assert!(dns.build().is_none());
}

#[test]
fn ovh_with_empty_access_key_builds_nothing() {
	let dns: Dns = toml::from_str(
		"provider = \"ovh\"\nzone = \"example.org\"\n\
		 access_key = \"\"\nsecret_key = \"sk\"\nconsumer_key = \"ck\"\nendpoint = \"ovh-eu\"",
	)
	.unwrap();
	assert!(dns.build().is_none());
}

#[test]
fn ovh_with_empty_consumer_key_builds_nothing() {
	let dns: Dns = toml::from_str(
		"provider = \"ovh\"\nzone = \"example.org\"\n\
		 access_key = \"ak\"\nsecret_key = \"sk\"\nconsumer_key = \"\"\nendpoint = \"ovh-eu\"",
	)
	.unwrap();
	assert!(dns.build().is_none());
}

#[test]
fn ovh_with_a_cleartext_endpoint_builds_nothing() {
	let toml = |endpoint: &str| {
		format!(
			"provider = \"ovh\"\nzone = \"example.org\"\n\
			 access_key = \"ak\"\nsecret_key = \"sk\"\nconsumer_key = \"ck\"\n\
			 endpoint = \"{endpoint}\""
		)
	};
	let cleartext: Dns = toml::from_str(&toml("http://ovh.example.net/1.0")).unwrap();
	assert!(cleartext.build().is_none());
	let https: Dns = toml::from_str(&toml("https://ovh.example.net/1.0")).unwrap();
	assert!(https.build().is_some());
}

#[test]
fn route53_with_empty_access_key_builds_nothing() {
	let dns: Dns = toml::from_str(
		"provider = \"route53\"\nzone = \"example.org\"\n\
		 access_key = \"\"\nsecret_key = \"sk\"\nhosted_zone_id = \"Z1\"",
	)
	.unwrap();
	assert!(dns.build().is_none());
}

#[test]
fn route53_with_empty_hosted_zone_id_builds_nothing() {
	let dns: Dns = toml::from_str(
		"provider = \"route53\"\nzone = \"example.org\"\n\
		 access_key = \"ak\"\nsecret_key = \"sk\"\nhosted_zone_id = \"\"",
	)
	.unwrap();
	assert!(dns.build().is_none());
}

#[test]
fn spaceship_with_empty_access_key_builds_nothing() {
	let dns: Dns = toml::from_str(
		"provider = \"spaceship\"\nzone = \"example.org\"\naccess_key = \"\"\nsecret_key = \"SK\"",
	)
	.unwrap();
	assert!(dns.build().is_none());
}

#[test]
fn gcloud_with_empty_credentials_file_builds_nothing() {
	let dns: Dns =
		toml::from_str("provider = \"gcloud\"\nzone = \"example.org\"\ntoken = \"x\"").unwrap();
	assert!(dns.build().is_none());
}

/// An empty `private_key` in the Google service-account JSON would
/// pass `serde_json` and build a provider that later fails at JWT
/// signing time, on the first write. The build must reject it
/// up front so the operator sees a missing-credential verdict
/// (the next `build()` returns `None`) rather than a runtime
/// error from the live API.
#[test]
fn gcloud_with_empty_private_key_in_credentials_file_builds_nothing() {
	let path = std::env::temp_dir().join(format!(
		"epistle-gcloud-empty-pk-{}.json",
		std::process::id()
	));
	std::fs::write(
		&path,
		br#"{"client_email":"sa@p.iam.gserviceaccount.com","private_key":"","project_id":"p"}"#,
	)
	.unwrap();
	let toml = format!(
		"provider = \"gcloud\"\nzone = \"example.org\"\ntoken = \"x\"\ncredentials_file = \"{}\"",
		path.display()
	);
	let dns: Dns = toml::from_str(&toml).unwrap();
	assert!(dns.build().is_none());
	let _ = std::fs::remove_file(&path);
}

/// A whitespace-only `private_key` is treated the same as an
/// empty one: the build refuses to construct a provider that
/// would later fail at JWT signing time.
#[test]
fn gcloud_with_whitespace_only_private_key_in_credentials_file_builds_nothing() {
	let path = std::env::temp_dir().join(format!(
		"epistle-gcloud-whitespace-pk-{}.json",
		std::process::id()
	));
	std::fs::write(
		&path,
		br#"{"client_email":"sa@p.iam.gserviceaccount.com","private_key":"   \n","project_id":"p"}"#,
	)
	.unwrap();
	let toml = format!(
		"provider = \"gcloud\"\nzone = \"example.org\"\ntoken = \"x\"\ncredentials_file = \"{}\"",
		path.display()
	);
	let dns: Dns = toml::from_str(&toml).unwrap();
	assert!(dns.build().is_none());
	let _ = std::fs::remove_file(&path);
}

#[test]
fn rfc2136_with_empty_endpoint_builds_nothing() {
	// `127.0.0.1:0` is a degenerate endpoint that would not dial
	// anywhere. The build rejects an empty endpoint string before
	// even constructing the signer; the value here is a TOML
	// placeholder the operator typed while authoring.
	let dns: Dns = toml::from_str(
		"provider = \"rfc2136\"\nzone = \"example.org\"\n\
		 token = \"c3VwZXJzZWNyZXQta2V5LW1hdGVyaWFsLWZvci10ZXN0cw==\"\n\
		 key_name = \"epistle-key.\"\n\
		 endpoint = \"\"",
	)
	.unwrap();
	assert!(dns.build().is_none());
}

#[test]
fn rfc2136_with_empty_key_name_builds_nothing() {
	let dns: Dns = toml::from_str(
		"provider = \"rfc2136\"\nzone = \"example.org\"\n\
		 token = \"c3VwZXJzZWNyZXQta2V5LW1hdGVyaWFsLWZvci10ZXN0cw==\"\n\
		 key_name = \"\"\n\
		 endpoint = \"127.0.0.1:5359\"",
	)
	.unwrap();
	assert!(dns.build().is_none());
}
