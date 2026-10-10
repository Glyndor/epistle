//! Tests for the DNS provider build arms and the `SUPPORTED_PROVIDERS` list
//! invariant. Sibling to `dns.rs` to keep that file under the per-file code
//! line limit; the entry point is `Dns::build` in `dns.rs`.

use super::*;

#[test]
fn porkbun_with_keys_builds() {
	let dns: Dns = toml::from_str(
		"provider = \"porkbun\"\nzone = \"example.org\"\naccess_key = \"pk1\"\nsecret_key = \"sk1\"",
	)
	.unwrap();
	assert!(dns.build().is_some());
}

#[test]
fn porkbun_without_access_key_builds_nothing() {
	let dns: Dns =
		toml::from_str("provider = \"porkbun\"\nzone = \"example.org\"\nsecret_key = \"sk1\"")
			.unwrap();
	assert!(dns.build().is_none());
}

#[test]
fn porkbun_without_secret_key_builds_nothing() {
	let dns: Dns =
		toml::from_str("provider = \"porkbun\"\nzone = \"example.org\"\naccess_key = \"pk1\"")
			.unwrap();
	assert!(dns.build().is_none());
}

#[test]
fn digitalocean_with_token_builds() {
	let dns: Dns =
		toml::from_str("provider = \"digitalocean\"\nzone = \"example.org\"\ntoken = \"dop_v1\"")
			.unwrap();
	assert!(dns.build().is_some());
}

#[test]
fn digitalocean_without_token_builds_nothing() {
	let dns: Dns = toml::from_str("provider = \"digitalocean\"\nzone = \"example.org\"").unwrap();
	assert!(dns.build().is_none());
}

#[test]
fn rfc2136_with_endpoint_and_key_name_builds() {
	// 32 bytes of base64, the `key` parameter of `rfc2136::decode_key`.
	let dns: Dns = toml::from_str(
		"provider = \"rfc2136\"\nzone = \"example.org\"\n\
		 token = \"c3VwZXJzZWNyZXQta2V5LW1hdGVyaWFsLWZvci10ZXN0cw==\"\n\
		 key_name = \"epistle-key.\"\n\
		 endpoint = \"127.0.0.1:5359\"",
	)
	.unwrap();
	assert!(dns.build().is_some());
}

#[test]
fn rfc2136_without_endpoint_builds_nothing() {
	let dns: Dns = toml::from_str(
		"provider = \"rfc2136\"\nzone = \"example.org\"\n\
		 token = \"c3VwZXJzZWNyZXQta2V5LW1hdGVyaWFsLWZvci10ZXN0cw==\"\n\
		 key_name = \"epistle-key.\"",
	)
	.unwrap();
	assert!(dns.build().is_none());
}

#[test]
fn rfc2136_without_key_name_builds_nothing() {
	let dns: Dns = toml::from_str(
		"provider = \"rfc2136\"\nzone = \"example.org\"\n\
		 token = \"c3VwZXJzZWNyZXQta2V5LW1hdGVyaWFsLWZvci10ZXN0cw==\"\n\
		 endpoint = \"127.0.0.1:5359\"",
	)
	.unwrap();
	assert!(dns.build().is_none());
}

#[test]
fn rfc2136_with_invalid_base64_key_builds_nothing() {
	// The TSIG key is base64-decoded at build time; a non-base64 value
	// must keep the build at None (fail closed) rather than panic.
	let dns: Dns = toml::from_str(
		"provider = \"rfc2136\"\nzone = \"example.org\"\n\
		 token = \"not-valid-base64!!!\"\n\
		 key_name = \"epistle-key.\"\n\
		 endpoint = \"127.0.0.1:5359\"",
	)
	.unwrap();
	assert!(dns.build().is_none());
}

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

/// Every name in `SUPPORTED_PROVIDERS` (other than the always-noop
/// `manual`) must build a provider when its required credentials are
/// present, and a name outside the list must not. The test pins the
/// invariant in both directions:
///
/// 1. Every fixture key is in `SUPPORTED_PROVIDERS`, and every
///    non-`manual` name in `SUPPORTED_PROVIDERS` has a fixture.
///    Without the reverse check, a name in the fixture table that
///    was removed from the list would never be exercised; the test
///    would stay green while the operator-facing list and the
///    build path drift.
/// 2. Every `match` arm in `Dns::build` is in
///    `SUPPORTED_PROVIDERS`. A new arm added without a list entry
///    would let the operator reach it through the build but not
///    through the loader or the answers validator, the gap the
///    second check is closing.
///
/// Changing either list without the other fails the test.
#[test]
fn provider_list_matches_build() {
	// The full-credential TOML for each provider, keyed by the
	// provider name. Every field the corresponding `match` arm reads
	// is set; missing required fields would make the test green for
	// the wrong reason (the build would still return None).
	let fixtures: &[(&str, &str)] = &[
		("bunny", r#"token = "bunny-key""#),
		("cloudflare", r#"token = "cf-token""#),
		("desec", r#"token = "desec-token""#),
		("digitalocean", r#"token = "do-token""#),
		(
			"dnsimple",
			r#"token = "dns-token"
account_id = "1010""#,
		),
		// gcloud needs a real credentials file on disk; the entry
		// below points the test at a temp file the loop writes
		// before iterating the list.
		(
			"gcloud",
			r#"token = "x"
credentials_file = "__GCLOUD_PATH__""#,
		),
		(
			"godaddy",
			r#"access_key = "gd-key"
secret_key = "gd-secret""#,
		),
		("namecheap", r#"token = "user:key""#),
		(
			"ovh",
			r#"access_key = "ak"
secret_key = "sk"
consumer_key = "ck"
endpoint = "ovh-eu""#,
		),
		(
			"porkbun",
			r#"access_key = "pk"
secret_key = "sk""#,
		),
		(
			"route53",
			r#"access_key = "ak"
secret_key = "sk"
hosted_zone_id = "Z1""#,
		),
		(
			"rfc2136",
			r#"token = "c3VwZXJzZWNyZXQta2V5LW1hdGVyaWFsLWZvci10ZXN0cw=="
key_name = "epistle-key."
endpoint = "127.0.0.1:5359""#,
		),
		(
			"spaceship",
			r#"access_key = "ak"
secret_key = "sk""#,
		),
	];
	let fixture_map: std::collections::HashMap<&str, &str> = fixtures.iter().copied().collect();

	// gcloud is the only provider whose fixture references a file
	// on disk. Write the file once so the loop can run over the list
	// without conditional branches for gcloud alone.
	let gcloud_path =
		std::env::temp_dir().join(format!("epistle-list-matches-{}.json", std::process::id()));
	std::fs::write(
		&gcloud_path,
		br#"{"client_email":"sa@p.iam.gserviceaccount.com","private_key":"-----BEGIN PRIVATE KEY-----\nMIIE...fake...\n-----END PRIVATE KEY-----","project_id":"p"}"#,
	)
	.unwrap();
	let gcloud_path_str = gcloud_path.display().to_string();

	// Direction 1: every fixture key is in SUPPORTED_PROVIDERS, and
	// every non-`manual` name in SUPPORTED_PROVIDERS has a fixture.
	for key in fixture_map.keys() {
		assert!(
			is_supported_provider(key),
			"fixture key {key:?} is not in SUPPORTED_PROVIDERS; \
			 a name the test exercises but the operator-facing list \
			 does not advertise would let a build succeed where the \
			 loader / answers validator would reject it"
		);
	}
	for name in SUPPORTED_PROVIDERS {
		if *name == "manual" {
			continue;
		}
		assert!(
			fixture_map.contains_key(name),
			"provider {name:?} is in SUPPORTED_PROVIDERS but the test has no \
			 full-credentials fixture for it; add one to provider_list_matches_build \
			 so the build path is exercised"
		);
	}

	// Direction 2: every build arm is in SUPPORTED_PROVIDERS.
	for arm in BUILD_ARM_NAMES {
		assert!(
			is_supported_provider(arm),
			"build arm {arm:?} is not in SUPPORTED_PROVIDERS; \
			 a name the build accepts but the operator-facing list \
			 does not advertise would let the operator reach the \
			 arm through a build but not through the loader or the \
			 answers validator"
		);
	}

	for name in SUPPORTED_PROVIDERS {
		if *name == "manual" {
			// The always-noop entry: it is in the list and validates,
			// but `build` returns None by design.
			let manual: Dns =
				toml::from_str("provider = \"manual\"\nzone = \"example.org\"").unwrap();
			assert!(
				manual.build().is_none(),
				"`manual` is the noop entry; build must return None"
			);
			continue;
		}
		let fixture = fixture_map.get(name).unwrap_or_else(|| {
			panic!(
				"provider {name:?} is in SUPPORTED_PROVIDERS but the test has no full-credentials \
				 fixture for it; add one to provider_list_matches_build so the build path is exercised"
			)
		});
		let fixture = fixture.replace("__GCLOUD_PATH__", &gcloud_path_str);
		let toml = format!("provider = {name:?}\nzone = \"example.org\"\n{fixture}");
		let dns: Dns =
			toml::from_str(&toml).unwrap_or_else(|e| panic!("parse {name}: {e}\n---\n{toml}\n---"));
		assert!(
			dns.build().is_some(),
			"provider {name} is in SUPPORTED_PROVIDERS but builds None with full credentials"
		);
	}

	// A name outside the list never builds.
	let bogus: Dns =
		toml::from_str("provider = \"cloudfare\"\nzone = \"example.org\"\ntoken = \"x\"").unwrap();
	assert!(bogus.build().is_none());

	let _ = std::fs::remove_file(&gcloud_path);
}

/// `Dns::build` lowercases the provider name on entry so `Cloudflare`
/// and `CLOUDFLARE` reach the same arm as `cloudflare`. The
/// validation paths also compare case-insensitively (see
/// `is_supported_provider`); this test pins the build half of that
/// contract so a future lowercasing change surfaces here.
#[test]
fn provider_name_is_matched_case_insensitively() {
	let dns: Dns =
		toml::from_str("provider = \"Cloudflare\"\nzone = \"example.org\"\ntoken = \"t\"").unwrap();
	assert!(dns.build().is_some());
	assert!(is_supported_provider("Cloudflare"));
	assert!(is_supported_provider("CLOUDFLARE"));
	assert!(!is_supported_provider("cloudfare"));
}
