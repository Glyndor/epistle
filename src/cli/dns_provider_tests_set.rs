use super::tests::{DNS, run};
use super::*;
use crate::config::{Dns, SUPPORTED_PROVIDERS};

#[test]
fn set_writes_a_new_section_with_only_the_needed_keys() {
	let run = run(
		"",
		&[
			"set",
			"Cloudflare",
			"--zone",
			"Example.ORG",
			"--token-env",
			"CF_TOKEN",
		],
		false,
	);
	assert_eq!(run.result.unwrap(), ExitCode::SUCCESS);
	assert_eq!(
		run.after,
		format!(
			"{}\n[dns]\nprovider = \"cloudflare\"\nzone = \"example.org\"\ntoken_env = \"CF_TOKEN\"\n",
			run.before
		),
		"a new section needs the lowercase provider and zone and only the credential source given"
	);
	assert_eq!(
		run.status,
		"dns provider saved\nThe server must be restarted.\n"
	);
}

#[test]
fn switching_provider_changes_in_place_and_clears_stale_credentials() {
	let run = run(
		DNS,
		&[
			"set",
			"route53",
			"--zone",
			"example.org",
			"--access-key",
			"AKIAEXAMPLE",
			"--secret-key-env",
			"AWS_SECRET",
			"--hosted-zone-id",
			"Z123",
		],
		false,
	);
	assert_eq!(run.result.unwrap(), ExitCode::SUCCESS);
	assert_eq!(
		run.after,
		run.before
			.replace(
				"provider = 'cloudflare' # who",
				"provider = \"route53\" # who"
			)
			.replace(
				"token_env = 'CF_TOKEN' # secret source\n",
				"access_key = \"AKIAEXAMPLE\"\nsecret_key_env = \"AWS_SECRET\"\nhosted_zone_id = \"Z123\"\n"
			) + "# secret source\n",
		"the previous token source must not survive a provider switch"
	);
}

#[test]
fn set_clears_an_inline_secret_left_by_hand() {
	let run = run(
		"\n[dns]\nprovider = 'cloudflare'\nzone = 'example.org'\ntoken = 'inline-secret'\n",
		&[
			"set",
			"cloudflare",
			"--zone",
			"example.org",
			"--token-file",
			"/etc/epistle/dns.token",
		],
		false,
	);
	assert_eq!(run.result.unwrap(), ExitCode::SUCCESS);
	assert!(!run.after.contains("inline-secret"), "{}", run.after);
	assert!(
		run.after
			.contains("token_file = \"/etc/epistle/dns.token\"")
	);
}

#[test]
fn set_dry_run_prints_the_diff_and_writes_nothing() {
	let run = run("", &["set", "manual", "--zone", "example.org"], true);
	assert!(run.out.contains("+provider = \"manual\""), "{}", run.out);
	assert_eq!(run.after, run.before);
	assert!(run.status.is_empty());
}

#[test]
fn invalid_requests_are_refused_and_leave_the_file_untouched() {
	let supported = SUPPORTED_PROVIDERS.join(", ");
	for (args, message) in [
		(
			vec!["set", "cloudfare", "--zone", "example.org"],
			format!("provider \"cloudfare\" is not a supported provider; supported: {supported}"),
		),
		(vec!["set", "manual"], "--zone is required".to_string()),
		(
			vec!["set", "cloudflare", "--zone", "example.org"],
			"cloudflare needs --token-env or --token-file".to_string(),
		),
		(
			vec![
				"set",
				"cloudflare",
				"--zone",
				"example.org",
				"--token-env",
				"A",
				"--token-file",
				"/a",
			],
			"choose one of --token-env and --token-file".to_string(),
		),
		(
			vec![
				"set",
				"cloudflare",
				"--zone",
				"example.org",
				"--token-env",
				"A",
				"--hosted-zone-id",
				"Z",
			],
			"--hosted-zone-id is not used by cloudflare".to_string(),
		),
		(
			vec![
				"set",
				"route53",
				"--zone",
				"example.org",
				"--access-key",
				"K",
				"--secret-key-env",
				"S",
			],
			"route53 needs --hosted-zone-id".to_string(),
		),
		(
			vec![
				"set",
				"dnsimple",
				"--zone",
				"example.org",
				"--token-env",
				"T",
			],
			"dnsimple needs --account-id".to_string(),
		),
		(
			vec![
				"set",
				"ovh",
				"--zone",
				"example.org",
				"--access-key",
				"K",
				"--secret-key-env",
				"S",
				"--consumer-key-env",
				"C",
				"--endpoint",
				"ovh-asia",
			],
			"--endpoint must be ovh-eu, ovh-ca, ovh-us or an https:// URL".to_string(),
		),
		(
			vec![
				"set",
				"rfc2136",
				"--zone",
				"example.org",
				"--token-env",
				"T",
				"--key-name",
				"k",
				"--endpoint",
				"ns1.example.org",
			],
			"--endpoint must be the nameserver HOST:PORT".to_string(),
		),
		(
			vec![
				"set",
				"rfc2136",
				"--zone",
				"example.org",
				"--token-env",
				"T",
				"--key-name",
				"k",
				"--endpoint",
				"ns1.example.org:53",
				"--algorithm",
				"hmac-md5",
			],
			"--algorithm must be hmac-sha256, hmac-sha384 or hmac-sha512".to_string(),
		),
		(
			vec![
				"set",
				"gcloud",
				"--zone",
				"example.org",
				"--token-env",
				"T",
				"--credentials-file",
				"sa.json",
			],
			"--credentials-file must be an absolute path".to_string(),
		),
		(
			vec![
				"set",
				"cloudflare",
				"--zone",
				"example.org",
				"--token-env",
				"A-B",
			],
			"--token-env \"A-B\" is not an environment variable name".to_string(),
		),
		(
			vec![
				"set",
				"cloudflare",
				"--zone",
				"not a zone",
				"--token-env",
				"A",
			],
			"--zone \"not a zone\" is not a valid DNS name".to_string(),
		),
	] {
		let run = run(DNS, &args, false);
		assert_eq!(run.result.unwrap_err(), message, "{args:?}");
		assert!(run.after == run.before, "{args:?} must not change the file");
	}
}

/// Every supported provider must be settable, and for the ones whose
/// credentials come only from the environment the saved section must be one
/// `Dns::build` accepts.
#[test]
fn every_supported_provider_is_settable_and_buildable_where_it_can_be() {
	let all = [
		("cloudflare", vec!["--token-env", "PATH"]),
		("bunny", vec!["--token-env", "PATH"]),
		("desec", vec!["--token-env", "PATH"]),
		("digitalocean", vec!["--token-env", "PATH"]),
		("namecheap", vec!["--token-env", "PATH"]),
		("dnsimple", vec!["--token-env", "PATH", "--account-id", "1"]),
		(
			"spaceship",
			vec!["--access-key", "k", "--secret-key-env", "PATH"],
		),
		(
			"godaddy",
			vec!["--access-key", "k", "--secret-key-env", "PATH"],
		),
		(
			"porkbun",
			vec!["--access-key", "k", "--secret-key-env", "PATH"],
		),
		(
			"ovh",
			vec![
				"--access-key",
				"k",
				"--secret-key-env",
				"PATH",
				"--consumer-key-env",
				"PATH",
				"--endpoint",
				"ovh-ca",
			],
		),
		(
			"route53",
			vec![
				"--access-key",
				"k",
				"--secret-key-env",
				"PATH",
				"--hosted-zone-id",
				"Z",
			],
		),
		(
			"rfc2136",
			vec![
				"--token-env",
				"PATH",
				"--key-name",
				"k",
				"--endpoint",
				"ns.example.org:53",
				"--algorithm",
				"hmac-sha512",
			],
		),
		(
			"gcloud",
			vec!["--token-env", "PATH", "--credentials-file", "/tmp/sa.json"],
		),
		("manual", vec![]),
	];
	assert_eq!(
		all.len(),
		SUPPORTED_PROVIDERS.len(),
		"a provider was added to the loader list without a rule here"
	);
	for name in SUPPORTED_PROVIDERS {
		let flags = &all
			.iter()
			.find(|(p, _)| p == name)
			.expect("covered provider")
			.1;
		let mut args = vec!["set", name, "--zone", "example.org"];
		args.extend(flags.iter().copied());
		let run = run("", &args, false);
		assert_eq!(run.result.unwrap(), ExitCode::SUCCESS, "{name}");
		if matches!(*name, "manual" | "gcloud" | "namecheap" | "rfc2136") {
			continue;
		}
		let section: toml::Value =
			toml::from_str(&run.after).expect("the saved configuration must parse");
		let dns: Dns = section["dns"].clone().try_into().expect("the dns section");
		assert!(
			dns.build().is_some(),
			"{name} must build from the saved section"
		);
	}
}
