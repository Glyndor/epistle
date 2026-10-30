//! The JSON each new `list` and `show` prints: an array for a list, one
//! object for a show, the same keys for a static and a dynamic account,
//! and nothing secret.

use std::process::ExitCode;

use serde_json::{Value, json};

use crate::cli::account::{self, CatchAllArgs, ForwardArgs, Subcommand, TwoFactorArgs};
use crate::directory_store::{AccountStore, AppPassword, AppPasswordStore, DynamicAccount};

/// A data dir with dynamic `bob` (a forward, a catch-all, TOTP enrolled)
/// and a config with a static `postmaster`.
fn setup() -> (tempfile::TempDir, tempfile::NamedTempFile) {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut file = tempfile::NamedTempFile::new().expect("config file");
	use std::io::Write as _;
	write!(
		file,
		"hostname = \"mail.example.org\"\ndata_dir = {:?}\ndomains = [\"example.org\"]\n\
		 [[accounts]]\nname = \"postmaster\"\naddresses = [\"postmaster@example.org\"]\n",
		dir.path()
	)
	.expect("write config");
	let config = crate::config::Config::load(file.path()).expect("config loads");
	let store = AccountStore::open(
		&config.data_dir,
		config.domains.clone(),
		config.domain_aliases.clone(),
		config.accounts.clone(),
	)
	.expect("open store");
	store
		.add(DynamicAccount {
			name: "bob".to_string(),
			addresses: vec!["bob@example.org".to_string()],
			password_hash: crate::smtp::auth::tests::base::hash(
				crate::smtp::auth::tests::base::fixture_password(),
			),
			forward: vec!["out@example.com".to_string()],
			catch_all: vec!["example.org".to_string()],
			..DynamicAccount::default()
		})
		.expect("add bob");
	store
		.set_totp("bob", Some("JBSWY3DPEHPK3PXP".to_string()))
		.expect("enrol");
	(dir, file)
}

fn run(config: &tempfile::NamedTempFile, action: Subcommand) -> Value {
	let mut out = Vec::new();
	assert_eq!(
		account::run(config.path(), action, false, &mut out),
		ExitCode::SUCCESS
	);
	let text = String::from_utf8(out).expect("utf8");
	assert_eq!(text.lines().count(), 1, "not one line of JSON: {text}");
	serde_json::from_str(&text).expect("valid JSON")
}

#[test]
fn account_list_json_is_an_array_sorted_by_name() {
	let (_dir, config) = setup();
	assert_eq!(
		run(&config, Subcommand::List { json: true }),
		json!([
			{ "name": "bob", "source": "dynamic", "display_name": null, "addresses": ["bob@example.org"] },
			{ "name": "postmaster", "source": "static", "display_name": null, "addresses": ["postmaster@example.org"] },
		])
	);
}

#[test]
fn account_show_json_has_the_same_keys_for_both_sources() {
	let (_dir, config) = setup();
	let show = |name: &str| {
		run(
			&config,
			Subcommand::Show {
				name: name.to_string(),
				json: true,
			},
		)
	};
	let mut bob = show("bob");
	assert!(
		bob["log_id"]
			.as_str()
			.is_some_and(|id| id.starts_with("acct-"))
	);
	bob["log_id"] = Value::Null;
	assert_eq!(
		bob,
		json!({
			"name": "bob", "log_id": null, "source": "dynamic", "display_name": null,
			"addresses": ["bob@example.org"], "disabled": false, "quota_bytes": null,
			"protocols": null, "two_factor": true,
			"forward": ["out@example.com"], "catch_all": ["example.org"],
		})
	);
	let postmaster = show("postmaster");
	let keys = |value: &Value| {
		let mut keys: Vec<String> = value.as_object().expect("object").keys().cloned().collect();
		keys.sort();
		keys
	};
	assert_eq!(keys(&postmaster), keys(&bob));
	assert_eq!(postmaster["source"], "static");
	assert!(!bob.to_string().contains("JBSWY3DP"), "TOTP secret printed");
}

#[test]
fn forward_catch_all_and_2fa_json() {
	let (_dir, config) = setup();
	use crate::cli::account::{CatchAllSubcommand, ForwardSubcommand, TwoFactorSubcommand};
	let name = || "bob".to_string();
	let forward = ForwardSubcommand::List {
		name: name(),
		json: true,
	};
	assert_eq!(
		run(
			&config,
			Subcommand::Forward(ForwardArgs { action: forward })
		),
		json!([{ "address": "out@example.com" }])
	);
	let catch_all = CatchAllSubcommand::List {
		name: name(),
		json: true,
	};
	assert_eq!(
		run(
			&config,
			Subcommand::CatchAll(CatchAllArgs { action: catch_all })
		),
		json!([{ "domain": "example.org" }])
	);
	let two_factor = TwoFactorSubcommand::Show {
		name: name(),
		json: true,
	};
	assert_eq!(
		run(
			&config,
			Subcommand::TwoFactor(TwoFactorArgs { action: two_factor })
		),
		json!({ "name": "bob", "enrolled": true })
	);
}

#[test]
fn app_password_list_json() {
	let (dir, config) = setup();
	AppPasswordStore::open(dir.path())
		.expect("open")
		.add(
			"bob",
			AppPassword {
				label: "phone".to_string(),
				hash: crate::smtp::auth::tests::base::hash(crate::test_fixtures::password()),
				expires_at: Some(99),
				ip_cidr: None,
				save_sent: None,
			},
		)
		.expect("add");
	let config = crate::config::Config::load(config.path()).expect("config");
	let mut out = Vec::new();
	let action = crate::cli::app::passwords::AppPasswordCli::List {
		account: None,
		json: true,
	};
	assert_eq!(
		crate::cli::app::passwords::run(&config, action, false, &mut out),
		ExitCode::SUCCESS
	);
	let value: Value = serde_json::from_slice(&out).expect("valid JSON");
	assert_eq!(
		value,
		json!([{ "account": "bob", "label": "phone", "expires_at": 99, "ip_cidr": null, "save_sent": null }])
	);
}

#[test]
fn limits_and_antispam_show_json_are_objects_keyed_by_name() {
	let (_dir, config) = setup();
	let config = crate::config::Config::load(config.path()).expect("config");
	let limits = crate::cli::limits::show_json(&config);
	assert_eq!(
		limits["quota"],
		json!({
			"value": crate::imap::session::DEFAULT_QUOTA_BYTES,
			"unit": "bytes",
			"source": "default",
			"kind": "adjustable",
			"class": "own",
			"bounds": null,
			"reference": "no standard mandate",
		})
	);
	let antispam = crate::cli::antispam::show::show_json(&config);
	assert_eq!(antispam["dnsbl-zones"]["value"], json!([]));
	assert_eq!(antispam["dnsbl-zones"]["source"], "default");
	assert_eq!(antispam["llm-api-key-env"]["value"], "unset");
}
