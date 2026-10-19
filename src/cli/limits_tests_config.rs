use std::io::{Seek, Write};
use std::process::ExitCode;

use super::*;

pub(super) fn config_file() -> (tempfile::TempDir, tempfile::NamedTempFile) {
	let dir = tempfile::tempdir_in(".").unwrap();
	let mut file = tempfile::NamedTempFile::new_in(dir.path()).unwrap();
	writeln!(
		file,
		"hostname = \"mail.example.org\"\ndata_dir = {:?}\ndomains = [\"example.org\"]\nlog_format = \"json\"\nsrs_secret = \"${{PATH}}\"\n[antispam]\nclamd_timeout_secs = 45",
		dir.path().canonicalize().unwrap().to_string_lossy()
	)
	.unwrap();
	(dir, file)
}

#[test]
fn limits_set_unset_round_trip_preserves_every_other_key() {
	let (_dir, file) = config_file();
	let original: toml::Value =
		toml::from_str(&std::fs::read_to_string(file.path()).unwrap()).unwrap();
	for (key, input, expected) in [
		(Key::Quota, "7G", 7 * 1024 * 1024 * 1024),
		(Key::SubmissionRate, "120", 120),
		(Key::NewRecipientsPerDay, "400", 400),
		(Key::QueueGiveUp, "12h", 43200),
		(Key::InboundRatePerIp, "25", 25),
		(Key::InboundRatePerSender, "80", 80),
		(Key::MaxConnectionsPerListener, "200", 200),
		(Key::MaskedAddressesMax, "30", 30),
		(Key::FirstTimeSenderDelay, "10s", 10),
		(Key::GreylistDelay, "3m", 180),
		(Key::MaxMessageSize, "10M", 10 * 1024 * 1024),
		(Key::MessageMemoryBudget, "128M", 128 * 1024 * 1024),
		(Key::MaxConnectionsPerIp, "5", 5),
		(Key::KnownNetworkWindow, "7d", 7 * 86400),
	] {
		let result = change_config(file.path(), key, Some(input));
		assert!(
			result.is_ok(),
			"limits set must save the numeric value in the existing config"
		);
		let mut edited: toml::Value =
			toml::from_str(&std::fs::read_to_string(file.path()).unwrap()).unwrap();
		assert_eq!(
			edited[key.field()].as_integer(),
			Some(expected),
			"limits set must write the mapped config field"
		);
		edited.as_table_mut().unwrap().remove(key.field());
		assert!(
			edited == original,
			"limits set must preserve unrelated keys and environment placeholders"
		);
		assert!(
			change_config(file.path(), key, None).is_ok(),
			"limits unset must remove the configured override"
		);
		let restored: toml::Value =
			toml::from_str(&std::fs::read_to_string(file.path()).unwrap()).unwrap();
		assert!(
			restored == original,
			"limits unset must restore the original config values"
		);
	}
}

#[test]
fn limits_invalid_values_leave_config_bytes_untouched() {
	let (_dir, file) = config_file();
	let original = std::fs::read(file.path()).unwrap();
	for (key, input) in [
		(Key::Quota, "1.5G"),
		(Key::SubmissionRate, "4294967296"),
		(Key::QueueGiveUp, "-5d"),
		(Key::MaskedAddressesMax, "9223372036854775808"),
	] {
		assert_eq!(
			change_config(file.path(), key, Some(input)).err(),
			Some(format!(
				"{}: expected a non-negative integer with a supported suffix within the field range",
				key.name()
			)),
			"limits must report the rejected key and the allowed numeric shape"
		);
		assert!(
			std::fs::read(file.path()).unwrap() == original,
			"invalid limits must leave the file byte-for-byte untouched"
		);
	}
}

#[test]
fn limits_refuse_a_message_size_the_memory_budget_cannot_hold() {
	let (_dir, file) = config_file();
	let original = std::fs::read(file.path()).unwrap();
	let result = change_config(file.path(), Key::MaxMessageSize, Some("1025M"));
	assert!(
		result
			.err()
			.is_some_and(|message| message.contains("message_memory_budget")),
		"a size over the 1 GiB a derived budget can reach is refused"
	);
	assert!(
		std::fs::read(file.path()).unwrap() == original,
		"the refused size leaves the file byte-for-byte untouched"
	);
	assert!(change_config(file.path(), Key::MessageMemoryBudget, Some("8M")).is_err());
	assert!(change_config(file.path(), Key::MaxMessageSize, Some("8M")).is_ok());
}

#[test]
fn limits_candidate_validation_preserves_invalid_config() {
	let (_dir, mut file) = config_file();
	let text = std::fs::read_to_string(file.path())
		.unwrap()
		.replace("mail.example.org", "bad hostname");
	file.as_file_mut().set_len(0).unwrap();
	file.as_file_mut().rewind().unwrap();
	file.write_all(text.as_bytes()).unwrap();
	let result = change_config(file.path(), Key::Quota, Some("7G"));
	assert!(
		result
			.err()
			.is_some_and(|message| message.contains("hostname")),
		"limits must validate the complete candidate before replacing the config"
	);
	assert!(
		std::fs::read_to_string(file.path()).unwrap() == text,
		"failed candidate validation must preserve the original file bytes"
	);
	assert_eq!(
		std::fs::read_dir(file.path().parent().unwrap())
			.unwrap()
			.count(),
		1,
		"failed validation must remove its staging file"
	);
}

#[test]
fn limits_show_marks_effective_defaults_and_configured_values() {
	let (_dir, file) = config_file();
	let config = Config::load(file.path()).unwrap();
	let mut out = Vec::new();
	show(&config, &mut out).unwrap();
	let printed = String::from_utf8(out).unwrap();
	for line in [
		"quota\t5368709120 bytes\tdefault\tadjustable\tno standard mandate",
		"submission-rate\tdisabled\tdefault\tadjustable\tno standard mandate",
		"queue-give-up\t432000 seconds\tdefault\trecommended\tRFC 5321 §4.5.4.1 (4-5 days recommended)",
		"queue-retry-base\t60 seconds\tdefault\trecommended\tRFC 5321 §4.5.4.1 (30 minutes recommended)",
		"max-recipients\t100\tdefault\trecommended\tRFC 5321 §4.5.3.1.8 (at least 100)",
		"message-memory-budget\tauto (204 MiB, no mail container limit found, 1g assumed)\tderived\tadjustable\tno standard mandate",
		"smtp-line-length\t998 octets\tfixed\tfixed\tRFC 5321 §4.5.3.1.6 (998 octets excl. CRLF; 1000 incl. CRLF)",
		"spf-max-dns-lookups\t10 count\tfixed\tfixed\tRFC 7208 §4.6.4 (max 10 DNS-querying terms)",
		"tls-minimum-version\t1.2 version\tfixed\tfixed\tRFC 8996 (TLS 1.0/1.1 prohibited)",
	] {
		assert!(
			printed.lines().any(|row| row == line),
			"limits show must include the row `{line}`; printed:\n{printed}"
		);
	}
	change_config(file.path(), Key::SubmissionRate, Some("120")).unwrap();
	let config = Config::load(file.path()).unwrap();
	let mut out = Vec::new();
	show(&config, &mut out).unwrap();
	assert!(
		String::from_utf8(out)
			.unwrap()
			.lines()
			.any(|line| line.starts_with("submission-rate\t120\tconfigured\tadjustable\t")),
		"limits show must mark a changed value as configured"
	);
}

#[test]
fn a_zero_quota_shows_as_unlimited() {
	let (_dir, file) = config_file();
	change_config(file.path(), Key::Quota, Some("0")).unwrap();
	let config = Config::load(file.path()).unwrap();
	let mut out = Vec::new();
	show(&config, &mut out).unwrap();
	let first = String::from_utf8(out)
		.unwrap()
		.lines()
		.next()
		.unwrap()
		.to_string();
	assert!(
		first.starts_with("quota\tunlimited\tconfigured\tadjustable\t"),
		"first row: {first}"
	);
}

/// `epistle limits show --json` must list every per-domain override
/// (quota and submission-rate) and every per-tenant submission-rate
/// alongside the global values, so an operator's one call answers the
/// "what is in force for every sender" question.
#[test]
fn limits_show_json_lists_every_domain_override_and_every_tenant_entry() {
	let (_dir, file) = config_file();
	let text = std::fs::read_to_string(file.path()).unwrap()
		+ "\n[domain_quotas]\n'example.org' = 10737418240 # cap\n"
		+ "[domain_submission_limits]\n'example.org' = 50 # rate\n"
		+ "\n[[tenant]]\nname = \"acme\"\ndomains = [\"example.org\"]\nsubmission_rate_limit_per_min = 200\n";
	std::fs::write(file.path(), text).unwrap();
	let config = Config::load(file.path()).unwrap();
	let json = super::show_json(&config);
	// Domain overrides: each domain name maps to its quota and
	// submission-rate entries (null when not set).
	let domain_overrides = &json["domain-overrides"];
	assert_eq!(
		domain_overrides["example.org"],
		serde_json::json!({"quota": 10_737_418_240_u64, "submission-rate": 50_u32})
	);
	// Tenant overrides: each named tenant maps to its aggregate dial.
	let tenants = &json["tenants"];
	assert_eq!(
		tenants["acme"],
		serde_json::json!({"submission-rate": 200_u32})
	);
	// The global submission-rate entry stays alongside the others
	// and reports the configured (default) value.
	let submission = &json["submission-rate"];
	assert_eq!(submission["unit"], "count");
	assert_eq!(submission["source"], "default");
	// The known-network window is a duration key the operator can
	// override through the same CLI surface; absent keeps the
	// 30-day default the policy ships with.
	let known_network = &json["known-network-window"];
	assert_eq!(known_network["unit"], "seconds");
	assert_eq!(known_network["value"], 30 * 24 * 60 * 60_u64);
}

/// `epistle limits set --json` emits a single JSON object on stdout and
/// still applies the change to the running server: a JSON caller gets the
/// same restart as everyone else, not a saved file the server ignores.
#[test]
fn limits_set_with_json_emits_only_the_confirmation_object_and_restarts() {
	let (dir, file) = config_file();
	let compose = crate::cli::init::compose_file_path(&dir.path().canonicalize().unwrap());
	std::fs::create_dir_all(compose.parent().unwrap()).unwrap();
	std::fs::write(&compose, "services: {}\n").unwrap();
	let mut out = Vec::new();
	let mut status = Vec::new();
	let mut restarted = false;
	let code = super::run_with_restart(
		file.path(),
		super::Action::Set {
			key: Key::SubmissionRate,
			domain: None,
			tenant: None,
			value: "120".into(),
			json: true,
		},
		false,
		&mut out,
		&mut status,
		|_, _| {
			restarted = true;
			ExitCode::SUCCESS
		},
	);
	assert_eq!(code, ExitCode::SUCCESS);
	assert!(restarted, "the running server must pick up the change");
	assert!(
		status.is_empty(),
		"nothing but the restart on the status stream"
	);
	let payload: serde_json::Value = serde_json::from_slice(out.as_slice()).expect("json payload");
	assert_eq!(payload["result"], "saved");
	assert_eq!(payload["key"], "submission-rate");
	assert_eq!(payload["action"], "set");
	assert_eq!(payload["scope"]["type"], "global");
	assert_eq!(payload["value"], 120_u64);
}

/// A submission rate of zero is refused at every scope: the limiter reads
/// zero as no limit, so accepting it would lift the cap it looks like it
/// tightens. `unset` is how a limit is removed.
#[test]
fn a_zero_submission_rate_is_refused() {
	let (_dir, file) = config_file();
	let before = std::fs::read_to_string(file.path()).unwrap();
	for (domain, tenant) in [
		(None, None),
		(Some("example.org"), None),
		(None, Some("acme")),
	] {
		let mut status = Vec::new();
		let code = super::run_with_restart(
			file.path(),
			super::Action::Set {
				key: Key::SubmissionRate,
				domain: domain.map(str::to_string),
				tenant: tenant.map(str::to_string),
				value: "0".into(),
				json: false,
			},
			false,
			&mut Vec::new(),
			&mut status,
			|_, _| panic!("nothing was saved"),
		);
		assert_eq!(code, ExitCode::FAILURE);
		let status = String::from_utf8(status).unwrap();
		assert!(status.contains("use `unset`"), "{status}");
	}
	assert_eq!(std::fs::read_to_string(file.path()).unwrap(), before);
}

/// `epistle limits set --json` carries the domain and tenant scope
/// through to the confirmation object, so an operator's pipeline
/// can audit which dial just moved.
#[test]
fn limits_set_with_json_records_domain_and_tenant_scope() {
	let (_dir, file) = config_file();
	let mut out = Vec::new();
	let mut status = Vec::new();
	let mut original = std::fs::read_to_string(file.path()).unwrap();
	original.push_str("\n[domain_submission_limits]\n'example.org' = 5 # rate\n");
	std::fs::write(file.path(), &original).unwrap();
	super::run_with_restart(
		file.path(),
		super::Action::Set {
			key: Key::SubmissionRate,
			domain: Some("example.org".into()),
			tenant: None,
			value: "20".into(),
			json: true,
		},
		false,
		&mut out,
		&mut status,
		|_, _| panic!("must not restart"),
	);
	let payload: serde_json::Value = serde_json::from_slice(out.as_slice()).expect("json payload");
	assert_eq!(payload["scope"]["type"], "domain");
	assert_eq!(payload["scope"]["name"], "example.org");
	assert_eq!(payload["value"], 20_u64);
}
