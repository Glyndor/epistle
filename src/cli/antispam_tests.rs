//! `epistle antispam`: covering all keys map to their TOML fields, the
//! loaded config exposes the same values, and the `unset` path restores
//! the defaults.

use std::fs;
use std::io::Write;
use std::path::Path;

use super::*;
use crate::cli::config_edit::ConfigDocument;
use crate::config::Config;

fn fixture(extra: &str) -> (tempfile::TempDir, tempfile::NamedTempFile) {
	let dir = tempfile::tempdir().unwrap();
	let mut file = tempfile::NamedTempFile::new_in(dir.path()).unwrap();
	writeln!(
		file,
		"hostname = \"mail.example.org\"\ndata_dir = {:?}\ndomains = [\"example.org\"]\n{extra}\n",
		dir.path().canonicalize().unwrap().to_string_lossy()
	)
	.unwrap();
	file.flush().unwrap();
	(dir, file)
}

fn fixture_with_db(extra: &str) -> (tempfile::TempDir, tempfile::NamedTempFile) {
	let dir = tempfile::tempdir().unwrap();
	let mut file = tempfile::NamedTempFile::new_in(dir.path()).unwrap();
	writeln!(
		file,
		"hostname = \"mail.example.org\"\ndata_dir = {:?}\ndomains = [\"example.org\"]\n{extra}\n[database]\nurl = \"postgres://localhost/epistle\"\ntls = \"insecure\"\n",
		dir.path().canonicalize().unwrap().to_string_lossy()
	)
	.unwrap();
	file.flush().unwrap();
	(dir, file)
}

fn load(path: &Path) -> Config {
	Config::load(path).expect("config must load")
}

fn open(path: &Path) -> ConfigDocument {
	ConfigDocument::open(path).expect("config document must open")
}

type Case = (Key, &'static str, Box<dyn Fn(&Config) -> bool>);

#[test]
fn set_writes_every_scalar_key_to_its_mapped_field() {
	let cases: [Case; 11] = [
		(
			Key::GreylistDelay,
			"5m",
			Box::new(|c| c.greylist_delay_secs == 300),
		),
		(
			Key::FirstTimeSenderDelay,
			"90s",
			Box::new(|c| c.first_time_sender_delay_secs == 90),
		),
		(
			Key::ClamdSocket,
			"/run/clamav/clamd.sock",
			Box::new(|c| {
				c.antispam
					.clamd_socket
					.as_ref()
					.map(|p| p.to_string_lossy() == "/run/clamav/clamd.sock")
					.unwrap_or(false)
			}),
		),
		(
			Key::ClamdOnFound,
			"reject",
			Box::new(|c| c.antispam.clamd_on_found == crate::config::ClamdOnFound::Reject),
		),
		(
			Key::ClamdTimeout,
			"60",
			Box::new(|c| c.antispam.clamd_timeout_secs == 60),
		),
		(
			Key::ClamdMaxSize,
			"16M",
			Box::new(|c| c.antispam.clamd_max_bytes == 16 * 1024 * 1024),
		),
		(
			Key::LlmEndpoint,
			"https://api.example/v1/chat/completions",
			Box::new(|c| {
				c.antispam_llm
					.as_ref()
					.map(|l| l.endpoint == "https://api.example/v1/chat/completions")
					.unwrap_or(false)
			}),
		),
		(
			Key::LlmModel,
			"gpt-4o-mini",
			Box::new(|c| {
				c.antispam_llm
					.as_ref()
					.map(|l| l.model == "gpt-4o-mini")
					.unwrap_or(false)
			}),
		),
		(
			Key::LlmApiKeyEnv,
			"EPISTLE_LLM_API_KEY",
			Box::new(|c| {
				c.antispam_llm
					.as_ref()
					.map(|l| l.api_key_env == "EPISTLE_LLM_API_KEY")
					.unwrap_or(false)
			}),
		),
		(
			Key::LlmUncertainLow,
			"0.25",
			Box::new(|c| {
				c.antispam_llm
					.as_ref()
					.map(|l| (l.uncertain_low - 0.25).abs() < 1e-9)
					.unwrap_or(false)
			}),
		),
		(
			Key::LlmUncertainHigh,
			"0.75",
			Box::new(|c| {
				c.antispam_llm
					.as_ref()
					.map(|l| (l.uncertain_high - 0.75).abs() < 1e-9)
					.unwrap_or(false)
			}),
		),
	];
	for (key, value, assertion) in cases {
		let (_dir, file) = fixture("");
		let mut document = open(file.path());
		// The LLM block requires every field present to load. Seed the
		// block with placeholders before testing a single key, so the
		// commit-time validate does not flag the rest as missing.
		if matches!(
			key,
			Key::LlmEndpoint
				| Key::LlmModel
				| Key::LlmApiKeyEnv
				| Key::LlmUncertainLow
				| Key::LlmUncertainHigh
		) {
			set_scalar_field(&mut document, Key::LlmEndpoint, "https://example.test/v1").unwrap();
			set_scalar_field(&mut document, Key::LlmModel, "placeholder").unwrap();
			set_scalar_field(&mut document, Key::LlmApiKeyEnv, "PLACEHOLDER_ENV").unwrap();
		}
		set_scalar_field(&mut document, key, value).expect("set must succeed");
		let outcome = document.commit().expect("commit must succeed");
		assert_eq!(
			outcome,
			crate::cli::config_edit::Outcome::Changed,
			"{key:?} set must mark the document changed"
		);
		let config = load(file.path());
		assert!(
			assertion(&config),
			"{key:?} = {value:?} must surface on the loaded config"
		);
	}
}

#[test]
fn set_subjectpass_on_only_with_db_section() {
	let (_dir, file) = fixture_with_db("");
	let mut document = open(file.path());
	set_scalar_field(&mut document, Key::Subjectpass, "on").expect("set must succeed");
	let outcome = document.commit().expect("commit must succeed");
	assert_eq!(outcome, crate::cli::config_edit::Outcome::Changed);
	let config = load(file.path());
	assert!(config.subjectpass.enabled);
}

#[test]
fn set_subjectpass_on_is_rejected_without_db() {
	let (_dir, file) = fixture("");
	let mut document = open(file.path());
	apply_set(&mut document, Key::Subjectpass, &["on".to_string()])
		.expect("apply_set writes to the document");
	// The validation that needs [database] fires at commit time: the loader
	// refuses to parse the document without a database when subjectpass is
	// enabled, so the commit step is the place the operator sees the
	// concrete refusal.
	let err = document.commit().unwrap_err();
	assert!(
		err.contains("subjectpass") && err.contains("database"),
		"set subjectpass on must surface the database requirement: {err}"
	);
}

#[test]
fn set_dnsbl_zone_replaces_the_whole_list() {
	let (_dir, file) = fixture("dnsbl_zones = [\"a.example\", \"b.example\"]\n");
	let mut document = open(file.path());
	set_list_field(
		&mut document,
		Key::DnsblZones,
		&["c.example".to_string(), "d.example".to_string()],
	)
	.expect("set must succeed");
	let outcome = document.commit().expect("commit must succeed");
	assert_eq!(outcome, crate::cli::config_edit::Outcome::Changed);
	let config = load(file.path());
	assert_eq!(config.dnsbl_zones, vec!["c.example", "d.example"]);
}

#[test]
fn unset_returns_a_scalar_to_its_default() {
	let (_dir, file) = fixture("greylist_delay_secs = 200\n[antispam]\nclamd_timeout_secs = 90\n");
	let mut document = open(file.path());
	let snapshot = load(file.path());
	assert_eq!(snapshot.greylist_delay_secs, 200);
	unset_scalar_field(&mut document, Key::GreylistDelay).expect("unset must succeed");
	let outcome = document.commit().expect("commit must succeed");
	assert_eq!(outcome, crate::cli::config_edit::Outcome::Changed);
	let config = load(file.path());
	assert_eq!(config.greylist_delay_secs, 0);
	assert_eq!(config.antispam.clamd_timeout_secs, 90);
}

#[test]
fn show_lists_every_key_and_marks_secrets_as_set_only() {
	let (_dir, file) = fixture(
		"[antispam_llm]\nendpoint = \"https://api.example/v1/chat/completions\"\napi_key_env = \"EPISTLE_LLM_API_KEY\"\nmodel = \"gpt-4o-mini\"\n",
	);
	let config = load(file.path());
	let mut out = Vec::new();
	show_keys(&config, &mut out).expect("show must succeed");
	let output = String::from_utf8(out).unwrap();
	for needle in [
		"dnsbl-zones\t(empty)\tdefault",
		"greylist-delay\t0 seconds\tdefault",
		"first-time-sender-delay\t0 seconds\tdefault",
		"clamd-socket\tunset\tdefault",
		"clamd-on-found\tquarantine\tset",
		"clamd-timeout\t30\tset",
		"subjectpass\toff\tset",
		"llm-endpoint\tset\tset",
		"llm-model\tset\tset",
		"llm-api-key-env\tset\tset",
		"llm-uncertain-low\t0.35\tset",
		"llm-uncertain-high\t0.65\tset",
	] {
		assert!(
			output.contains(needle),
			"show must contain {needle:?}\n--- got ---\n{output}"
		);
	}
	assert!(
		!output.contains("EPISTLE_LLM_API_KEY"),
		"show must never print the configured env var name"
	);
	assert!(
		!output.contains("https://api.example/v1/chat/completions"),
		"show must never print the configured endpoint"
	);
}

#[test]
fn idempotent_set_reports_unchanged_outcome() {
	let (_dir, file) = fixture("greylist_delay_secs = 300");
	let mut document = open(file.path());
	set_scalar_field(&mut document, Key::GreylistDelay, "5m").expect("set must succeed");
	let outcome = document.commit().expect("commit must succeed");
	assert_eq!(
		outcome,
		crate::cli::config_edit::Outcome::Unchanged,
		"writing the same value twice must report Unchanged"
	);
}

#[test]
fn reject_set_writes_a_specific_rejection_outcome() {
	let (_dir, file) = fixture("");
	let mut document = open(file.path());
	set_scalar_field(&mut document, Key::ClamdOnFound, "reject").expect("set must succeed");
	document.commit().expect("commit must succeed");
	let config = load(file.path());
	assert_eq!(
		config.antispam.clamd_on_found,
		crate::config::ClamdOnFound::Reject
	);
}

#[test]
fn unloadable_config_is_rejected_before_edit() {
	let (_dir, file) = fixture("scanner_hook_url = \"http://scanner.example/\"\n");
	let mut document = open(file.path());
	let err = apply_set(
		&mut document,
		Key::ClamdSocket,
		&["/run/clamav/clamd.sock".to_string()],
	)
	.unwrap_err();
	assert_eq!(
		err,
		"clamd-socket and scanner-hook-url cannot be set together: only one scanner per server",
		"the loader conflict must surface a specific message before any write"
	);
	let raw = fs::read_to_string(file.path()).unwrap();
	assert!(
		!raw.contains("/run/clamav/clamd.sock"),
		"the rejected edit must leave the file untouched"
	);
}
