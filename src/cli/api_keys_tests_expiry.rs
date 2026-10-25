//! Tests for `api-key create --expires-at/--expires-in` and the readable
//! expiry in `api-key list`.

use clap::Parser;

use super::*;
use crate::cli::{Cli, Command};

fn config(data_dir: &std::path::Path) -> Config {
	let toml = format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"{}\"\n",
		data_dir.display()
	);
	toml::from_str(&toml).expect("config parses")
}

fn parsed(extra: &[&str]) -> Result<Option<u64>, clap::Error> {
	let mut args = vec!["epistle", "api-key", "create", "ci", "--scope", "read"];
	args.extend_from_slice(extra);
	let cli = Cli::try_parse_from(args)?;
	match cli.command {
		Command::ApiKey {
			action: ApiKeyCli::Create {
				expires_at,
				expires_in,
				..
			},
			..
		} => Ok(expires_at.or(expires_in)),
		other => panic!("expected api-key create, got {other:?}"),
	}
}

#[test]
fn the_epoch_form_of_expires_at_still_parses() {
	assert_eq!(
		parsed(&["--expires-at", "4102444800"]).expect("epoch"),
		Some(4_102_444_800)
	);
}

#[test]
fn expires_at_takes_a_date_and_expires_in_a_duration() {
	assert_eq!(
		parsed(&["--expires-at", "2100-01-01"]).expect("date"),
		Some(4_102_444_800)
	);
	let soon = parsed(&["--expires-in", "90d"])
		.expect("duration")
		.expect("set");
	let want = super::super::api_keys_expiry::now_secs() + 90 * 86_400;
	assert!(soon.abs_diff(want) < 60, "{soon} vs {want}");
}

#[test]
fn the_two_flags_exclude_each_other_and_junk_is_refused() {
	assert!(parsed(&["--expires-at", "2100-01-01", "--expires-in", "1d"]).is_err());
	assert!(parsed(&["--expires-in", "soon"]).is_err());
	assert!(parsed(&["--expires-at", "2001-01-01"]).is_err());
}

#[test]
fn list_prints_the_expiry_readable_and_json_keeps_the_epoch() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path());
	for (label, expires_at) in [("later", 4_102_444_800), ("gone", 1_700_000_000)] {
		let key = NewKey {
			label: label.to_string(),
			expires_at: Some(expires_at),
			scopes: vec!["read".to_string()],
			..NewKey::default()
		};
		let code = create(&config, key, false, &mut Vec::new(), &mut Vec::new());
		assert_eq!(code, ExitCode::SUCCESS);
	}
	let mut out = Vec::new();
	assert_eq!(
		list(&config, false, &mut out, &mut Vec::new()),
		ExitCode::SUCCESS
	);
	let text = String::from_utf8(out).expect("utf8");
	assert!(
		text.contains("later\texpires=2100-01-01T00:00:00Z\t"),
		"{text}"
	);
	assert!(
		text.contains("gone\texpires=2023-11-14T22:13:20Z (expired)\t"),
		"{text}"
	);
	let mut out = Vec::new();
	assert_eq!(
		list(&config, true, &mut out, &mut Vec::new()),
		ExitCode::SUCCESS
	);
	let rows: serde_json::Value = serde_json::from_slice(&out).expect("json");
	assert!(rows.to_string().contains("4102444800"), "{rows}");
}
