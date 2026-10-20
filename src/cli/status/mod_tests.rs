//! Tests for the status runner: exit codes, the table and the JSON shape.

use std::process::ExitCode;

use super::report::{AreaReport, Item, Level, any_failed, render_json, render_table};
use super::{CheckArea, execute};

fn write_config(dir: &std::path::Path, body: &str) -> std::path::PathBuf {
	let path = dir.join("mail.toml");
	std::fs::write(&path, body).expect("write config");
	std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600))
		.expect("chmod config");
	path
}

fn valid(dir: &std::path::Path) -> std::path::PathBuf {
	write_config(
		dir,
		&format!(
			"hostname = \"mail.example.org\"\ndata_dir = {:?}\n",
			dir.display().to_string()
		),
	)
}

#[test]
fn status_prints_one_line_per_area_and_exits_zero_when_nothing_fails() {
	let dir = tempfile::tempdir().expect("tempdir");
	let path = valid(dir.path());
	let mut out = Vec::new();
	let code = execute(&path, &[CheckArea::Config], false, false, &mut out);
	let text = String::from_utf8(out).expect("utf8");
	let first = text.lines().next().expect("a line");
	assert!(first.starts_with("config     ok    "), "line was: {first}");
	assert_eq!(text.lines().count(), 1, "{text}");
	assert_eq!(code, ExitCode::SUCCESS);
}

#[test]
fn status_exits_one_and_reports_fail_when_the_config_does_not_load() {
	let dir = tempfile::tempdir().expect("tempdir");
	let path = write_config(dir.path(), "this is not toml = = =");
	let mut out = Vec::new();
	let code = execute(&path, &[CheckArea::Config], false, false, &mut out);
	let text = String::from_utf8(out).expect("utf8");
	assert!(
		text.lines()
			.next()
			.expect("a line")
			.starts_with("config     fail  "),
		"output was: {text}"
	);
	assert_eq!(code, ExitCode::FAILURE);
}

#[test]
fn json_has_an_entry_per_area_with_status_detail_and_items() {
	let dir = tempfile::tempdir().expect("tempdir");
	let path = valid(dir.path());
	let mut out = Vec::new();
	execute(&path, &[CheckArea::Config], true, false, &mut out);
	let value: serde_json::Value = serde_json::from_slice(&out).expect("valid JSON");
	let config = &value["config"];
	assert_eq!(config["status"], "ok", "{value}");
	assert!(
		config["detail"]
			.as_str()
			.is_some_and(|d| d.contains("mail.toml"))
	);
	assert_eq!(config["items"][0]["name"], "restart", "{value}");
	assert_eq!(value.as_object().expect("object").len(), 1);
}

#[test]
fn json_includes_api_keys_without_exposing_the_stored_hash() {
	let dir = tempfile::tempdir().expect("tempdir");
	let path = valid(dir.path());
	std::fs::write(
		dir.path().join("api_keys.toml"),
		"[[keys]]\nlabel = \"automation\"\nhash = \"sha256:private-digest\"\nscopes = [\"read\"]\n",
	)
	.expect("key store");
	let mut out = Vec::new();
	let code = execute(&path, &[CheckArea::ApiKeys], true, false, &mut out);
	let output = String::from_utf8(out).expect("utf8");
	let value: serde_json::Value = serde_json::from_str(&output).expect("valid JSON");
	assert_eq!(value["api_keys"]["status"], "warn", "{output}");
	assert_eq!(value["api_keys"]["items"][0]["name"], "automation (read)");
	assert!(output.contains("no expiry"));
	assert!(!output.contains("private-digest"));
	assert_eq!(code, ExitCode::SUCCESS);
}

#[test]
fn a_warning_alone_does_not_fail_the_run() {
	let reports = vec![(
		CheckArea::Config,
		AreaReport::single(Level::Warn, "careful"),
	)];
	assert!(!any_failed(&reports));
	let reports = vec![(CheckArea::Config, AreaReport::fail("broken"))];
	assert!(any_failed(&reports));
}

#[test]
fn the_area_status_is_the_worst_item_status() {
	let report = AreaReport::from_items(
		vec![
			Item::new("a", Level::Ok, "fine"),
			Item::new("b", Level::Warn, "meh"),
		],
		"summary",
	);
	assert_eq!(report.status, Level::Warn);
	let report = AreaReport::from_items(
		vec![
			Item::new("a", Level::Fail, "bad"),
			Item::new("b", Level::Warn, "meh"),
		],
		"summary",
	);
	assert_eq!(report.status, Level::Fail);
}

#[test]
fn check_lists_items_under_the_area_line_and_status_does_not() {
	let reports = vec![(
		CheckArea::Config,
		AreaReport::from_items(vec![Item::new("smtp", Level::Warn, "slow")], "1 warning"),
	)];
	let mut detailed = Vec::new();
	render_table(&reports, true, None, &mut detailed).expect("render");
	let detailed = String::from_utf8(detailed).expect("utf8");
	assert_eq!(detailed, "config     warn  1 warning\n  warn  smtp: slow\n");
	let mut compact = Vec::new();
	render_table(&reports, false, None, &mut compact).expect("render");
	assert_eq!(
		String::from_utf8(compact).expect("utf8"),
		"config     warn  1 warning\n"
	);
	let mut json = Vec::new();
	render_json(&reports, &mut json).expect("render");
	let value: serde_json::Value = serde_json::from_slice(&json).expect("json");
	assert_eq!(value["config"]["items"][0]["name"], "smtp");
}

#[test]
fn status_covers_every_area_in_a_stable_order() {
	let names: Vec<_> = CheckArea::ALL.iter().map(|area| area.name()).collect();
	assert_eq!(
		clap::ValueEnum::from_str("api_keys", false),
		Ok(CheckArea::ApiKeys)
	);
	assert_eq!(
		names,
		[
			"config",
			"ports",
			"tls",
			"dns",
			"db",
			"api_keys",
			"antivirus",
			"antispam",
			"queue",
			"disk",
			"spool",
			"subid",
			"warmup",
			"resources",
			"clock",
			"evidence"
		]
	);
}
