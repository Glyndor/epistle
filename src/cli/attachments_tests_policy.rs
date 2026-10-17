//! `epistle attachments policy show|set|unset`: the exact output, what is
//! written, and what is refused.

use std::io::Write;
use std::process::ExitCode;

use super::{PolicyCli, PolicyKey, policy};
use crate::antispam::attachments::rules::ALWAYS_DANGEROUS;
use crate::cli::resource::ResourceError;

fn fixture(extra: &str) -> (tempfile::TempDir, std::path::PathBuf) {
	use std::os::unix::fs::PermissionsExt;
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("mail.toml");
	let mut file = std::fs::File::create(&path).unwrap();
	writeln!(
		file,
		"hostname = \"mail.example.org\"\ndata_dir = {:?}\ndomains = [\"example.org\"]\n{extra}",
		dir.path().canonicalize().unwrap().to_string_lossy()
	)
	.unwrap();
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
	(dir, path)
}

/// Run `action`; what it returned, what it printed on stdout and on the
/// status stream. A restart is never really run.
fn run(
	path: &std::path::Path,
	action: PolicyCli,
	dry_run: bool,
) -> (Result<ExitCode, String>, String, String) {
	run_with(path, action, (dry_run, false))
}

/// [`run`] with the command-level `--json` too.
fn run_with(
	path: &std::path::Path,
	action: PolicyCli,
	mode: (bool, bool),
) -> (Result<ExitCode, String>, String, String) {
	let (mut out, mut status) = (Vec::new(), Vec::new());
	let result = policy::execute(path, action, mode, &mut out, &mut status, |_, _| {
		panic!("no stack in a test")
	})
	.map_err(|error: ResourceError| error.to_string());
	(
		result,
		String::from_utf8(out).unwrap(),
		String::from_utf8(status).unwrap(),
	)
}

fn set(key: PolicyKey, values: &[&str]) -> PolicyCli {
	PolicyCli::Set {
		key,
		value: values.iter().map(|value| value.to_string()).collect(),
	}
}

fn section(path: &std::path::Path) -> toml::Value {
	let text = std::fs::read_to_string(path).unwrap();
	let config: toml::Value = toml::from_str(&text).unwrap();
	config
		.get("attachments")
		.cloned()
		.unwrap_or(toml::Value::Table(Default::default()))
}

#[test]
fn show_prints_every_key_in_effect() {
	let (_dir, path) =
		fixture("[attachments]\nmode = \"quarantine\"\nblock_extensions = [\".DOCM\"]\n");
	let (result, out, _) = run(&path, PolicyCli::Show { json: false }, false);
	assert_eq!(result, Ok(ExitCode::SUCCESS));
	assert_eq!(
		out,
		format!(
			"mode\tquarantine\nmacros\tflag\nencrypted-archives\tflag\nblock-extensions\tdocm\n\
			 allow-extensions\t(none)\nalways-dangerous\t{}\n",
			ALWAYS_DANGEROUS.join(",")
		)
	);
}

#[test]
fn show_json_is_one_object_with_lists_as_arrays() {
	let (_dir, path) = fixture("[attachments]\nallow_extensions = [\"svg\"]\n");
	let (result, out, _) = run(&path, PolicyCli::Show { json: true }, false);
	assert_eq!(result, Ok(ExitCode::SUCCESS));
	let value: serde_json::Value = serde_json::from_str(&out).expect("one JSON value");
	assert_eq!(
		value,
		serde_json::json!({
			"mode": "flag",
			"macros": "flag",
			"encrypted-archives": "flag",
			"block-extensions": [],
			"allow-extensions": ["svg"],
			"always-dangerous": ALWAYS_DANGEROUS,
		})
	);
	assert_eq!(out.lines().count(), 1);
}

#[test]
fn set_writes_the_key_and_asks_for_a_restart() {
	let (_dir, path) = fixture("");
	let (result, out, status) = run(&path, set(PolicyKey::Mode, &["Reject"]), false);
	assert_eq!(result, Ok(ExitCode::SUCCESS));
	assert_eq!(out, "");
	assert_eq!(
		status,
		"attachments mode set.\nThe server must be restarted.\n"
	);
	assert_eq!(
		section(&path).get("mode").and_then(toml::Value::as_str),
		Some("reject")
	);
	for (key, value, field) in [
		(PolicyKey::Macros, "allow", "macros"),
		(
			PolicyKey::EncryptedArchives,
			"quarantine",
			"encrypted_archives",
		),
	] {
		let (result, _, _) = run(&path, set(key, &[value]), false);
		assert_eq!(result, Ok(ExitCode::SUCCESS), "{field}");
		assert_eq!(
			section(&path).get(field).and_then(toml::Value::as_str),
			Some(value),
			"{field}"
		);
	}
}

#[test]
fn set_replaces_a_list_with_normalised_extensions() {
	let (_dir, path) = fixture("[attachments]\nblock_extensions = [\"docm\"]\n");
	let (result, _, _) = run(
		&path,
		set(PolicyKey::BlockExtensions, &[".XLSM", "pptm"]),
		false,
	);
	assert_eq!(result, Ok(ExitCode::SUCCESS));
	assert_eq!(
		section(&path).get("block_extensions"),
		Some(&toml::Value::Array(vec!["xlsm".into(), "pptm".into()]))
	);
}

#[test]
fn set_json_prints_one_result_object() {
	let (_dir, path) = fixture("");
	let set = |values: &[&str]| set(PolicyKey::AllowExtensions, values);
	let (result, out, status) = run_with(&path, set(&["SVG", ".svg"]), (false, true));
	assert_eq!(result, Ok(ExitCode::SUCCESS));
	let value: serde_json::Value = serde_json::from_str(&out).expect("one JSON value");
	assert_eq!(
		value,
		serde_json::json!({
			"result": "saved", "action": "set", "key": "allow-extensions",
			"value": ["svg"], "reload": "restart-needed",
		})
	);
	assert_eq!(out.lines().count(), 1, "one document");
	assert_eq!(
		status, "attachments allow-extensions set.\nThe server must be restarted.\n",
		"the notes stay on the status stream"
	);
	// The same value again changes nothing.
	let (_, out, _) = run_with(&path, set(&["svg"]), (false, true));
	let value: serde_json::Value = serde_json::from_str(&out).expect("one JSON value");
	assert_eq!(value["result"], "unchanged");
	assert_eq!(value["reload"], "none");
}

#[test]
fn a_scalar_key_reports_its_value() {
	let (_dir, path) = fixture("");
	let (_, out, _) = run_with(&path, set(PolicyKey::Mode, &["Reject"]), (false, true));
	let value: serde_json::Value = serde_json::from_str(&out).expect("one JSON value");
	assert_eq!(value["value"], "reject");
}

#[test]
fn unset_json_prints_one_result_object() {
	let (_dir, path) = fixture("[attachments]\nmode = \"reject\"\n");
	let unset = PolicyCli::Unset {
		key: PolicyKey::Mode,
	};
	let (result, out, _) = run_with(&path, unset, (false, true));
	assert_eq!(result, Ok(ExitCode::SUCCESS));
	let value: serde_json::Value = serde_json::from_str(&out).expect("one JSON value");
	assert_eq!(
		value,
		serde_json::json!({
			"result": "saved", "action": "unset", "key": "mode", "reload": "restart-needed",
		})
	);
}

#[test]
fn a_dry_run_with_json_carries_the_diff_and_writes_nothing() {
	let (_dir, path) = fixture("");
	let before = std::fs::read(&path).unwrap();
	let (result, out, status) = run_with(&path, set(PolicyKey::Mode, &["reject"]), (true, true));
	assert_eq!(result, Ok(ExitCode::SUCCESS));
	let value: serde_json::Value = serde_json::from_str(&out).expect("one JSON value");
	assert_eq!(value["result"], "dry-run");
	assert_eq!(value["action"], "set");
	assert!(
		value["diff"]
			.as_str()
			.is_some_and(|diff| diff.contains("reject")),
		"{value}"
	);
	assert_eq!(status, "");
	assert_eq!(std::fs::read(&path).unwrap(), before);
}

#[test]
fn a_refused_change_prints_nothing_on_stdout_under_json() {
	let (_dir, path) = fixture("");
	let (result, out, _) = run_with(&path, set(PolicyKey::Mode, &["delete"]), (false, true));
	assert!(result.is_err());
	assert_eq!(out, "");
}

#[test]
fn an_always_dangerous_extension_is_refused_and_nothing_is_written() {
	let (_dir, path) = fixture("");
	let before = std::fs::read(&path).unwrap();
	let (result, _, _) = run(
		&path,
		set(PolicyKey::AllowExtensions, &["svg", "url"]),
		false,
	);
	assert_eq!(
		result,
		Err("invalid configuration: [attachments] allow_extensions: url is always dangerous and cannot be allowed".to_string())
	);
	assert_eq!(std::fs::read(&path).unwrap(), before, "file untouched");
}

#[test]
fn bad_values_are_refused_with_the_accepted_ones() {
	let (_dir, path) = fixture("");
	for (action, expected) in [
		(
			set(PolicyKey::Mode, &["delete"]),
			"mode expected off, flag, quarantine or reject (got \"delete\")",
		),
		(
			set(PolicyKey::Macros, &["reject"]),
			"macros expected allow, flag or quarantine (got \"reject\")",
		),
		(
			set(PolicyKey::Mode, &["flag", "reject"]),
			"mode takes exactly one value (received 2)",
		),
		(
			set(PolicyKey::AllowExtensions, &["a/b"]),
			"allow-extensions: \"a/b\" is not an extension (letters, digits, - and _, up to 32)",
		),
		(
			set(PolicyKey::BlockExtensions, &["x\u{1b}[2J"]),
			"block-extensions: \"x\\u{1b}[2J\" is not an extension (letters, digits, - and _, up to 32)",
		),
	] {
		let (result, _, _) = run(&path, action, false);
		assert_eq!(result, Err(expected.to_string()));
	}
}

#[test]
fn unset_restores_the_default() {
	let (_dir, path) = fixture("[attachments]\nmode = \"reject\"\nallow_extensions = [\"svg\"]\n");
	let (result, _, status) = run(
		&path,
		PolicyCli::Unset {
			key: PolicyKey::Mode,
		},
		false,
	);
	assert_eq!(result, Ok(ExitCode::SUCCESS));
	assert_eq!(
		status,
		"attachments mode unset.\nThe server must be restarted.\n"
	);
	assert_eq!(section(&path).get("mode"), None);
	let (_, out, _) = run(&path, PolicyCli::Show { json: false }, false);
	assert!(out.starts_with("mode\tflag\n"), "the default is back");
	let (result, _, _) = run(
		&path,
		PolicyCli::Unset {
			key: PolicyKey::AllowExtensions,
		},
		false,
	);
	assert_eq!(result, Ok(ExitCode::SUCCESS));
	assert_eq!(section(&path).get("allow_extensions"), None);
}

#[test]
fn dry_run_prints_the_diff_and_writes_nothing() {
	let (_dir, path) = fixture("");
	let before = std::fs::read(&path).unwrap();
	let (result, out, status) = run(&path, set(PolicyKey::Mode, &["quarantine"]), true);
	assert_eq!(result, Ok(ExitCode::SUCCESS));
	assert!(
		out.contains("+[attachments]\n+mode = \"quarantine\"\n"),
		"{out}"
	);
	assert_eq!(status, "");
	assert_eq!(std::fs::read(&path).unwrap(), before);
}

#[test]
fn a_huge_extension_list_is_refused_in_linear_time() {
	let (_dir, path) = fixture("");
	let values: Vec<String> = (0..200_000).map(|n| format!("x{n}")).collect();
	let values: Vec<&str> = values.iter().map(String::as_str).collect();
	let started = std::time::Instant::now();
	let (result, _, _) = run(&path, set(PolicyKey::BlockExtensions, &values), false);
	assert_eq!(
		result,
		Err("block-extensions takes at most 256 extensions (received 200000)".to_string())
	);
	assert!(
		started.elapsed() < std::time::Duration::from_secs(2),
		"refused before any per-value work"
	);
}

#[test]
fn exactly_the_cap_is_accepted_and_written() {
	let (_dir, path) = fixture("");
	let values: Vec<String> = (0..256).map(|n| format!("x{n}")).collect();
	let values: Vec<&str> = values.iter().map(String::as_str).collect();
	let (result, _, _) = run(&path, set(PolicyKey::BlockExtensions, &values), false);
	assert!(result.is_ok(), "256 extensions are the loader's own limit");
	let written = section(&path);
	assert_eq!(
		written["block_extensions"].as_array().map(Vec::len),
		Some(256)
	);
}
