//! `account add --display-name`, `account set-name`, and the display name in
//! `account show` / `account list --json`: kept as written, cleared by an
//! empty name, refused with a line break.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output, Stdio};

const PASSWORD: &[u8] = b"Zq8!vT3#mL0@pW6$\n";

fn epistle(args: &[&str], stdin: &[u8]) -> Output {
	let mut child = Command::new(env!("CARGO_BIN_EXE_epistle"))
		.args(args)
		.env("NO_COLOR", "1")
		.stdin(Stdio::piped())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped())
		.spawn()
		.expect("spawn epistle");
	child
		.stdin
		.take()
		.expect("stdin")
		.write_all(stdin)
		.expect("write stdin");
	child.wait_with_output().expect("wait epistle")
}

fn config(dir: &Path) -> String {
	let path = dir.join("mail.toml");
	std::fs::create_dir(dir.join("data")).expect("data dir");
	std::fs::write(
		&path,
		format!(
			"hostname = \"mail.example.org\"\ndata_dir = {:?}\ndomains = [\"example.org\"]\n\n\
			 [[accounts]]\nname = \"carol\"\naddresses = [\"carol@example.org\"]\n\
			 display_name = \"Carol from the config\"\n",
			dir.join("data")
		),
	)
	.expect("write config");
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
	path.to_string_lossy().into_owned()
}

fn text(bytes: &[u8]) -> String {
	String::from_utf8_lossy(bytes).into_owned()
}

fn show_json(config: &str, name: &str) -> serde_json::Value {
	let shown = epistle(
		&["account", "--config", config, "show", name, "--json"],
		b"",
	);
	assert!(shown.status.success(), "{}", text(&shown.stderr));
	serde_json::from_slice(&shown.stdout).expect("json")
}

#[test]
fn set_show_and_clear_a_display_name() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path());
	let added = epistle(
		&[
			"account",
			"--config",
			&config,
			"add",
			"ana",
			"--address",
			"ana@example.org",
			"--display-name",
			"  Ana MARÍA Núñez ",
		],
		PASSWORD,
	);
	assert!(added.status.success(), "{}", text(&added.stderr));
	assert_eq!(show_json(&config, "ana")["display_name"], "Ana MARÍA Núñez");
	let shown = epistle(&["account", "--config", &config, "show", "ana"], b"");
	assert!(
		text(&shown.stdout).contains("\ndisplay_name: Ana MARÍA Núñez\n"),
		"{}",
		text(&shown.stdout)
	);

	let set = epistle(
		&["account", "--config", &config, "set-name", "ana", "Ana Ñ"],
		b"",
	);
	assert_eq!(text(&set.stdout), "display name of ana set to \"Ana Ñ\"\n");
	let list = epistle(&["account", "--config", &config, "list", "--json"], b"");
	let rows: serde_json::Value = serde_json::from_slice(&list.stdout).expect("json");
	assert_eq!(rows[0]["name"], "ana");
	assert_eq!(rows[0]["display_name"], "Ana Ñ");
	assert_eq!(rows[1]["display_name"], "Carol from the config");

	let cleared = epistle(
		&["account", "--config", &config, "set-name", "ana", ""],
		b"",
	);
	assert_eq!(text(&cleared.stdout), "display name of ana cleared\n");
	assert_eq!(
		show_json(&config, "ana")["display_name"],
		serde_json::Value::Null
	);
}

#[test]
fn a_line_break_in_a_display_name_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path());
	let refused = epistle(
		&[
			"account",
			"--config",
			&config,
			"add",
			"bob",
			"--address",
			"bob@example.org",
			"--display-name",
			"Bob\r\nBcc: x@example.net",
		],
		PASSWORD,
	);
	assert!(!refused.status.success());
	assert_eq!(
		text(&refused.stderr),
		"error: account bob: the display name must not contain control characters or line breaks\n"
	);
	assert_eq!(
		show_json(&config, "carol")["display_name"],
		"Carol from the config"
	);
}
