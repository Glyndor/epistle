use std::path::Path;
use std::process::{Command, Output};

fn run(config: &Path, args: &[&str]) -> Output {
	Command::new(env!("CARGO_BIN_EXE_epistle"))
		.args(["service", "--config", config.to_str().unwrap()])
		.args(args)
		.output()
		.unwrap()
}

pub(super) fn fixture() -> (tempfile::TempDir, std::path::PathBuf) {
	let dir = tempfile::tempdir().unwrap();
	let config = dir.path().join("mail.toml");
	let content = format!(
		"hostname = \"mail.example.org\"\ndomains = [\"example.org\"]\ndata_dir = {:?}\n[tls]\ncert_file = \"/cert.pem\"\nkey_file = \"/key.pem\"\n[[listeners]]\nkind = \"smtp\"\naddr = \"::\"\n[[listeners]]\nkind = \"imaps\"\naddr = \"::\"\nport = 19993\n",
		dir.path().to_str().unwrap()
	);
	std::fs::write(&config, content).unwrap();
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
	}
	(dir, config)
}

#[test]
fn service_cli_host_round_trip() {
	let (_dir, config) = fixture();
	let output = run(&config, &["enable", "imap"]);
	assert_eq!(
		output.status.code(),
		Some(0),
		"service enable must succeed on a host config"
	);
	assert_eq!(
		String::from_utf8(output.stderr).unwrap(),
		"imap enabled.\nThe server must be restarted.\n"
	);
	let cfg = epistle::config::Config::load(&config).unwrap();
	assert_eq!(
		cfg.listeners.len(),
		3,
		"CLI enable must add only the selected listener"
	);
	let before = std::fs::read(&config).unwrap();
	let noop = run(&config, &["enable", "imap"]);
	assert_eq!(noop.status.code(), Some(0));
	assert_eq!(
		String::from_utf8(noop.stderr).unwrap(),
		"imap is already enabled; nothing changed.\n"
	);
	assert!(
		std::fs::read(&config).unwrap() == before,
		"CLI no-op must preserve bytes"
	);
	let output = run(&config, &["disable", "imap"]);
	assert_eq!(output.status.code(), Some(0));
	assert_eq!(
		epistle::config::Config::load(&config)
			.unwrap()
			.listeners
			.len(),
		2
	);
	let smtp = run(&config, &["disable", "smtp"]);
	assert_eq!(smtp.status.code(), Some(1));
	assert!(
		String::from_utf8(smtp.stderr)
			.unwrap()
			.contains("smtp cannot be disabled: inbound mail needs it")
	);
}

#[test]
fn service_cli_lists_real_sockets_and_every_name() {
	let (_dir, config) = fixture();
	let output = run(&config, &["list", "--json"]);
	assert_eq!(
		output.status.code(),
		Some(0),
		"service list --json must succeed"
	);
	let rows: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
	let rows = rows.as_array().unwrap();
	assert_eq!(
		rows.len(),
		9,
		"list must include SMTP and all eight optional services"
	);
	for (name, port) in [
		("smtp", 25),
		("imap", 143),
		("imaps", 19993),
		("submission", 587),
		("submissions", 465),
		("pop3", 995),
		("managesieve", 4190),
		("webdav", 8090),
		("api", 8025),
	] {
		let row = rows.iter().find(|row| row["name"] == name).unwrap();
		assert_eq!(
			row["port"], port,
			"list must resolve configured and default ports"
		);
		assert_eq!(row["enabled"], name == "smtp" || name == "imaps");
		assert_eq!(
			row["bind"],
			if name == "api" || name == "webdav" {
				"127.0.0.1"
			} else {
				"::"
			},
			"a listener with no TLS transport is listed on loopback"
		);
	}
	let table = run(&config, &["list"]);
	assert_eq!(table.status.code(), Some(0));
	let text = String::from_utf8(table.stdout).unwrap();
	assert_eq!(
		text.lines().next(),
		Some("SERVICE       STATE     PORT   BIND")
	);
	assert!(
		text.lines()
			.any(|line| line.split_whitespace().collect::<Vec<_>>()
				== ["imaps", "enabled", "19993", "::"]),
		"table must show the configured IMAPS socket"
	);
}

/// A configuration with one API listener on loopback, plus whatever `extra`
/// carries, next to `dir`'s own mail.toml.
fn api_fixture(dir: &tempfile::TempDir, extra: &str) -> std::path::PathBuf {
	let config = dir.path().join("api.toml");
	let body = format!(
		"hostname = \"mail.example.org\"\ndomains = [\"example.org\"]\ndata_dir = {:?}\n{extra}\n[api]\ntoken_hash = \"sha256:0000000000000000000000000000000000000000000000000000000000000000\"\n[[listeners]]\nkind = \"smtp\"\naddr = \"0.0.0.0\"\n[[listeners]]\nkind = \"api\"\naddr = \"127.0.0.1\"\n",
		dir.path().join("data").to_str().unwrap()
	);
	std::fs::write(&config, body).unwrap();
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).expect("chmod");
	}
	config
}

#[test]
fn service_set_moves_an_enabled_listener_and_leaves_the_rest_alone() {
	let (dir, config) = fixture();
	let output = run(
		&config,
		&["set", "imaps", "--bind", "127.0.0.1", "--port", "11993"],
	);
	assert_eq!(
		output.status.code(),
		Some(0),
		"a free socket must be accepted: {}",
		String::from_utf8_lossy(&output.stderr)
	);
	assert_eq!(
		String::from_utf8(output.stderr).unwrap(),
		"imaps set to 127.0.0.1:11993.\nThe server must be restarted.\n"
	);
	let cfg = epistle::config::Config::load(&config).unwrap();
	assert_eq!(cfg.listeners.len(), 2, "set moves a listener, it adds none");
	assert_eq!(cfg.listeners[0].kind.as_str(), "smtp", "smtp is untouched");
	let imaps = &cfg.listeners[1];
	assert_eq!(imaps.kind.as_str(), "imaps");
	assert_eq!(imaps.addr.to_string(), "127.0.0.1");
	assert_eq!(imaps.socket_addr().port(), 11993);
	let raw = std::fs::read_to_string(&config).unwrap();
	assert!(
		raw.contains("[tls]") && raw.contains("cert_file"),
		"the edit must preserve the sections around it: {raw}"
	);
	assert!(
		!dir.path().join("compose").exists(),
		"a host install must not grow a container stack"
	);
}

#[test]
fn service_set_refuses_what_it_can_not_do() {
	let (_dir, config) = fixture();
	let before = std::fs::read_to_string(&config).unwrap();
	for (args, expected) in [
		(
			&["set", "imap", "--bind", "127.0.0.1"][..],
			"imap is not enabled: run `epistle service enable imap` first",
		),
		(
			&["set", "imaps", "--port", "0"][..],
			"port 0 is not a listener port: pick one between 1 and 65535",
		),
		(
			&["set", "imaps", "--port", "25"][..],
			"port 25 is already used by smtp on [::]:25",
		),
		(
			&["set", "imaps"][..],
			"nothing to change: pass --bind, --port, or both",
		),
	] {
		let output = run(&config, args);
		assert_eq!(output.status.code(), Some(1), "{args:?}");
		let stderr = String::from_utf8(output.stderr).unwrap();
		assert!(stderr.contains(expected), "{args:?} said {stderr:?}");
		assert_eq!(
			std::fs::read_to_string(&config).unwrap(),
			before,
			"{args:?} must leave every byte alone"
		);
	}
}

#[test]
fn service_set_refuses_an_address_that_is_not_one() {
	let (_dir, config) = fixture();
	let output = run(
		&config,
		&["set", "imaps", "--bind", "127.0.0.1.example.org"],
	);
	assert_eq!(
		output.status.code(),
		Some(2),
		"an address the parser refuses never reaches the command"
	);
	let stderr = String::from_utf8(output.stderr).unwrap();
	assert!(stderr.contains("--bind"), "{stderr}");
	assert!(
		!stderr.contains("already"),
		"nothing may be reported as done after a parse error: {stderr}"
	);
	let imaps = &epistle::config::Config::load(&config).unwrap().listeners[1];
	assert_eq!(imaps.addr.to_string(), "::", "the listener keeps its bind");
	assert_eq!(imaps.socket_addr().port(), 19993);
}

#[test]
fn service_set_keeps_http_on_loopback_with_or_without_mail_certificates() {
	let dir = tempfile::tempdir().unwrap();
	for extra in [
		"",
		"[tls]\ncert_file = \"/cert.pem\"\nkey_file = \"/key.pem\"\n",
	] {
		let config = api_fixture(&dir, extra);
		let before = std::fs::read(&config).unwrap();
		let output = run(&config, &["set", "api", "--bind", "10.0.0.5"]);
		assert_eq!(output.status.code(), Some(1));
		assert!(String::from_utf8_lossy(&output.stderr).contains("serves HTTP without TLS"));
		assert_eq!(std::fs::read(&config).unwrap(), before);
		let output = run(&config, &["set", "api", "--bind", "::1"]);
		assert_eq!(output.status.code(), Some(0));
		assert_eq!(
			epistle::config::Config::load(&config).unwrap().listeners[1]
				.addr
				.to_string(),
			"::1"
		);
	}
}

#[test]
fn service_set_says_nothing_changed_when_it_is_asked_for_the_same_thing() {
	let (_dir, config) = fixture();
	assert_eq!(
		run(
			&config,
			&["set", "imaps", "--bind", "10.0.0.9", "--port", "11993"]
		)
		.status
		.code(),
		Some(0)
	);
	let bytes = std::fs::read(&config).unwrap();
	let modified = std::fs::metadata(&config).unwrap().modified().unwrap();
	let again = run(
		&config,
		&["set", "imaps", "--bind", "10.0.0.9", "--port", "11993"],
	);
	assert_eq!(again.status.code(), Some(0));
	assert_eq!(
		String::from_utf8(again.stderr).unwrap(),
		"imaps is already set to 10.0.0.9:11993; nothing changed.\n"
	);
	assert_eq!(
		std::fs::read(&config).unwrap(),
		bytes,
		"a no-op preserves bytes"
	);
	assert_eq!(
		std::fs::metadata(&config).unwrap().modified().unwrap(),
		modified,
		"a no-op does not replace the file"
	);
	assert_eq!(
		run(&config, &["set", "imaps"]).status.code(),
		Some(1),
		"a command with nothing to change is a refusal"
	);
}
