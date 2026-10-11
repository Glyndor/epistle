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
		assert_eq!(row["bind"], if name == "api" { "127.0.0.1" } else { "::" });
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
