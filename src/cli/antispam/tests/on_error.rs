//! `epistle antispam set|unset|show clamd-on-error`.

use std::io::Write;

use super::*;
use crate::cli::config_edit::ConfigDocument;
use crate::config::{ClamdOnError, Config};

fn fixture(extra: &str) -> (tempfile::TempDir, std::path::PathBuf) {
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("mail.toml");
	let mut file = std::fs::File::create(&path).unwrap();
	writeln!(
		file,
		"hostname = \"mail.example.org\"\ndata_dir = {:?}\ndomains = [\"example.org\"]\n{extra}",
		dir.path().canonicalize().unwrap().to_string_lossy()
	)
	.unwrap();
	use std::os::unix::fs::PermissionsExt;
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
	(dir, path)
}

fn shown(config: &Config) -> String {
	let mut out = Vec::new();
	show_keys(config, &mut out).expect("show");
	String::from_utf8(out)
		.unwrap()
		.lines()
		.find(|line| line.starts_with("clamd-on-error\t"))
		.expect("a clamd-on-error row")
		.to_string()
}

#[test]
fn set_unset_and_show_clamd_on_error() {
	let (_dir, path) = fixture("");
	let config = Config::load(&path).unwrap();
	assert_eq!(shown(&config), "clamd-on-error\taccept\tset");
	assert_eq!(
		show::show_json(&config)["clamd-on-error"],
		serde_json::json!({ "value": "accept", "source": "set" })
	);
	let mut document = ConfigDocument::open(&path).unwrap();
	apply_set(&mut document, Key::ClamdOnError, &["Defer".to_string()]).expect("set");
	document.commit().expect("commit");
	let config = Config::load(&path).unwrap();
	assert_eq!(config.antispam.clamd_on_error, ClamdOnError::Defer);
	assert_eq!(shown(&config), "clamd-on-error\tdefer\tset");
	let mut document = ConfigDocument::open(&path).unwrap();
	apply_unset(&mut document, Key::ClamdOnError).expect("unset");
	document.commit().expect("commit");
	let text = std::fs::read_to_string(&path).unwrap();
	assert!(!text.contains("clamd_on_error"), "{text}");
}

#[test]
fn set_refuses_anything_but_accept_or_defer() {
	let (_dir, path) = fixture("");
	let mut document = ConfigDocument::open(&path).unwrap();
	assert_eq!(
		apply_set(&mut document, Key::ClamdOnError, &["drop".to_string()]),
		Err("clamd-on-error expected accept or defer (got \"drop\")".to_string())
	);
}
