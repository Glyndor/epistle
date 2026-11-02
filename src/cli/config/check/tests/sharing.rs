//! `config-check` on keys shared between domains: two domains on the
//! `[dkim]` key warn, a copy of one key under two names fails.

use std::io::Write;
use std::process::ExitCode;

fn check(text: &str, json: bool) -> (ExitCode, String, String) {
	let mut file = tempfile::NamedTempFile::new().expect("temp file");
	file.write_all(text.as_bytes()).expect("write");
	let mut out = Vec::new();
	let mut err = Vec::new();
	let code = crate::cli::config::check::tests::run(file.path(), json, &mut out, &mut err);
	(
		code,
		String::from_utf8_lossy(&out).into_owned(),
		String::from_utf8_lossy(&err).into_owned(),
	)
}

fn key(dir: &std::path::Path, name: &str) -> std::path::PathBuf {
	let (pem, _) = crate::dkim::generate_key().expect("key");
	let path = dir.join(name);
	std::fs::write(&path, pem).expect("write");
	path
}

#[test]
fn two_domains_on_the_default_key_warn_and_still_pass() {
	let dir = tempfile::tempdir().expect("dir");
	let default = key(dir.path(), "default.pem");
	let (code, _, err) = check(
		&format!(
			"hostname = 'mail.example.org'\ndata_dir = {:?}\ndomains = ['a.example', 'b.example']\n\
			 [dkim]\nselector = 's1'\nkey_file = {default:?}\n",
			dir.path()
		),
		false,
	);
	assert_eq!(code, ExitCode::SUCCESS, "{err}");
	assert!(
		err.contains("2 domains sign with the one [dkim] key (a.example, b.example)"),
		"{err}"
	);
}

#[test]
fn the_warning_is_in_the_json_result() {
	let dir = tempfile::tempdir().expect("dir");
	let default = key(dir.path(), "default.pem");
	let (code, out, _) = check(
		&format!(
			"hostname = 'mail.example.org'\ndata_dir = {:?}\ndomains = ['a.example', 'b.example']\n\
			 [dkim]\nselector = 's1'\nkey_file = {default:?}\n",
			dir.path()
		),
		true,
	);
	assert_eq!(code, ExitCode::SUCCESS);
	assert!(
		out.contains("domains sign with the one [dkim] key"),
		"{out}"
	);
}

#[test]
fn one_domain_per_key_is_quiet() {
	let dir = tempfile::tempdir().expect("dir");
	let default = key(dir.path(), "default.pem");
	let own = key(dir.path(), "b.pem");
	let (code, _, err) = check(
		&format!(
			"hostname = 'mail.example.org'\ndata_dir = {:?}\ndomains = ['a.example', 'b.example']\n\
			 [dkim]\nselector = 's1'\nkey_file = {default:?}\n\
			 [[dkim.domain]]\nname = 'b.example'\nselector = 's1'\nkey_file = {own:?}\n",
			dir.path()
		),
		false,
	);
	assert_eq!(code, ExitCode::SUCCESS, "{err}");
	assert!(!err.contains("sign with the one"), "{err}");
}

#[test]
fn a_copy_of_the_default_key_under_another_name_fails() {
	let dir = tempfile::tempdir().expect("dir");
	let default = key(dir.path(), "default.pem");
	let copy = dir.path().join("copy.pem");
	std::fs::copy(&default, &copy).expect("copy");
	let (code, _, err) = check(
		&format!(
			"hostname = 'mail.example.org'\ndata_dir = {:?}\ndomains = ['a.example', 'b.example']\n\
			 [dkim]\nselector = 's1'\nkey_file = {default:?}\n\
			 [[dkim.domain]]\nname = 'b.example'\nselector = 's1'\nkey_file = {copy:?}\n",
			dir.path()
		),
		false,
	);
	assert_eq!(code, ExitCode::FAILURE);
	assert!(err.contains("the same ed25519 public key"), "{err}");
}
