//! End-to-end integration tests for the RSA DKIM key step of `init`:
//! the key is made in process, so nothing on `PATH` decides whether
//! the run lands it. A broken `openssl` on `PATH` must not stop the
//! run, and the key that lands must be a PKCS#8 RSA key.
//! Lifted into a sibling so `init_end_to_end.rs` stays under the
//! per-file line limit.

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[path = "../../common/executable.rs"]
mod executable;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn binary() -> &'static Path {
	Path::new(env!("CARGO_BIN_EXE_epistle"))
}

fn write_answers(dir: &Path, name: &str, body: &str) -> PathBuf {
	let path = dir.join(name);
	std::fs::write(&path, body).expect("write answers");
	path
}

/// The answers an `init` run needs: a manual run with one domain and
/// no database.
fn answers_body(data_dir: &Path, config_path: &Path) -> String {
	format!(
		"mode = \"manual\"\n\
		 hostname = \"mail.example.org\"\n\
		 domains = [\"example.org\"]\n\
		 data_dir = \"{}\"\n\
		 config_path = \"{}\"\n\
		 image = \"localhost/epistle:dev\"\n\n\
		 [services]\n\
		 database = false\n",
		data_dir.display(),
		config_path.display(),
	)
}

/// A broken `openssl` on `PATH` must not stop the run: the RSA key is
/// made in process, so a shim that refuses every subcommand is
/// irrelevant. The run lands the key and the config names it.
#[cfg(unix)]
#[test]
fn init_writes_the_rsa_key_even_when_openssl_on_path_is_broken() {
	let dir = tempfile::tempdir().expect("tempdir");
	let shim_dir = dir.path().join("bin");
	std::fs::create_dir(&shim_dir).expect("mkdir shim dir");
	let shim_path = shim_dir.join("openssl");
	let shim_body = "#!/bin/sh\n\
		case \"$1\" in\n\
			version)\n\
				echo \"OpenSSL 99.9.9 (test shim)\"\n\
				exit 0\n\
				;;\n\
		*)\n\
			echo \"shim: $@ refused\" >&2\n\
			exit 1\n\
			;;\n\
		esac\n";
	executable::write_executable(&shim_path, shim_body);

	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("etc").join("mail.toml");
	std::fs::create_dir_all(config_path.parent().unwrap()).expect("mkdir etc");
	let answers = write_answers(
		dir.path(),
		"answers.toml",
		&answers_body(&data_dir, &config_path),
	);
	let system_path = std::env::var_os("PATH").unwrap_or_default();
	let combined_path = {
		let mut p = shim_dir.as_os_str().to_owned();
		if !system_path.is_empty() {
			p.push(":");
			p.push(&system_path);
		}
		p
	};
	let mut cmd = Command::new(binary());
	cmd.args(["init", "--answers", answers.to_str().unwrap()]);
	cmd.env("PATH", &combined_path);
	cmd.stdin(Stdio::null())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped());
	let output = cmd.output().expect("spawn epistle");
	assert!(
		output.status.success(),
		"a broken openssl on PATH must not stop the run; exit: {:?}; stderr: {}",
		output.status,
		String::from_utf8_lossy(&output.stderr)
	);
	let keys_dir = data_dir.join("keys");
	assert!(
		keys_dir.join("s2.pem").exists(),
		"s2.pem must be on disk: the key is made in process"
	);
	let rendered = std::fs::read_to_string(&config_path).expect("read config");
	assert!(
		rendered.contains("rsa_selector") && rendered.contains("rsa_key_file"),
		"the config must carry the RSA fields: {rendered}"
	);
}

/// The RSA key `init` writes is a PKCS#8 PEM the signer can load, and
/// it is owner-only from its first byte. The key is made in process, so
/// there is no external program whose output could be anything else.
#[cfg(unix)]
#[test]
fn the_rsa_key_init_writes_is_a_pkcs8_pem() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("etc").join("mail.toml");
	std::fs::create_dir_all(config_path.parent().unwrap()).expect("mkdir etc");
	let answers = write_answers(
		dir.path(),
		"answers.toml",
		&answers_body(&data_dir, &config_path),
	);
	let mut cmd = Command::new(binary());
	cmd.args(["init", "--answers", answers.to_str().unwrap()]);
	cmd.stdin(Stdio::null())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped());
	let output = cmd.output().expect("spawn epistle");
	assert!(
		output.status.success(),
		"the run must succeed; exit: {:?}; stderr: {}",
		output.status,
		String::from_utf8_lossy(&output.stderr)
	);
	let s2 = data_dir.join("keys").join("s2.pem");
	let pem = std::fs::read_to_string(&s2).expect("read s2.pem");
	assert!(
		pem.starts_with("-----BEGIN PRIVATE KEY-----\n"),
		"s2.pem must be a PKCS#8 PEM: {pem}"
	);
	let mode = std::fs::metadata(&s2)
		.expect("stat s2.pem")
		.permissions()
		.mode();
	assert_eq!(
		mode & 0o777,
		0o600,
		"the key must be owner-only, got {mode:o}"
	);
	let body: String = pem
		.lines()
		.filter(|line| !line.starts_with("-----"))
		.collect::<Vec<_>>()
		.join("");
	assert!(
		!body.is_empty()
			&& body
				.bytes()
				.all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'='),
		"the PEM body must be base64: {body}"
	);
}
