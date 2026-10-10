//! Shared helpers for every `init_end_to_end` integration test.
//! The binary path, the answers-file builder, the openssl-on-PATH
//! probe, the plan-output parser, the file-mode helpers, and the
//! data-dir-clean assertion every interactive test reaches for all
//! live here so each topic split pulls from one place.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub fn binary() -> &'static Path {
	Path::new(env!("CARGO_BIN_EXE_epistle"))
}

pub fn write_answers(dir: &Path, name: &str, body: &str) -> PathBuf {
	let path = dir.join(name);
	std::fs::write(&path, body).expect("write answers");
	path
}

pub fn make_answers_body(data_dir: &Path, config_path: &Path) -> String {
	format!(
		"mode = \"manual\"\n\
		 hostname = \"mail.example.org\"\n\
		 domains = [\"example.org\"]\n\
		 public_ipv4 = \"8.8.8.8\"\n\
		 data_dir = \"{}\"\n\
		 config_path = \"{}\"\n\n\
		 [services]\n\
		 database = false\n",
		data_dir.display(),
		config_path.display(),
	)
}

pub fn openssl_on_path() -> bool {
	Command::new("openssl")
		.arg("version")
		.stdin(Stdio::null())
		.stdout(Stdio::null())
		.stderr(Stdio::null())
		.status()
		.map(|status| status.success())
		.unwrap_or(false)
}

pub fn plan_paths(stderr: &str) -> Vec<String> {
	let mut paths = Vec::new();
	for line in stderr.lines() {
		let Some(idx) = line.find("generate ") else {
			continue;
		};
		let rest = &line[idx + "generate ".len()..];
		// The pair step renders as "generate <cert> (and <key>)"; pull
		// both paths out so the test can match them as a set.
		if let Some(and_idx) = rest.find(" (and ") {
			let cert = rest[..and_idx].trim();
			let key_part = &rest[and_idx + " (and ".len()..];
			let key = key_part.trim_end_matches(')').trim();
			paths.push(cert.to_string());
			paths.push(key.to_string());
		} else {
			paths.push(rest.trim().to_string());
		}
	}
	paths
}

#[cfg(unix)]
pub fn sha256_of(path: &Path) -> Vec<u8> {
	let bytes = std::fs::read(path).expect("read");
	ring::digest::digest(&ring::digest::SHA256, &bytes)
		.as_ref()
		.to_vec()
}

#[cfg(unix)]
pub fn mtime(path: &Path) -> std::time::SystemTime {
	std::fs::metadata(path)
		.expect("metadata")
		.modified()
		.expect("mtime")
}

#[cfg(unix)]
pub fn mode(path: &Path) -> u32 {
	use std::os::unix::fs::PermissionsExt;
	std::fs::metadata(path)
		.expect("metadata")
		.permissions()
		.mode()
		& 0o777
}

/// The operator sees a single confirmation prompt when every
/// answer is valid; if the interactive run aborted before writing
/// anything, the data_dir (and its keys) must not exist.
#[cfg(unix)]
pub fn data_dir_is_clean(dir: &Path) {
	let data_dir = dir.join("data");
	assert!(
		!data_dir.exists(),
		"data_dir must not be created when the interactive run aborted: {}",
		data_dir.display()
	);
}
