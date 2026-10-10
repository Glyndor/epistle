use std::ffi::CString;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

#[path = "backup.rs"]
mod backup;
#[path = "mail.rs"]
mod mail;

fn special(path: &Path, kind: &str, outside: &Path) {
	match kind {
		"symlink" | "directory-link" | "broken-link" => symlink(outside, path).unwrap(),
		"socket" | "fifo" => {
			let name = CString::new(path.as_os_str().as_bytes()).unwrap();
			let mode = if kind == "socket" {
				libc::S_IFSOCK
			} else {
				libc::S_IFIFO
			};
			// SAFETY: name is a NUL-terminated path, and mknod needs no device number here.
			let rc = unsafe { libc::mknod(name.as_ptr(), mode | 0o600, 0) };
			assert_eq!(rc, 0, "special-file fixture must be created");
		}
		_ => unreachable!(),
	}
}

fn config(root: &Path, data: &Path) -> PathBuf {
	let path = root.join("mail.toml");
	std::fs::write(
		&path,
		format!(
			"hostname = \"mail.example.org\"\ndata_dir = \"{}\"\n",
			data.display()
		),
	)
	.unwrap();
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
	path
}

fn run(args: &[&str]) -> Option<Output> {
	let mut child = Command::new(env!("CARGO_BIN_EXE_epistle"))
		.args(args)
		.env("NO_COLOR", "1")
		.stdout(Stdio::piped())
		.stderr(Stdio::piped())
		.spawn()
		.unwrap();
	let started = Instant::now();
	loop {
		if child.try_wait().unwrap().is_some() {
			return Some(child.wait_with_output().unwrap());
		}
		if started.elapsed() > Duration::from_secs(2) {
			child.kill().unwrap();
			child.wait().unwrap();
			return None;
		}
		std::thread::sleep(Duration::from_millis(10));
	}
}

fn archive_names(bytes: &[u8]) -> Vec<String> {
	let mut tar = Vec::new();
	flate2::read::GzDecoder::new(bytes)
		.read_to_end(&mut tar)
		.unwrap();
	let mut names = Vec::new();
	let mut offset = 0;
	while offset + 512 <= tar.len() && tar[offset] != 0 {
		let header = &tar[offset..offset + 512];
		let name = header[..100].split(|b| *b == 0).next().unwrap();
		names.push(String::from_utf8(name.to_vec()).unwrap());
		let size = std::str::from_utf8(&header[124..136])
			.unwrap()
			.trim_matches('\0')
			.trim();
		let size = usize::from_str_radix(size, 8).unwrap();
		offset += 512 + size.div_ceil(512) * 512;
	}
	names
}

fn assert_warning_once(output: &Output, path: &Path) {
	let warning = format!("skipping non-regular data path {}", path.display());
	assert_eq!(
		String::from_utf8_lossy(&output.stderr)
			.matches(&warning)
			.count(),
		1,
		"each skipped path must produce exactly one warning"
	);
}

#[path = "reports.rs"]
mod reports;
