use super::*;
use std::cell::RefCell;
use std::fs::Permissions;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

/// Records every hand-over to the account instead of changing owners, so
/// the staging runs without root.
#[derive(Default)]
struct Owner(RefCell<Vec<(PathBuf, u32)>>);

impl Owner {
	fn chown(&self) -> impl Fn(&File, &Path) -> io::Result<()> + '_ {
		|file, rel| {
			let mode = file.metadata()?.permissions().mode() & 0o7777;
			self.0.borrow_mut().push((rel.to_path_buf(), mode));
			Ok(())
		}
	}

	fn handed(&self) -> Vec<(PathBuf, u32)> {
		self.0.borrow().clone()
	}
}

/// The account's uid in these tests: this process plays the account and
/// writes the outputs.
fn me() -> u32 {
	// SAFETY: geteuid takes no arguments and cannot fail.
	unsafe { libc::geteuid() }
}

fn os(list: &[&str]) -> Vec<OsString> {
	list.iter().map(OsString::from).collect()
}

fn imap(extra: &[&str]) -> Vec<OsString> {
	let mut line = os(&[
		"migrate",
		"imap",
		"--account",
		"alice",
		"--host",
		"imap.example.org",
		"--user",
		"alice",
	]);
	line.extend(os(extra));
	line
}

fn mode(path: &Path) -> u32 {
	fs::symlink_metadata(path).unwrap().permissions().mode() & 0o7777
}

fn entries(dir: &Path) -> Vec<PathBuf> {
	fs::read_dir(dir)
		.unwrap()
		.map(|entry| entry.unwrap().path())
		.collect()
}

fn write(path: &Path, text: &str, mode: u32) {
	fs::create_dir_all(path.parent().unwrap()).unwrap();
	fs::write(path, text).unwrap();
	fs::set_permissions(path, Permissions::from_mode(mode)).unwrap();
}

/// Every refusal leaves no staging directory behind.
fn refused(line: &[OsString], home: &Path, table: &[Staged]) -> String {
	let error = Stage::prepare_with(line, home, me(), &Owner::default().chown(), table)
		.err()
		.expect("refused");
	assert!(entries(home).is_empty(), "a refused stage leaves nothing");
	error.to_string()
}

mod copy;
mod links;
mod outputs;
