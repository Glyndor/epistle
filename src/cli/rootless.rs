//! Re-execute packaged stack commands under the persistent rootless account.

use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, ExitStatus};

struct ServiceUser {
	uid: u32,
	home: PathBuf,
}

fn delegate(
	euid: u32,
	lookup: impl FnOnce() -> io::Result<Option<ServiceUser>>,
	runtime_exists: impl FnOnce(&Path) -> bool,
	exe: &Path,
	args: &[OsString],
	spawn: impl FnOnce(&mut Command) -> io::Result<ExitStatus>,
) -> io::Result<Option<ExitCode>> {
	if euid != 0 {
		return Ok(None);
	}
	let Some(user) = lookup()? else {
		return Ok(None);
	};
	let runtime = PathBuf::from(format!("/run/user/{}", user.uid));
	if !runtime_exists(&runtime) {
		return Err(io::Error::other(format!(
			"{} does not exist; run `loginctl enable-linger glyndor-epistle`",
			runtime.display()
		)));
	}
	let mut command = Command::new("runuser");
	command
		.args(["-u", "glyndor-epistle", "--"])
		.arg(exe)
		.args(args);
	command.env("XDG_RUNTIME_DIR", &runtime);
	command.env(
		"DBUS_SESSION_BUS_ADDRESS",
		format!("unix:path={}/bus", runtime.display()),
	);
	command.env("HOME", &user.home).current_dir(&user.home);
	let status = spawn(&mut command)?;
	Ok(Some(ExitCode::from(status.code().unwrap_or(1) as u8)))
}

pub(super) fn reexecute() -> io::Result<Option<ExitCode>> {
	#[cfg(unix)]
	{
		// SAFETY: geteuid takes no arguments and cannot fail.
		let euid = unsafe { libc::geteuid() };
		delegate(
			euid,
			lookup_user,
			Path::is_dir,
			&std::env::current_exe()?,
			&std::env::args_os().skip(1).collect::<Vec<_>>(),
			|command| command.status(),
		)
	}
	#[cfg(not(unix))]
	{
		Ok(None)
	}
}

#[cfg(unix)]
fn lookup_user() -> io::Result<Option<ServiceUser>> {
	use std::ffi::CStr;
	use std::os::unix::ffi::OsStrExt;

	let mut buffer = vec![0 as libc::c_char; 1024];
	loop {
		// SAFETY: a zeroed passwd is valid storage for getpwnam_r's output.
		let mut passwd: libc::passwd = unsafe { std::mem::zeroed() };
		let mut result = std::ptr::null_mut();
		// SAFETY: all output storage outlives the call; result is checked before use.
		let rc = unsafe {
			libc::getpwnam_r(
				c"glyndor-epistle".as_ptr(),
				&mut passwd,
				buffer.as_mut_ptr(),
				buffer.len(),
				&mut result,
			)
		};
		if rc == libc::ERANGE && buffer.len() < 1 << 20 {
			buffer.resize(buffer.len() * 2, 0);
			continue;
		}
		if rc != 0 {
			return Err(io::Error::from_raw_os_error(rc));
		}
		if result.is_null() {
			return Ok(None);
		}
		// SAFETY: successful getpwnam_r supplies a NUL-terminated home within buffer.
		let home = unsafe { CStr::from_ptr(passwd.pw_dir) };
		return Ok(Some(ServiceUser {
			uid: passwd.pw_uid,
			home: PathBuf::from(std::ffi::OsStr::from_bytes(home.to_bytes())),
		}));
	}
}

#[cfg(test)]
#[path = "rootless_tests.rs"]
mod tests;
