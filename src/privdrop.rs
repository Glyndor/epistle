//! Dropping OS privileges after privileged ports are bound.
//!
//! A mail server must bind low ports (25, 465, 587, 993, 143, 995, 80), which
//! requires root (or `CAP_NET_BIND_SERVICE`). Once they are bound it should run
//! as an unprivileged user so a later compromise cannot act as root. This
//! module performs that transition and **fails closed**: if the requested drop
//! cannot be guaranteed, the caller aborts startup rather than continue with
//! more privilege than intended.

use crate::config::Privileges;

/// Drop to the configured user and group. A no-op when `privileges` is `None`.
///
/// Fails closed: any resolution or syscall failure, or an inability to reach
/// the requested identity, returns an error.
pub fn drop_privileges(privileges: Option<&Privileges>) -> std::io::Result<()> {
	let Some(privileges) = privileges else {
		return Ok(());
	};
	#[cfg(unix)]
	{
		unix::drop_to(&privileges.user, privileges.group.as_deref())
	}
	#[cfg(not(unix))]
	{
		let _ = privileges;
		Err(std::io::Error::other(
			"[privileges] is only supported on Unix",
		))
	}
}

#[cfg(unix)]
mod unix {
	use std::ffi::CString;
	use std::io::{Error, Result};

	/// Drop the process to `user` and `group` (group defaults to the user's
	/// primary group).
	///
	/// Order matters: supplementary groups and the gid must be set **before**
	/// the uid, because dropping the uid first forfeits the privilege needed to
	/// change the groups. After the drop we verify it took effect and cannot be
	/// undone.
	pub fn drop_to(user: &str, group: Option<&str>) -> Result<()> {
		let (uid, primary_gid) = resolve_user(user)?;
		let gid = match group {
			Some(group) => resolve_group(group)?,
			None => primary_gid,
		};

		// SAFETY: getuid/geteuid take no arguments and cannot fail.
		let (uid_now, euid) = unsafe { (libc::getuid(), libc::geteuid()) };
		if euid != 0 {
			// Not root: identity cannot be changed. Accept only if we are
			// already exactly the requested user; otherwise fail closed.
			if uid_now == uid && euid == uid {
				return Ok(());
			}
			return Err(Error::other(format!(
				"cannot drop privileges to {user:?}: not running as root"
			)));
		}

		// SAFETY: replacing our own supplementary group list with just the
		// target gid; `gid` outlives the call.
		if unsafe { libc::setgroups(1, &gid) } != 0 {
			return Err(Error::last_os_error());
		}
		// SAFETY: drop the gid before the uid (see above).
		if unsafe { libc::setgid(gid) } != 0 {
			return Err(Error::last_os_error());
		}
		// SAFETY: drop the uid last. Coming from euid 0, this sets the real,
		// effective and saved-set uids together, so root cannot be regained.
		if unsafe { libc::setuid(uid) } != 0 {
			return Err(Error::last_os_error());
		}

		verify(uid, gid)
	}

	/// Confirm the drop took effect and cannot be reversed.
	fn verify(uid: libc::uid_t, gid: libc::gid_t) -> Result<()> {
		// SAFETY: plain getters, no preconditions.
		let (ruid, euid) = unsafe { (libc::getuid(), libc::geteuid()) };
		let (rgid, egid) = unsafe { (libc::getgid(), libc::getegid()) };
		if ruid != uid || euid != uid || rgid != gid || egid != gid {
			return Err(Error::other("privilege drop did not take effect"));
		}
		// Dropping to non-root must make regaining root impossible.
		// SAFETY: a best-effort check; success here is the failure condition.
		if uid != 0 && unsafe { libc::setuid(0) } == 0 {
			return Err(Error::other("root could be regained after the drop"));
		}
		Ok(())
	}

	/// Resolve a user name to its uid and primary gid via `getpwnam_r`.
	fn resolve_user(name: &str) -> Result<(libc::uid_t, libc::gid_t)> {
		let c_name =
			CString::new(name).map_err(|_| Error::other("user name contains a NUL byte"))?;
		let mut buf = vec![0_i8 as libc::c_char; 1024];
		loop {
			let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
			let mut result: *mut libc::passwd = std::ptr::null_mut();
			// SAFETY: `pwd`, `buf` and `result` outlive the call; `result` is
			// checked before any field of `pwd` is read.
			let rc = unsafe {
				libc::getpwnam_r(
					c_name.as_ptr(),
					&mut pwd,
					buf.as_mut_ptr(),
					buf.len(),
					&mut result,
				)
			};
			if rc == libc::ERANGE && buf.len() < 1 << 20 {
				buf.resize(buf.len() * 2, 0);
				continue;
			}
			if rc != 0 {
				return Err(Error::from_raw_os_error(rc));
			}
			if result.is_null() {
				return Err(Error::other(format!("unknown user {name:?}")));
			}
			return Ok((pwd.pw_uid, pwd.pw_gid));
		}
	}

	/// Resolve a group name to its gid via `getgrnam_r`.
	fn resolve_group(name: &str) -> Result<libc::gid_t> {
		let c_name =
			CString::new(name).map_err(|_| Error::other("group name contains a NUL byte"))?;
		let mut buf = vec![0_i8 as libc::c_char; 1024];
		loop {
			let mut grp: libc::group = unsafe { std::mem::zeroed() };
			let mut result: *mut libc::group = std::ptr::null_mut();
			// SAFETY: as in `resolve_user`.
			let rc = unsafe {
				libc::getgrnam_r(
					c_name.as_ptr(),
					&mut grp,
					buf.as_mut_ptr(),
					buf.len(),
					&mut result,
				)
			};
			if rc == libc::ERANGE && buf.len() < 1 << 20 {
				buf.resize(buf.len() * 2, 0);
				continue;
			}
			if rc != 0 {
				return Err(Error::from_raw_os_error(rc));
			}
			if result.is_null() {
				return Err(Error::other(format!("unknown group {name:?}")));
			}
			return Ok(grp.gr_gid);
		}
	}
}

#[cfg(test)]
#[path = "privdrop_tests.rs"]
mod tests;
