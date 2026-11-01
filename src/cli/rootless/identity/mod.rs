//! Becoming the service account inside the child process, without `runuser`.
//!
//! `runuser` stands between the delegating root process and the account's
//! command, and it answers a SIGTERM aimed at its process group by forwarding
//! it and killing the command about two seconds later, whatever the command
//! is doing (#1342; measured on the Debian 13 VM with util-linux 2.41.3, where
//! a child that needed six seconds to close cleanly was killed at two). A
//! restore that holds the stop signals until its next safe point, as
//! `backup::restore_signals` does, never got to use them.
//!
//! Here the child changes identity itself between `fork` and `exec`, so the
//! account's command is a direct child of the delegating process and a signal
//! reaches it unchanged. The environment is not touched: the caller sets the
//! few variables the user manager and rootless Podman expect, as it did for
//! `runuser`, which does not reset them either in its `-u` form.

use std::io;
use std::os::unix::process::CommandExt;
use std::process::Command;

/// One of the three identity changes, in the order they must happen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::cli) enum Step {
	/// Replace the supplementary groups with the account's own.
	Groups,
	/// Set the real, effective and saved group id.
	Gid,
	/// Set the real, effective and saved user id. Last, because giving up
	/// root first would take away the right to change the groups and the gid.
	Uid,
}

/// The user id, group id and supplementary groups the child takes.
#[derive(Debug, Clone)]
pub(in crate::cli) struct Identity {
	uid: libc::uid_t,
	gid: libc::gid_t,
	groups: Vec<libc::gid_t>,
}

impl Identity {
	/// An identity with the groups already worked out, so the child does
	/// nothing but system calls (see [`groups_of`]). `groups` should hold `gid`
	/// too.
	pub(in crate::cli) fn new(
		uid: libc::uid_t,
		gid: libc::gid_t,
		groups: Vec<libc::gid_t>,
	) -> Self {
		Self { uid, gid, groups }
	}

	/// Run the three steps in the order `setgroups`, `setgid`, `setuid`,
	/// asking `call` to perform each one, and stop at the first that fails: a
	/// child that could not drop the groups or the gid must not go on to the
	/// uid and run with a mixed identity. `call` returns the system call's
	/// result, `-1` meaning failure with `errno` set.
	pub(in crate::cli) fn switch(
		&self,
		mut call: impl FnMut(Step, &Self) -> libc::c_int,
	) -> io::Result<()> {
		for step in [Step::Groups, Step::Gid, Step::Uid] {
			if call(step, self) != 0 {
				return Err(io::Error::last_os_error());
			}
		}
		Ok(())
	}

	/// The real system calls behind [`Identity::switch`].
	fn perform(step: Step, identity: &Self) -> libc::c_int {
		// SAFETY: each is a plain system call. `groups` outlives the call and
		// the length passed is its own.
		unsafe {
			match step {
				Step::Groups => {
					libc::setgroups(identity.groups.len() as _, identity.groups.as_ptr())
				}
				Step::Gid => libc::setgid(identity.gid),
				Step::Uid => libc::setuid(identity.uid),
			}
		}
	}

	/// Whether the process now has exactly this identity in all of its ids.
	fn took_effect(&self) -> bool {
		// SAFETY: plain getters, no preconditions.
		let plain = unsafe {
			libc::getuid() == self.uid
				&& libc::geteuid() == self.uid
				&& libc::getgid() == self.gid
				&& libc::getegid() == self.gid
		};
		plain && self.saved_ids_match()
	}

	/// The saved ids are the way back to root, so they are read too.
	#[cfg(target_os = "linux")]
	fn saved_ids_match(&self) -> bool {
		let (mut r, mut e, mut s) = (0, 0, 0);
		// SAFETY: three valid out-pointers.
		let uids =
			unsafe { libc::getresuid(&mut r, &mut e, &mut s) } == 0 && [r, e, s] == [self.uid; 3];
		// SAFETY: as above.
		let gids =
			unsafe { libc::getresgid(&mut r, &mut e, &mut s) } == 0 && [r, e, s] == [self.gid; 3];
		uids && gids
	}

	#[cfg(not(target_os = "linux"))]
	fn saved_ids_match(&self) -> bool {
		true
	}
}

/// The groups the system lists for the account `name`, with `gid` among them.
/// They are read in the parent, because the lookup allocates and may load
/// name-service modules, neither of which is allowed after `fork`.
pub(in crate::cli) fn groups_of(name: &str, gid: u32) -> io::Result<Vec<libc::gid_t>> {
	let name = std::ffi::CString::new(name)
		.map_err(|_| io::Error::other("the account name has a NUL byte"))?;
	let mut groups: Vec<libc::gid_t> = vec![0; 32];
	loop {
		let mut count = libc::c_int::try_from(groups.len())
			.map_err(|_| io::Error::other("the account has too many groups"))?;
		// SAFETY: `groups` holds `count` entries and outlives the call; the
		// call writes at most `count` of them and updates `count`.
		let rc = unsafe {
			libc::getgrouplist(
				name.as_ptr(),
				gid as _,
				groups.as_mut_ptr().cast(),
				&mut count,
			)
		};
		let needed = usize::try_from(count).unwrap_or(0);
		if rc >= 0 {
			groups.truncate(needed);
			break;
		}
		if needed <= groups.len() || groups.len() >= 1 << 16 {
			return Err(io::Error::other("cannot list the groups of the account"));
		}
		groups.resize(needed, 0);
	}
	if !groups.contains(&(gid as libc::gid_t)) {
		groups.push(gid as libc::gid_t);
	}
	Ok(groups)
}

/// Mark every descriptor above stderr close-on-exec, so the account's command
/// starts with the three standard streams and nothing a root caller left open.
/// The kernel's `close_range` does it in one call; where it answers an error
/// (before Linux 5.11, a seccomp filter, another system) every descriptor up to
/// the soft limit is marked one at a time. A descriptor that cannot be marked
/// fails the whole thing, so the command never starts with one left open.
///
/// The descriptors are marked, not closed, because the standard library holds
/// a pipe open across the exec to report a failed one.
fn seal_descriptors() -> io::Result<()> {
	seal_with(close_range_cloexec)
}

/// [`seal_descriptors`] with the first attempt injected, so a kernel that
/// refuses it can be played. Makes system calls only, no allocation.
fn seal_with(close_range: impl FnOnce() -> libc::c_int) -> io::Result<()> {
	if close_range() == 0 {
		return Ok(());
	}
	let mut limit = libc::rlimit {
		rlim_cur: 0,
		rlim_max: 0,
	};
	// SAFETY: `limit` is valid storage for getrlimit's answer.
	let known = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } == 0;
	// No readable limit, or none set: the usual ceiling of a process.
	let top = if known && limit.rlim_cur != libc::RLIM_INFINITY {
		limit.rlim_cur.min(1 << 22)
	} else {
		1 << 20
	};
	for fd in 3..top as libc::c_int {
		// SAFETY: fcntl on a number that may not be open answers EBADF.
		let rc = unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
		if rc != 0 {
			let error = io::Error::last_os_error();
			if error.raw_os_error() != Some(libc::EBADF) {
				return Err(error);
			}
		}
	}
	Ok(())
}

/// `close_range(3, ~0, CLOSE_RANGE_CLOEXEC)`: 0 on success, -1 with `errno`
/// set when the kernel does not support it, and always -1 off Linux.
fn close_range_cloexec() -> libc::c_int {
	#[cfg(target_os = "linux")]
	{
		const CLOSE_RANGE_CLOEXEC: libc::c_uint = 4;
		// SAFETY: close_range takes three plain integers and touches no memory.
		unsafe {
			libc::syscall(
				libc::SYS_close_range,
				3 as libc::c_uint,
				libc::c_uint::MAX,
				CLOSE_RANGE_CLOEXEC,
			) as libc::c_int
		}
	}
	#[cfg(not(target_os = "linux"))]
	{
		-1
	}
}

/// Make `command` run as `identity`: after the `fork` and before the `exec` it
/// seals the descriptors and changes groups, gid and uid, in that order. When
/// a step fails the `exec` does not happen and the spawn reports the error.
pub(in crate::cli) fn run_as(command: &mut Command, identity: Identity) {
	// SAFETY: the closure runs between fork and exec, so it must use only
	// async-signal-safe calls. It does: system calls, and no allocation, lock
	// or name-service lookup (the groups were listed in the parent).
	unsafe {
		command.pre_exec(move || {
			seal_descriptors()?;
			identity.switch(Identity::perform)?;
			if identity.took_effect() {
				Ok(())
			} else {
				Err(io::Error::from_raw_os_error(libc::EPERM))
			}
		});
	}
}

#[cfg(test)]
mod tests;
