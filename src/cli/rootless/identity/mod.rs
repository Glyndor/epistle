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
/// (before Linux 5.11, a seccomp filter, another system) the open descriptors
/// are listed and marked one at a time. A descriptor that cannot be marked
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
	// The soft limit is not a bound: it can be lowered after a descriptor was
	// opened under a higher one. The descriptors actually open are listed, and
	// only when they cannot be is the whole range the kernel allows swept.
	seal_by_listing().or_else(|_| seal_by_sweep())
}

/// Mark `fd` close-on-exec; a number that is not open is fine.
fn mark(fd: libc::c_int) -> io::Result<()> {
	// SAFETY: fcntl on a number that may not be open answers EBADF.
	if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
		let error = io::Error::last_os_error();
		if error.raw_os_error() != Some(libc::EBADF) {
			return Err(error);
		}
	}
	Ok(())
}

/// The number a `/proc/self/fd` entry names, or `None` for `.` and `..`.
fn fd_number(name: &[u8]) -> Option<libc::c_int> {
	let end = name
		.iter()
		.position(|&byte| byte == 0)
		.unwrap_or(name.len());
	let digits = &name[..end];
	if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
		return None;
	}
	digits.iter().try_fold(0 as libc::c_int, |number, &digit| {
		number
			.checked_mul(10)?
			.checked_add(libc::c_int::from(digit - b'0'))
	})
}

/// Mark every open descriptor above stderr by reading `/proc/self/fd` with raw
/// system calls and a buffer on the stack, so nothing allocates after `fork`.
#[cfg(target_os = "linux")]
fn seal_by_listing() -> io::Result<()> {
	// SAFETY: open takes a NUL-terminated path.
	let dir = unsafe {
		libc::open(
			c"/proc/self/fd".as_ptr(),
			libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
		)
	};
	if dir < 0 {
		return Err(io::Error::last_os_error());
	}
	let mut buffer = [0_u8; 2048];
	let result = loop {
		// SAFETY: getdents64 fills at most `buffer.len()` bytes of `buffer`.
		let read =
			unsafe { libc::syscall(libc::SYS_getdents64, dir, buffer.as_mut_ptr(), buffer.len()) };
		if read < 0 {
			break Err(io::Error::last_os_error());
		}
		if read == 0 {
			break Ok(());
		}
		let (read, mut at) = (read as usize, 0);
		let mut entries = Ok(());
		// A linux_dirent64 is an inode, an offset, a 16-bit record length, a
		// type byte and the name.
		while at + 19 <= read {
			let length = usize::from(u16::from_ne_bytes([buffer[at + 16], buffer[at + 17]]));
			if length < 20 || at + length > read {
				entries = Err(io::Error::other("a malformed /proc/self/fd entry"));
				break;
			}
			if let Some(fd) = fd_number(&buffer[at + 19..at + length])
				&& fd >= 3 && fd != dir
			{
				entries = entries.and(mark(fd));
			}
			at += length;
		}
		if entries.is_err() {
			break entries;
		}
	};
	// SAFETY: closing the descriptor opened above.
	unsafe { libc::close(dir) };
	result
}

#[cfg(not(target_os = "linux"))]
fn seal_by_listing() -> io::Result<()> {
	Err(io::Error::other("no way to list the open descriptors"))
}

/// Mark every descriptor number the kernel allows, up to `fs.nr_open`, which
/// no descriptor can exceed whatever the soft limit says. Fails, and so does
/// the spawn, when that bound cannot be read or is too large to sweep.
fn seal_by_sweep() -> io::Result<()> {
	let top = nr_open()?;
	if top > 1 << 24 {
		return Err(io::Error::other("fs.nr_open is too large to sweep"));
	}
	(3..top).try_for_each(mark)
}

/// `fs.nr_open`, read with raw calls and a buffer on the stack.
fn nr_open() -> io::Result<libc::c_int> {
	// SAFETY: open takes a NUL-terminated path.
	let file = unsafe {
		libc::open(
			c"/proc/sys/fs/nr_open".as_ptr(),
			libc::O_RDONLY | libc::O_CLOEXEC,
		)
	};
	if file < 0 {
		return Err(io::Error::last_os_error());
	}
	let mut buffer = [0_u8; 32];
	// SAFETY: read fills at most `buffer.len()` bytes of `buffer`.
	let read = unsafe { libc::read(file, buffer.as_mut_ptr().cast(), buffer.len()) };
	// SAFETY: closing the descriptor opened above.
	unsafe { libc::close(file) };
	if read <= 0 {
		return Err(io::Error::other("cannot read fs.nr_open"));
	}
	let text = &buffer[..read as usize];
	let end = text
		.iter()
		.position(|byte| !byte.is_ascii_digit())
		.unwrap_or(text.len());
	fd_number(&text[..end]).ok_or_else(|| io::Error::other("cannot read fs.nr_open"))
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
///
/// `USER` and `LOGNAME` become the account's name, as `runuser` made them:
/// left as root's, `podup` looked at root's linger setting instead of the
/// account's. The rest of the environment is the caller's.
pub(in crate::cli) fn run_as(command: &mut Command, identity: Identity) {
	command
		.env("USER", super::ACCOUNT)
		.env("LOGNAME", super::ACCOUNT);
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
