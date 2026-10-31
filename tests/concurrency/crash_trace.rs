//! Linux syscall stops select actual storage publication boundaries without sleeps.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::mpsc::SyncSender;
use std::time::Instant;

use super::support::DEADLINE;

fn ptrace(request: u32, tid: i32, data: usize) -> io::Result<()> {
	// SAFETY: tid is our child's announced runtime thread. GETREGS receives
	// a writable user_regs_struct; other requests interpret data as flags.
	let result = unsafe {
		libc::ptrace(
			request as _,
			tid,
			std::ptr::null_mut::<libc::c_void>(),
			data as *mut libc::c_void,
		)
	};
	if result == -1 {
		Err(io::Error::last_os_error())
	} else {
		Ok(())
	}
}

fn wait(tid: i32, deadline: Instant) -> io::Result<i32> {
	loop {
		let mut status = 0;
		// SAFETY: status is writable and tid belongs to the child we trace.
		let result = unsafe { libc::waitpid(tid, &mut status, libc::__WALL | libc::WNOHANG) };
		if result == tid {
			return Ok(status);
		}
		if result == -1 {
			let error = io::Error::last_os_error();
			if error.kind() != io::ErrorKind::Interrupted {
				return Err(error);
			}
		}
		if Instant::now() >= deadline {
			return Err(io::Error::new(
				io::ErrorKind::TimedOut,
				"storage syscall not reached",
			));
		}
		std::thread::yield_now();
	}
}

fn registers(tid: i32) -> io::Result<libc::user_regs_struct> {
	let mut regs = std::mem::MaybeUninit::<libc::user_regs_struct>::uninit();
	ptrace(libc::PTRACE_GETREGS, tid, regs.as_mut_ptr() as usize)?;
	// SAFETY: successful GETREGS initialized this exact structure.
	Ok(unsafe { regs.assume_init() })
}

fn path_at(tid: i32, address: u64) -> io::Result<PathBuf> {
	let mut bytes = Vec::new();
	for offset in (0..4096).step_by(std::mem::size_of::<libc::c_long>()) {
		// SAFETY: PEEKDATA copies a word from the stopped child. Invalid
		// addresses return an error rather than being dereferenced locally.
		let word = unsafe {
			libc::ptrace(
				libc::PTRACE_PEEKDATA,
				tid,
				(address as usize + offset) as *mut libc::c_void,
				std::ptr::null_mut::<libc::c_void>(),
			)
		};
		if word == -1 {
			return Err(io::Error::last_os_error());
		}
		for byte in word.to_ne_bytes() {
			if byte == 0 {
				use std::os::unix::ffi::OsStringExt;
				return Ok(PathBuf::from(std::ffi::OsString::from_vec(bytes)));
			}
			bytes.push(byte);
		}
	}
	Err(io::Error::new(
		io::ErrorKind::InvalidData,
		"unbounded syscall path",
	))
}

fn boundary(
	tid: i32,
	regs: &libc::user_regs_struct,
	temporary: &Path,
) -> io::Result<Option<String>> {
	// On x86_64 Linux the return register holds -ENOSYS at syscall entry.
	// Only entry stops count, so one fsync cannot consume two cut points.
	if regs.rax != (-(libc::ENOSYS as i64)) as u64 {
		return Ok(None);
	}
	let syscall = regs.orig_rax as libc::c_long;
	let path = if [
		libc::SYS_write,
		libc::SYS_writev,
		libc::SYS_pwrite64,
		libc::SYS_fsync,
		libc::SYS_fdatasync,
	]
	.contains(&syscall)
	{
		match std::fs::read_link(format!("/proc/{tid}/fd/{}", regs.rdi)) {
			Ok(path) => path,
			Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
			Err(error) => return Err(error),
		}
	} else if syscall == libc::SYS_rename {
		path_at(tid, regs.rdi)?
	} else if syscall == libc::SYS_renameat || syscall == libc::SYS_renameat2 {
		path_at(tid, regs.rsi)?
	} else {
		return Ok(None);
	};
	Ok(path
		.starts_with(temporary)
		.then(|| format!("syscall={syscall} path={}", path.display())))
}

struct KillOnDrop(i32);
impl Drop for KillOnDrop {
	fn drop(&mut self) {
		// SAFETY: the parent retains its Child until this tracer has joined,
		// so this pid cannot have been reaped and reused by another process.
		unsafe {
			libc::kill(self.0, libc::SIGKILL);
		}
	}
}

/// Arm before the next DATA terminator, then kill at the selected storage call.
/// EPERM and an unreached cut are errors, never silently skipped scenarios.
pub fn kill_at(
	pid: i32,
	tid: i32,
	temporary: PathBuf,
	cut: usize,
	ready: SyncSender<()>,
) -> io::Result<String> {
	let _cleanup = KillOnDrop(pid);
	let deadline = Instant::now() + DEADLINE;
	ptrace(
		libc::PTRACE_SEIZE,
		tid,
		libc::PTRACE_O_TRACESYSGOOD as usize,
	)?;
	ptrace(libc::PTRACE_INTERRUPT, tid, 0)?;
	let status = wait(tid, deadline)?;
	if !libc::WIFSTOPPED(status) {
		return Err(io::Error::other("child exited before tracing"));
	}
	ptrace(libc::PTRACE_SYSCALL, tid, 0)?;
	ready
		.send(())
		.map_err(|_| io::Error::other("parent left before tracer armed"))?;
	let mut reached = 0;
	loop {
		let status = wait(tid, deadline)?;
		if !libc::WIFSTOPPED(status) {
			return Err(io::Error::other(format!(
				"child exited before cut {cut}, status={status}"
			)));
		}
		let signal = libc::WSTOPSIG(status);
		if signal == (libc::SIGTRAP | 0x80) {
			if let Some(description) = boundary(tid, &registers(tid)?, &temporary)? {
				if reached == cut {
					// SAFETY: pid is still our live, owned child, stopped here.
					if unsafe { libc::kill(pid, libc::SIGKILL) } == -1 {
						return Err(io::Error::last_os_error());
					}
					let terminal = wait(tid, deadline)?;
					if !libc::WIFSIGNALED(terminal) || libc::WTERMSIG(terminal) != libc::SIGKILL {
						return Err(io::Error::other(format!(
							"unexpected kill status {terminal}"
						)));
					}
					return Ok(description);
				}
				reached += 1;
			}
			ptrace(libc::PTRACE_SYSCALL, tid, 0)?;
		} else {
			// Preserve unrelated signal delivery while tracing.
			ptrace(libc::PTRACE_SYSCALL, tid, signal as usize)?;
		}
	}
}
