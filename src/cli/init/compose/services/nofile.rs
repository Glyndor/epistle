//! The open-file limit asked for the `mail` service, and the host limit it is capped by.

/// The `stop_grace_period` of the `mail` service, in seconds: how long podup
/// waits after SIGTERM before SIGKILL. `serve` drains for 5 s less.
pub(crate) const MAIL_STOP_GRACE_SECS: u64 = 30;

/// The open-file limit of the `mail` service. Podman starts a rootless
/// container with the invoking user's soft limit, often 1024, and every
/// connection is a descriptor: around a thousand idle connections the
/// listeners stopped greeting. Every listener cap together (SMTP 1000, IMAP
/// and POP3 500, ManageSieve 100, HTTP 1024) plus the spool, the database
/// socket and the logs stay well under this.
pub(crate) const MAIL_NOFILE: u64 = 65_536;

/// The open-file limit to ask for given the hard limit of the process that
/// writes the compose file (`None` when it is unlimited or unknown). Podman
/// refuses to start a container whose limit is above the hard limit of the
/// user that runs it (`setrlimit RLIMIT_NOFILE: Operation not permitted`), so
/// a lower hard limit lowers the request, and one that leaves nothing above
/// the usual soft limit of 1024 asks for nothing.
pub(crate) fn mail_nofile(host_hard_limit: Option<u64>) -> Option<u64> {
	match host_hard_limit {
		None => Some(MAIL_NOFILE),
		Some(hard) if hard > 1024 => Some(hard.min(MAIL_NOFILE)),
		Some(_) => None,
	}
}

/// Explain why a generated request leaves too little room for the listeners.
///
/// Two cases warrant a warning, both about the host's `RLIMIT_NOFILE`
/// hard limit landing below 8192:
///
/// 1. The host hard limit is known and the ask `mail_nofile(hard)` made
///    is still below 8192 (`hard` is between 1025 and 8191 inclusive).
///    The warning names the value the container ends up with.
/// 2. The host hard limit is so low that `mail_nofile` declines to ask
///    for anything (`hard <= 1024`, including the boundary at 1024). The
///    container then inherits the kernel soft limit, so the warning
///    names the host hard limit and the reason no larger value was
///    requested.
///
/// Both cases describe a host whose limit is the real ceiling; the
/// earlier shape missed case 2 at the 1024 boundary.
pub(crate) fn warn_low_nofile(hard: Option<u64>, out: &mut dyn std::io::Write) {
	const WARN_BELOW: u64 = 8192;
	match (mail_nofile(hard), hard) {
		(Some(requested), _) if requested < WARN_BELOW => {
			let _ = writeln!(
				out,
				"warning: the mail container nofile limit is {requested}, below {WARN_BELOW}, because the host RLIMIT_NOFILE hard limit is {requested}; raise the hard open-file limit for the account running init and the stack (for example with LimitNOFILE in its systemd unit or limits.conf), then run epistle init again"
			);
		}
		(None, Some(host_hard)) if host_hard < WARN_BELOW => {
			let _ = writeln!(
				out,
				"warning: the host RLIMIT_NOFILE hard limit is {host_hard}, below {WARN_BELOW}, so the mail container inherits the kernel soft limit and the nofile request is omitted (the container cannot be raised above the host hard limit); raise the hard open-file limit for the account running init and the stack (for example with LimitNOFILE in its systemd unit or limits.conf), then run epistle init again"
			);
		}
		_ => {}
	}
}

/// The hard open-file limit of this process, or `None` when it is unlimited
/// or cannot be read.
pub(crate) fn host_hard_nofile() -> Option<u64> {
	let mut limit = libc::rlimit {
		rlim_cur: 0,
		rlim_max: 0,
	};
	// SAFETY: `limit` is a valid, writable `rlimit` for the whole call.
	let read = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) };
	(read == 0 && limit.rlim_max != libc::RLIM_INFINITY).then_some(limit.rlim_max)
}
