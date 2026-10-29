//! Tests for privilege dropping. The suite runs unprivileged, so these cover
//! the no-op, resolution-failure and fail-closed paths; the actual
//! setuid/setgid syscalls only run as root in production.

use super::*;
use crate::config::Privileges;

#[test]
fn none_is_noop() {
	assert!(drop_privileges(None).is_ok());
}

#[cfg(unix)]
fn current_user_name() -> Option<String> {
	use std::ffi::CStr;
	// SAFETY: getuid cannot fail; getpwuid_r's out-params outlive the call and
	// `result` is checked before `pwd` is read.
	let uid = unsafe { libc::getuid() };
	let mut buf = vec![0_i8 as libc::c_char; 1024];
	let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
	let mut result: *mut libc::passwd = std::ptr::null_mut();
	let rc = unsafe { libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr(), buf.len(), &mut result) };
	if rc != 0 || result.is_null() {
		return None;
	}
	// SAFETY: result non-null => pw_name points into `buf`.
	let name = unsafe { CStr::from_ptr(pwd.pw_name) };
	name.to_str().ok().map(str::to_owned)
}

#[cfg(unix)]
#[test]
fn unknown_user_fails_closed() {
	let privileges = Privileges {
		user: "epistle-no-such-user-zzz".into(),
		group: None,
	};
	assert!(drop_privileges(Some(&privileges)).is_err());
}

#[cfg(unix)]
#[test]
fn unknown_group_fails_closed() {
	// `root` always exists; the group lookup is what must fail.
	let privileges = Privileges {
		user: "root".into(),
		group: Some("epistle-no-such-group-zzz".into()),
	};
	assert!(drop_privileges(Some(&privileges)).is_err());
}

#[cfg(unix)]
#[test]
fn dropping_to_other_user_without_root_fails_closed() {
	// SAFETY: geteuid cannot fail.
	if unsafe { libc::geteuid() } == 0 {
		return; // running as root: this fail-closed path does not apply.
	}
	let privileges = Privileges {
		user: "root".into(),
		group: None,
	};
	assert!(drop_privileges(Some(&privileges)).is_err());
}

#[cfg(unix)]
#[test]
fn dropping_to_self_is_ok_when_not_root() {
	// SAFETY: geteuid cannot fail.
	if unsafe { libc::geteuid() } == 0 {
		return;
	}
	let Some(name) = current_user_name() else {
		return;
	};
	let privileges = Privileges {
		user: name,
		group: None,
	};
	assert!(drop_privileges(Some(&privileges)).is_ok());
}
