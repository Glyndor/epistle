//! Port bases for the `epistle local` tests that no other test can hold.
//!
//! `epistle local --port-base B` binds `B + offset` for six offsets. Probing
//! one free port and rounding it down says nothing about the other six, and
//! says nothing about a test in another process that picked a base a moment
//! earlier and has not bound it yet. A base is therefore only returned once
//! every derived port is claimed on disk and a bind probe found it free.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::{Ipv4Addr, TcpListener};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

/// The six listener offsets the `local` subcommand adds to `--port-base`.
const OFFSETS: [u16; 6] = [25, 143, 465, 587, 993, 8025];
/// The lowest base tried. Ports under 10000 are left to fixed services.
const FIRST_BASE: u32 = 10_000;
/// The highest derived port stays under 32768, the floor of Linux's default
/// ephemeral range: a client socket of another test picks from that range and
/// would take a listener port out from under the child.
const BASE_SPAN: u32 = 32_768 - 8_025 - FIRST_BASE - 1;
/// Claims older than this belong to a run that is gone, on a platform where
/// the owner's pid cannot be looked up.
const STALE_AFTER: std::time::Duration = std::time::Duration::from_secs(3_600);
const ATTEMPTS: usize = 2_000;

fn claim_dir() -> PathBuf {
	let dir = std::env::temp_dir().join("epistle-test-port-claims");
	let _ = fs::create_dir_all(&dir);
	dir
}

fn owner_is_gone(path: &std::path::Path) -> bool {
	let Ok(text) = fs::read_to_string(path) else {
		return false;
	};
	let Ok(pid) = text.trim().parse::<u32>() else {
		return true;
	};
	if pid == std::process::id() {
		return false;
	}
	if cfg!(target_os = "linux") {
		return !PathBuf::from(format!("/proc/{pid}")).exists();
	}
	fs::metadata(path)
		.and_then(|meta| meta.modified())
		.ok()
		.and_then(|at| at.elapsed().ok())
		.is_some_and(|age| age > STALE_AFTER)
}

/// Create the claim file for `port`. A claim whose owner has exited is
/// replaced; one held by a live process, this one included, is refused.
fn claim(dir: &std::path::Path, port: u16) -> Option<PathBuf> {
	let path = dir.join(port.to_string());
	for _ in 0..2 {
		match OpenOptions::new().write(true).create_new(true).open(&path) {
			Ok(mut file) => {
				let _ = write!(file, "{}", std::process::id());
				return Some(path);
			}
			Err(_) if owner_is_gone(&path) => {
				let _ = fs::remove_file(&path);
			}
			Err(_) => return None,
		}
	}
	None
}

/// One port is free when a listener can take it for an instant.
fn bindable(port: u16) -> bool {
	TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok()
}

/// A base whose six derived ports are all claimed by this call and free on
/// the loopback. A base that fails either check is skipped, and the claims it
/// took are given back, so the next attempt starts from a clean slate. The
/// search starts at an offset taken from the pid, so two test binaries that
/// start together do not walk the same sequence.
pub fn pick_port_base() -> u16 {
	static COUNTER: AtomicUsize = AtomicUsize::new(0);
	let dir = claim_dir();
	let start = (std::process::id() as usize).wrapping_mul(7_919);
	for _ in 0..ATTEMPTS {
		let step = COUNTER.fetch_add(1, Ordering::Relaxed).wrapping_mul(2_003);
		let base = (FIRST_BASE as usize + start.wrapping_add(step) % BASE_SPAN as usize) as u16;
		let mut taken = Vec::new();
		let mut ok = true;
		for offset in OFFSETS {
			let port = base + offset;
			match claim(&dir, port) {
				Some(path) => taken.push(path),
				None => {
					ok = false;
					break;
				}
			}
			if !bindable(port) {
				ok = false;
				break;
			}
		}
		if ok {
			return base;
		}
		for path in taken {
			let _ = fs::remove_file(path);
		}
	}
	panic!("no port base with six free derived ports after {ATTEMPTS} attempts");
}
