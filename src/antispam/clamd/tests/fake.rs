//! A clamd stand-in for tests that cross the synchronous sink: it runs on a
//! plain thread, so it keeps answering while the test's runtime thread is
//! blocked inside a synchronous sink waiting for a scan. It reports the
//! EICAR test signature for any message that carries the EICAR string and
//! `OK` for everything else.

use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// The signature name the fake reports, as real clamd names it.
pub(crate) const SIGNATURE: &str = "Win.Test.EICAR_HDB-1";

/// The EICAR anti-virus test string. Assembled at run time so the source
/// file itself is not flagged by a scanner on the machine that builds it.
pub(crate) fn eicar() -> String {
	[
		"X5O!P%@AP[4\\PZX54(P^)7CC)7}$",
		"EICAR-STANDARD-ANTIVIRUS-",
		"TEST-FILE!$H+H*",
	]
	.concat()
}

/// A running fake. The listener thread is detached; it ends with the
/// process, and its socket goes with the temporary directory.
pub(crate) struct FakeClamd {
	_dir: tempfile::TempDir,
	/// Where the fake listens.
	pub(crate) socket: PathBuf,
	scans: Arc<AtomicUsize>,
}

impl FakeClamd {
	pub(crate) fn start() -> Self {
		Self::start_with(None)
	}

	/// A fake that answers every request with `reply` (without the NUL).
	pub(crate) fn start_replying(reply: &'static str) -> Self {
		Self::start_with(Some(reply))
	}

	fn start_with(fixed: Option<&'static str>) -> Self {
		let dir = tempfile::tempdir().expect("tempdir");
		let socket = dir.path().join("clamd.sock");
		let listener = UnixListener::bind(&socket).expect("bind fake clamd");
		let scans = Arc::new(AtomicUsize::new(0));
		let counter = Arc::clone(&scans);
		std::thread::spawn(move || {
			for stream in listener.incoming() {
				let Ok(mut stream) = stream else {
					return;
				};
				let Some(payload) = read_instream(&mut stream) else {
					continue;
				};
				counter.fetch_add(1, Ordering::SeqCst);
				let infected = String::from_utf8_lossy(&payload).contains(&eicar());
				let reply = if let Some(fixed) = fixed {
					format!("{fixed}\0")
				} else if infected {
					format!("stream: {SIGNATURE} FOUND\0")
				} else {
					"stream: OK\0".to_string()
				};
				let _ = stream.write_all(reply.as_bytes());
			}
		});
		FakeClamd {
			_dir: dir,
			socket,
			scans,
		}
	}

	/// How many messages the fake has scanned.
	pub(crate) fn scans(&self) -> usize {
		self.scans.load(Ordering::SeqCst)
	}
}

/// Read one `zINSTREAM` request and return its payload.
fn read_instream(stream: &mut impl Read) -> Option<Vec<u8>> {
	let mut command = [0u8; 10];
	stream.read_exact(&mut command).ok()?;
	if &command != b"zINSTREAM\0" {
		return None;
	}
	let mut payload = Vec::new();
	loop {
		let mut length = [0u8; 4];
		stream.read_exact(&mut length).ok()?;
		let length = u32::from_be_bytes(length) as usize;
		if length == 0 {
			return Some(payload);
		}
		let start = payload.len();
		payload.resize(start + length, 0);
		stream.read_exact(&mut payload[start..]).ok()?;
	}
}
